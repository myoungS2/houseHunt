/**
 * 집 고르기 장부 — Cloudflare Worker
 *
 *  1. 이메일과 비밀번호로 회원가입, 로그인 (가입 코드를 아는 사람만)
 *  2. 사람별로 완전히 분리된 매물 API (D1)
 *  3. 사진 저장 (R2)
 *  4. 앱 HTML 서빙
 *
 * 비밀번호는 서버에 도착하지 않습니다. 브라우저가 PBKDF2로 60만 번 늘린
 * 결과만 보내고, 워커는 거기에 임의 소금을 섞어 1만 2천 번 더 늘려 저장합니다.
 * DB를 통째로 훔쳐도 원래 비밀번호를 캐려면 한 번 찍을 때마다 61만 번을 돌려야 합니다.
 */
import APP_HTML from "../index.html";

/* ── 설정값 ── */
const CLIENT_ITER  = 600000;   // 브라우저가 도는 횟수. 로그인 화면 스크립트와 반드시 같아야 합니다.
const SERVER_ITER  = 12000;    // 워커가 도는 횟수. 무료 플랜 CPU 한도 안에 들어갑니다.
const KEY_BYTES    = 32;
const MIN_PW       = 10;       // 화면에서 막는 최소 길이
const SESSION_DAYS = 30;
const MAX_PHOTO    = 6 * 1024 * 1024;

const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAIL  = 8;
const LOGIN_LOCK_MS   = 15 * 60 * 1000;
const SIGNUP_WINDOW_MS = 60 * 60 * 1000;
const SIGNUP_MAX       = 5;

const SESSION_COOKIE = 'hh_session';

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    try {
      if (path.startsWith('/auth/')) return await handleAuth(req, env, url);

      if (path === '/api/me') {
        const u = await currentUser(req, env);
        if (!u) return json({ error: 'unauthorized', login: '/auth/login' }, 401);
        return json({ email: u.email, name: u.name, photos: !!env.PHOTOS, mode: 'password' });
      }

      if (path.startsWith('/api/') || path.startsWith('/photo/')) {
        const u = await currentUser(req, env);
        if (!u) return json({ error: 'unauthorized', login: '/auth/login' }, 401);
        if (req.method !== 'GET' && !sameOrigin(req, url)) {
          return json({ error: '요청 출처가 올바르지 않습니다' }, 403);
        }
        return await handleApi(req, env, url, u);
      }

      if (path === '/' || path === '/index.html') {
        const u = await currentUser(req, env);
        if (!u) return redirect(url.origin + '/auth/login');
        return serveApp();
      }
      return new Response('찾는 페이지가 없습니다', { status: 404, headers: baseHeaders() });
    } catch (err) {
      return json({ error: (err && err.message) || String(err) }, 500);
    }
  }
};

/* ═══ 앱 서빙 ═══════════════════════════════ */
function serveApp() {
  const nonce = b64(crypto.getRandomValues(new Uint8Array(16)));
  const body = APP_HTML
    .replace('<style>', '<style nonce="' + nonce + '">')
    .replace('<script>', '<script nonce="' + nonce + '">');
  return new Response(shell(nonce, body), {
    headers: Object.assign(baseHeaders(), {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': csp(nonce)
    })
  });
}
function shell(nonce, body) {
  return '<!doctype html><html lang="ko"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta name="color-scheme" content="light dark">' +
    '<style nonce="' + nonce + '">body{margin:0}img{max-width:100%}[hidden]{display:none!important}</style>' +
    '</head><body>' + body + '</body></html>';
}
function csp(nonce) {
  return "default-src 'none'; script-src 'nonce-" + nonce + "'; " +
    "style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; " +
    "img-src 'self' data: blob:; connect-src 'self'; form-action 'self'; " +
    "base-uri 'none'; frame-ancestors 'none'";
}
function baseHeaders() {
  return {
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'same-origin',
    'x-frame-options': 'DENY',
    'strict-transport-security': 'max-age=31536000; includeSubDomains'
  };
}
function sameOrigin(req, url) {
  const o = req.headers.get('Origin');
  if (!o) return true;                 // 같은 출처 요청은 Origin을 안 붙이기도 합니다
  return o === url.origin;
}

/* ═══ 세션 ══════════════════════════════════ */
async function currentUser(req, env) {
  if (env.ALLOW_OPEN === '1') return { email: 'open@local', name: '공용', key: 'open@local' };

  const raw = readCookie(req, SESSION_COOKIE);
  if (!raw) return null;
  const cut = raw.lastIndexOf('.');
  if (cut < 0) return null;
  const payload = raw.slice(0, cut), sig = raw.slice(cut + 1);
  if (!(await sigOk(env, payload, sig))) return null;

  let d;
  try { d = JSON.parse(dec(payload)); } catch (e) { return null; }
  if (!d || !d.e || !d.x || d.x < Date.now()) return null;

  const row = await env.DB.prepare(
    'SELECT email, name, session_epoch FROM users WHERE email = ?').bind(d.e).first();
  if (!row) return null;
  if (Number(d.v || 0) !== Number(row.session_epoch)) return null;   // 비밀번호를 바꾸면 옛 세션이 끊깁니다

  return { email: row.email, name: row.name || row.email.split('@')[0], key: row.email };
}

async function sessionCookie(env, email, epoch, secure) {
  const payload = enc(JSON.stringify({ e: email, v: epoch, x: Date.now() + SESSION_DAYS * 864e5 }));
  const sig = await sign(env, payload);
  return SESSION_COOKIE + '=' + payload + '.' + sig +
    '; Path=/; Max-Age=' + SESSION_DAYS * 86400 + '; HttpOnly; SameSite=Lax' + (secure ? '; Secure' : '');
}
function clearCookie(secure) {
  return SESSION_COOKIE + '=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax' + (secure ? '; Secure' : '');
}

/* ═══ 비밀번호 ══════════════════════════════ */
async function pbkdf2(material, salt, iter) {
  const key = await crypto.subtle.importKey('raw',
    typeof material === 'string' ? new TextEncoder().encode(material) : material,
    'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, key, KEY_BYTES * 8));
}
async function hashKey(clientKey) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const out = await pbkdf2(clientKey, salt, SERVER_ITER);
  return 'pbkdf2$' + SERVER_ITER + '$' + b64(salt) + '$' + b64(out);
}
async function verifyKey(clientKey, stored) {
  const p = String(stored || '').split('$');
  if (p.length !== 4 || p[0] !== 'pbkdf2') return false;
  const iter = parseInt(p[1], 10);
  if (!(iter > 0 && iter <= 1000000)) return false;
  const out = await pbkdf2(clientKey, b64ToBytes(p[2]), iter);
  return eqBytes(out, b64ToBytes(p[3]));
}
/* 없는 계정에도 같은 시간을 쓰게 해서, 응답 속도로 가입 여부를 못 알아내게 합니다 */
async function dummyWork() {
  await pbkdf2('x'.repeat(43), new Uint8Array(16), SERVER_ITER);
}
function validKey(k) { return typeof k === 'string' && /^[A-Za-z0-9_-]{43}$/.test(k); }
function validEmail(e) {
  return typeof e === 'string' && e.length <= 254 && /^[^\s@]+@[^\s@.]+\.[^\s@]+$/.test(e);
}

/* ═══ 시도 횟수 제한 ════════════════════════ */
async function rateBlocked(env, key) {
  const row = await env.DB.prepare(
    'SELECT until FROM login_attempts WHERE key = ?').bind(key).first();
  return row && row.until && row.until > Date.now() ? row.until : 0;
}
async function rateFail(env, key, windowMs, maxFail, lockMs) {
  const now = Date.now();
  const row = await env.DB.prepare(
    'SELECT count, first_at FROM login_attempts WHERE key = ?').bind(key).first();
  let count = 1, first = now;
  if (row && now - row.first_at <= windowMs) { count = row.count + 1; first = row.first_at; }
  const until = count >= maxFail ? now + lockMs : null;
  await env.DB.prepare(
    'INSERT INTO login_attempts (key, count, first_at, until) VALUES (?,?,?,?) ' +
    'ON CONFLICT(key) DO UPDATE SET count=excluded.count, first_at=excluded.first_at, until=excluded.until'
  ).bind(key, count, first, until).run();
  return until;
}
async function rateClear(env, key) {
  await env.DB.prepare('DELETE FROM login_attempts WHERE key = ?').bind(key).run();
}
function clientIp(req) { return req.headers.get('CF-Connecting-IP') || '0.0.0.0'; }
function minutesLeft(until) { return Math.max(1, Math.ceil((until - Date.now()) / 60000)); }

/* ═══ 로그인 화면과 처리 ════════════════════ */
async function handleAuth(req, env, url) {
  const path = url.pathname, secure = url.protocol === 'https:';

  if (path === '/auth/logout') {
    if (req.method !== 'POST') return redirect(url.origin + '/');
    const h = new Headers({ location: '/auth/login' });
    h.append('set-cookie', clearCookie(secure));
    return new Response(null, { status: 303, headers: h });
  }

  if (path === '/auth/login' && req.method === 'GET') {
    const u = await currentUser(req, env);
    if (u) return redirect(url.origin + '/');
    return authPage('login');
  }

  if (path === '/auth/signup' && req.method === 'GET') {
    return authPage('signup');
  }

  if (path === '/auth/password' && req.method === 'GET') {
    const u = await currentUser(req, env);
    if (!u) return redirect(url.origin + '/auth/login');
    return authPage('password', u.email);
  }

  if (req.method !== 'POST') return new Response('없는 경로입니다', { status: 404, headers: baseHeaders() });
  if (!sameOrigin(req, url)) return json({ error: '요청 출처가 올바르지 않습니다' }, 403);

  let body;
  try { body = await req.json(); } catch (e) { return json({ error: '요청을 읽지 못했습니다' }, 400); }
  const email = String(body.email || '').trim().toLowerCase();

  /* ── 로그인 ── */
  if (path === '/auth/login') {
    if (!validEmail(email) || !validKey(body.key)) {
      return json({ error: '이메일 또는 비밀번호가 맞지 않습니다' }, 401);
    }
    const ipKey = 'i:' + clientIp(req), emKey = 'e:' + email;
    const blocked = (await rateBlocked(env, emKey)) || (await rateBlocked(env, ipKey));
    if (blocked) {
      return json({ error: '로그인 시도가 너무 많습니다. ' + minutesLeft(blocked) + '분 뒤에 다시 해주세요' }, 429);
    }

    const row = await env.DB.prepare(
      'SELECT email, name, pw, session_epoch FROM users WHERE email = ?').bind(email).first();
    const ok = row ? await verifyKey(body.key, row.pw) : (await dummyWork(), false);
    if (!ok) {
      await rateFail(env, emKey, LOGIN_WINDOW_MS, LOGIN_MAX_FAIL, LOGIN_LOCK_MS);
      await rateFail(env, ipKey, LOGIN_WINDOW_MS, LOGIN_MAX_FAIL * 3, LOGIN_LOCK_MS);
      return json({ error: '이메일 또는 비밀번호가 맞지 않습니다' }, 401);
    }

    await rateClear(env, emKey);
    await env.DB.prepare('UPDATE users SET last_login = ? WHERE email = ?').bind(nowIso(), email).run();
    const h = new Headers({ 'content-type': 'application/json; charset=utf-8' });
    h.append('set-cookie', await sessionCookie(env, email, row.session_epoch, secure));
    return new Response(JSON.stringify({ ok: true, next: '/' }), { headers: h });
  }

  /* ── 회원가입 ── */
  if (path === '/auth/signup') {
    const ipKey = 's:' + clientIp(req);
    const blocked = await rateBlocked(env, ipKey);
    if (blocked) return json({ error: '가입 시도가 너무 많습니다. ' + minutesLeft(blocked) + '분 뒤에 다시 해주세요' }, 429);

    const code = env.SIGNUP_CODE || '';
    if (!code) return json({ error: '가입이 닫혀 있습니다. 장부 주인에게 문의하세요' }, 403);
    if (!eqStr(String(body.code || '').trim(), code)) {
      await rateFail(env, ipKey, SIGNUP_WINDOW_MS, SIGNUP_MAX, SIGNUP_WINDOW_MS);
      return json({ error: '가입 코드가 맞지 않습니다' }, 403);
    }
    if (!validEmail(email)) return json({ error: '이메일 형식이 올바르지 않습니다' }, 400);
    if (!validKey(body.key)) return json({ error: '비밀번호를 다시 입력해 주세요' }, 400);

    const allow = (env.ALLOWED_EMAILS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    if (allow.length && allow.indexOf(email) < 0) {
      return json({ error: '이 이메일은 초대 목록에 없습니다' }, 403);
    }

    const exists = await env.DB.prepare('SELECT email FROM users WHERE email = ?').bind(email).first();
    if (exists) return json({ error: '이미 가입된 이메일입니다. 로그인해 주세요' }, 409);

    const pw = await hashKey(body.key);
    const name = String(body.name || '').trim().slice(0, 40) || email.split('@')[0];
    await env.DB.prepare(
      'INSERT INTO users (email, name, pw, session_epoch, created_at) VALUES (?,?,?,1,?)'
    ).bind(email, name, pw, nowIso()).run();
    await rateFail(env, ipKey, SIGNUP_WINDOW_MS, SIGNUP_MAX, SIGNUP_WINDOW_MS);

    const h = new Headers({ 'content-type': 'application/json; charset=utf-8' });
    h.append('set-cookie', await sessionCookie(env, email, 1, secure));
    return new Response(JSON.stringify({ ok: true, next: '/' }), { headers: h });
  }

  /* ── 비밀번호 변경 ── */
  if (path === '/auth/password') {
    const u = await currentUser(req, env);
    if (!u) return json({ error: '로그인이 필요합니다' }, 401);
    if (!validKey(body.key) || !validKey(body.newKey)) return json({ error: '비밀번호를 다시 입력해 주세요' }, 400);

    const emKey = 'p:' + u.email;
    const blocked = await rateBlocked(env, emKey);
    if (blocked) return json({ error: '시도가 너무 많습니다. ' + minutesLeft(blocked) + '분 뒤에 다시 해주세요' }, 429);

    const row = await env.DB.prepare(
      'SELECT pw, session_epoch FROM users WHERE email = ?').bind(u.email).first();
    if (!row || !(await verifyKey(body.key, row.pw))) {
      await rateFail(env, emKey, LOGIN_WINDOW_MS, LOGIN_MAX_FAIL, LOGIN_LOCK_MS);
      return json({ error: '지금 쓰는 비밀번호가 맞지 않습니다' }, 401);
    }
    await rateClear(env, emKey);

    const epoch = Number(row.session_epoch) + 1;
    await env.DB.prepare('UPDATE users SET pw = ?, session_epoch = ? WHERE email = ?')
      .bind(await hashKey(body.newKey), epoch, u.email).run();

    const h = new Headers({ 'content-type': 'application/json; charset=utf-8' });
    h.append('set-cookie', await sessionCookie(env, u.email, epoch, secure));
    return new Response(JSON.stringify({ ok: true, next: '/' }), { headers: h });
  }

  return new Response('없는 경로입니다', { status: 404, headers: baseHeaders() });
}

/* ═══ 로그인·가입 화면 ══════════════════════ */
function authPage(kind, email) {
  const nonce = b64(crypto.getRandomValues(new Uint8Array(16)));
  const T = {
    login:    { title: '집 고르기 장부', lead: '로그인', btn: '로그인', path: '/auth/login' },
    signup:   { title: '집 고르기 장부', lead: '회원가입', btn: '가입하고 시작하기', path: '/auth/signup' },
    password: { title: '집 고르기 장부', lead: '비밀번호 변경', btn: '비밀번호 바꾸기', path: '/auth/password' }
  }[kind];

  const fields =
    kind === 'signup' ? [
      row('email', '이메일', 'email', 'username', '', true),
      row('name', '이름 (안 써도 됩니다)', 'text', 'name'),
      row('pw', '비밀번호', 'password', 'new-password', MIN_PW + '자 이상'),
      row('pw2', '비밀번호 다시', 'password', 'new-password'),
      row('code', '가입 코드', 'text', 'off', '장부 주인에게 받은 코드')
    ].join('') :
    kind === 'password' ? [
      '<p class="who">' + esc(email) + '</p>',
      row('pw', '지금 비밀번호', 'password', 'current-password'),
      row('pw2', '새 비밀번호', 'password', 'new-password', MIN_PW + '자 이상'),
      row('pw3', '새 비밀번호 다시', 'password', 'new-password')
    ].join('') : [
      row('email', '이메일', 'email', 'username', '', true),
      row('pw', '비밀번호', 'password', 'current-password')
    ].join('');

  const foot =
    kind === 'login'  ? '<p class="alt">처음이신가요? <a href="/auth/signup">가입 코드로 시작하기</a></p>' :
    kind === 'signup' ? '<p class="alt">이미 계정이 있나요? <a href="/auth/login">로그인</a></p>' :
                        '<p class="alt"><a href="/">장부로 돌아가기</a></p>';

  const html = '<!doctype html><html lang="ko"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta name="color-scheme" content="light dark"><title>' + T.lead + ' · 집 고르기 장부</title>' +
    '<link rel="preconnect" href="https://fonts.googleapis.com">' +
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>' +
    '<link href="https://fonts.googleapis.com/css2?family=Hahmlet:wght@600&family=IBM+Plex+Sans+KR:wght@400;500;600&display=swap" rel="stylesheet">' +
    '<style nonce="' + nonce + '">' + AUTH_CSS + '</style></head><body>' +
    '<main class="card">' +
      '<div class="mark">집</div>' +
      '<h1>' + T.title + '</h1><p class="lead">' + T.lead + '</p>' +
      '<form id="f" novalidate>' + fields +
        '<p class="err" id="err" hidden></p>' +
        '<button type="submit" id="go">' + T.btn + '</button>' +
      '</form>' + foot +
    '</main>' +
    '<script nonce="' + nonce + '">' + authScript(kind, T.path) + '</script></body></html>';

  return new Response(html, {
    headers: Object.assign(baseHeaders(), {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': csp(nonce)
    })
  });
}
function row(id, label, type, ac, ph, autofocus) {
  return '<label for="' + id + '">' + label + '</label>' +
    '<input id="' + id + '" type="' + type + '" autocomplete="' + ac + '"' +
    (ph ? ' placeholder="' + esc(ph) + '"' : '') + (autofocus ? ' autofocus' : '') + '>';
}

const AUTH_CSS = [
':root{--bg:#EDF1EF;--surface:#fff;--ink:#152220;--muted:#71847F;--line:#C0CCC8;--accent:#14594A;--bad:#A63F29}',
'@media (prefers-color-scheme:dark){:root{--bg:#101614;--surface:#18201E;--ink:#E9EFEC;--muted:#879995;--line:#3C4A47;--accent:#5FBFA4;--bad:#E28B72}}',
'*{box-sizing:border-box}',
'body{margin:0;background:var(--bg);color:var(--ink);font-family:"IBM Plex Sans KR","Apple SD Gothic Neo",system-ui,sans-serif;',
'display:grid;place-items:center;min-height:100vh;padding:24px;font-size:15px}',
'.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:30px 28px 24px;width:min(390px,100%);',
'box-shadow:0 2px 6px rgba(14,36,31,.07),0 18px 44px -24px rgba(14,36,31,.5)}',
'.mark{width:36px;height:36px;border-radius:9px;background:var(--accent);color:var(--surface);display:grid;place-items:center;',
'font-family:Hahmlet,serif;font-weight:600;font-size:18px;margin-bottom:16px}',
'h1{font-family:Hahmlet,"Noto Serif KR",serif;font-size:19px;font-weight:600;margin:0}',
'.lead{margin:2px 0 22px;color:var(--muted);font-size:13px}',
'.who{margin:0 0 18px;padding:8px 12px;background:var(--bg);border-radius:8px;font-size:13px;color:var(--muted)}',
'label{display:block;font-size:12px;color:var(--muted);font-weight:500;margin:0 0 5px}',
'input{width:100%;padding:9px 11px;border:1px solid var(--line);border-radius:8px;background:var(--surface);',
'color:var(--ink);font:inherit;font-size:14px;margin-bottom:14px}',
'input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 18%,transparent)}',
'button{width:100%;padding:11px;border:0;border-radius:9px;background:var(--accent);color:var(--surface);',
'font:inherit;font-weight:600;font-size:14px;cursor:pointer;margin-top:4px}',
'button:hover:not(:disabled){filter:brightness(1.1)}',
'button:disabled{opacity:.6;cursor:progress}',
'.err{margin:0 0 12px;padding:9px 12px;background:color-mix(in srgb,var(--bad) 12%,transparent);',
'color:var(--bad);border-radius:8px;font-size:13px;line-height:1.45}',
'.alt{margin:18px 0 0;font-size:13px;color:var(--muted);text-align:center}',
'a{color:var(--accent)}',
'@media (prefers-reduced-motion:reduce){*{transition:none!important}}'
].join('');

function authScript(kind, postPath) {
  return [
'(function(){',
'"use strict";',
'var ITER=' + CLIENT_ITER + ', MIN=' + MIN_PW + ', KIND=' + JSON.stringify(kind) + ', PATH=' + JSON.stringify(postPath) + ';',
'var f=document.getElementById("f"), go=document.getElementById("go"), errBox=document.getElementById("err");',
'var label=go.textContent;',
'function val(id){var el=document.getElementById(id);return el?el.value:"";}',
'function fail(m){errBox.textContent=m;errBox.hidden=false;go.disabled=false;go.textContent=label;}',
'function b64u(buf){var s="",a=new Uint8Array(buf);for(var i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);',
'return btoa(s).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/,"");}',
/* 비밀번호는 이 브라우저를 떠나지 않습니다. 늘린 결과만 보냅니다. */
'async function derive(email,pw){',
' var e=new TextEncoder();',
' var k=await crypto.subtle.importKey("raw",e.encode(pw.normalize("NFC")),"PBKDF2",false,["deriveBits"]);',
' return b64u(await crypto.subtle.deriveBits({name:"PBKDF2",salt:e.encode("house-hunt|"+email),iterations:ITER,hash:"SHA-256"},k,256));',
'}',
'f.addEventListener("submit",async function(ev){',
' ev.preventDefault(); errBox.hidden=true;',
' if(!window.crypto||!crypto.subtle){return fail("이 브라우저에서는 로그인할 수 없습니다. 주소가 https인지 확인해 주세요.");}',
' var body={};',
' var email = (KIND==="password") ? "" : val("email").trim().toLowerCase();',
' if(KIND!=="password"){',
'  if(!email||email.indexOf("@")<0) return fail("이메일을 확인해 주세요.");',
'  if(val("pw").length<MIN) return fail("비밀번호는 "+MIN+"자 이상이어야 합니다.");',
' }',
' if(KIND==="signup"){',
'  if(val("pw")!==val("pw2")) return fail("두 비밀번호가 서로 다릅니다.");',
'  if(!val("code").trim()) return fail("가입 코드를 넣어 주세요.");',
'  if(val("pw").toLowerCase().indexOf(email.split("@")[0].toLowerCase())>=0) return fail("비밀번호에 이메일을 그대로 쓰지 마세요.");',
' }',
' if(KIND==="password"){',
'  if(val("pw2").length<MIN) return fail("새 비밀번호는 "+MIN+"자 이상이어야 합니다.");',
'  if(val("pw2")!==val("pw3")) return fail("새 비밀번호가 서로 다릅니다.");',
'  if(val("pw")===val("pw2")) return fail("지금 쓰는 비밀번호와 같습니다.");',
' }',
' go.disabled=true; go.textContent="확인 중…";',
' try{',
'  if(KIND==="password"){',
'   var me=document.querySelector(".who").textContent.trim();',
'   body.key=await derive(me,val("pw")); body.newKey=await derive(me,val("pw2"));',
'  }else{',
'   body.email=email; body.key=await derive(email,val("pw"));',
'   if(KIND==="signup"){ body.name=val("name").trim(); body.code=val("code").trim(); }',
'  }',
'  var r=await fetch(PATH,{method:"POST",credentials:"same-origin",',
'   headers:{"content-type":"application/json"},body:JSON.stringify(body)});',
'  var j=null; try{ j=await r.json(); }catch(e){}',
'  if(r.ok&&j&&j.ok){ location.href=(j.next||"/"); return; }',
'  fail((j&&j.error)||"처리하지 못했습니다. 잠시 뒤에 다시 시도해 주세요.");',
' }catch(e){ fail("연결하지 못했습니다. 잠시 뒤에 다시 시도해 주세요."); }',
'});',
'})();'
  ].join('\n');
}

/* ═══ API ═══════════════════════════════════ */
async function handleApi(req, env, url, u) {
  const path = url.pathname, method = req.method, uk = u.key;

  if (path === '/api/state' && method === 'GET') {
    const props = await env.DB.prepare(
      'SELECT data FROM properties WHERE user_key = ?').bind(uk).all();
    const st = await env.DB.prepare(
      'SELECT data FROM settings WHERE user_key = ?').bind(uk).first();
    return json({
      properties: (props.results || []).map(r => safeParse(r.data)).filter(Boolean),
      settings: st ? safeParse(st.data) : null
    });
  }

  if (path === '/api/settings' && method === 'PUT') {
    const body = await req.json();
    await env.DB.prepare(
      'INSERT INTO settings (user_key, data, updated_at) VALUES (?, ?, ?) ' +
      'ON CONFLICT(user_key) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at'
    ).bind(uk, JSON.stringify(body), nowIso()).run();
    return json({ ok: true });
  }

  if (path === '/api/properties' && method === 'PUT') {
    const body = await req.json();
    const items = Array.isArray(body.items) ? body.items : [];
    if (!items.length) return json({ ok: true, saved: 0 });
    if (items.length > 200) return json({ error: '한 번에 200곳까지만 저장합니다' }, 400);
    const at = nowIso();
    await env.DB.batch(items.filter(p => p && p.id).map(p =>
      env.DB.prepare(UPSERT_PROP).bind(uk, String(p.id), JSON.stringify(p), at)));
    return json({ ok: true, saved: items.length });
  }

  const one = path.match(/^\/api\/properties\/([A-Za-z0-9_-]{1,64})$/);
  if (one) {
    const id = one[1];
    if (method === 'PUT') {
      const body = await req.json();
      body.id = id;
      const doc = JSON.stringify(body);
      if (doc.length > 200000) return json({ error: '내용이 너무 깁니다' }, 413);
      await env.DB.prepare(UPSERT_PROP).bind(uk, id, doc, nowIso()).run();
      return json({ ok: true });
    }
    if (method === 'DELETE') {
      await env.DB.prepare('DELETE FROM properties WHERE user_key = ? AND id = ?').bind(uk, id).run();
      return json({ ok: true });
    }
  }

  if (path === '/api/photos' && method === 'POST') {
    if (!env.PHOTOS) return json({ error: '사진 저장소가 연결되지 않았습니다' }, 501);
    const type = req.headers.get('content-type') || 'image/jpeg';
    if (!/^image\//.test(type)) return json({ error: '이미지만 올릴 수 있습니다' }, 415);
    const buf = await req.arrayBuffer();
    if (!buf.byteLength) return json({ error: '빈 파일입니다' }, 400);
    if (buf.byteLength > MAX_PHOTO) return json({ error: '사진이 너무 큽니다' }, 413);
    const id = crypto.randomUUID().replace(/-/g, '');
    await env.PHOTOS.put(uk + '/' + id, buf, { httpMetadata: { contentType: type } });
    await env.DB.prepare(
      'INSERT INTO photos (id, user_key, object_key, content_type, size, created_at) VALUES (?,?,?,?,?,?)'
    ).bind(id, uk, uk + '/' + id, type, buf.byteLength, nowIso()).run();
    return json({ id, url: '/photo/' + id });
  }

  const photo = path.match(/^\/photo\/([a-f0-9]{32})$/);
  if (photo && method === 'GET') {
    if (!env.PHOTOS) return new Response('사진 저장소가 없습니다', { status: 404, headers: baseHeaders() });
    const row = await env.DB.prepare(
      'SELECT object_key, content_type FROM photos WHERE id = ? AND user_key = ?'
    ).bind(photo[1], uk).first();
    if (!row) return new Response('없는 사진입니다', { status: 404, headers: baseHeaders() });
    const obj = await env.PHOTOS.get(row.object_key);
    if (!obj) return new Response('없는 사진입니다', { status: 404, headers: baseHeaders() });
    return new Response(obj.body, {
      headers: Object.assign(baseHeaders(), {
        'content-type': row.content_type || 'image/jpeg',
        'cache-control': 'private, max-age=86400',
        'etag': obj.httpEtag
      })
    });
  }

  if (photo && method === 'DELETE') {
    const row = await env.DB.prepare(
      'SELECT object_key FROM photos WHERE id = ? AND user_key = ?').bind(photo[1], uk).first();
    if (row && env.PHOTOS) await env.PHOTOS.delete(row.object_key);
    await env.DB.prepare('DELETE FROM photos WHERE id = ? AND user_key = ?').bind(photo[1], uk).run();
    return json({ ok: true });
  }

  return json({ error: '없는 경로입니다' }, 404);
}

const UPSERT_PROP =
  'INSERT INTO properties (user_key, id, data, updated_at) VALUES (?, ?, ?, ?) ' +
  'ON CONFLICT(user_key, id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at';

/* ═══ 잡다한 것 ══════════════════════════════ */
function json(o, status) {
  return new Response(JSON.stringify(o), {
    status: status || 200,
    headers: Object.assign(baseHeaders(), {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store'
    })
  });
}
function redirect(to) {
  return new Response(null, { status: 302, headers: Object.assign(baseHeaders(), { location: to }) });
}
function nowIso() { return new Date().toISOString(); }
function safeParse(s) { try { return JSON.parse(s); } catch (e) { return null; } }
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function readCookie(req, name) {
  const raw = req.headers.get('Cookie');
  if (!raw) return null;
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}
function b64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64ToBytes(s) {
  const t = String(s).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(t + '='.repeat((4 - t.length % 4) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function enc(str) { return b64(new TextEncoder().encode(str)); }
function dec(s) { return new TextDecoder().decode(b64ToBytes(s)); }
function eqBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
function eqStr(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
async function sign(env, data) {
  const secret = env.SESSION_SECRET;
  if (!secret) throw new Error('SESSION_SECRET이 설정되지 않았습니다');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64(new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data))));
}
async function sigOk(env, data, sig) {
  return eqStr(await sign(env, data), String(sig));
}
