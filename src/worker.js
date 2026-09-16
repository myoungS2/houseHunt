/**
 * 하우스헌팅 — Cloudflare Worker
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
const MAX_PHOTO_DB = 700 * 1024;   // R2 없이 D1에 담을 때 한 장 크기
const MAX_PHOTOS_DB = 300;        // R2 없이 D1에 담을 때 장부당 장수
const MAX_MEMBERS  = 6;        // 한 장부에 들어올 수 있는 사람 수
const INVITE_DAYS  = 7;        // 초대 링크가 살아 있는 기간
const MAX_BOOKS    = 5;        // 한 사람이 주인으로 가질 수 있는 장부 수
const MAX_PROPS    = 300;      // 한 장부에 담을 수 있는 매물 수
const MAX_PROP_LEN = 200000;   // 매물 한 곳의 JSON 길이

const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAIL  = 8;
const LOGIN_LOCK_MS   = 15 * 60 * 1000;
const SIGNUP_WINDOW_MS = 60 * 60 * 1000;
const SIGNUP_MAX       = 5;

const SESSION_COOKIE = 'hh_session';

/* ── 구글 로그인 ── */
const OAUTH_COOKIE = 'hh_oauth';
const OAUTH_TTL_MS = 10 * 60 * 1000;   // 구글에 다녀오는 데 주는 시간
const GOOGLE_AUTH  = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN = 'https://oauth2.googleapis.com/token';
const GOOGLE_ISS   = ['accounts.google.com', 'https://accounts.google.com'];

/* 연령대. 통계를 내려고 받는 값이라 이 여섯 중 하나이거나 아예 없거나입니다. */
const AGE_BANDS = ['10s', '20s', '30s', '40s', '50s', '60s'];
function validAge(v) { return AGE_BANDS.indexOf(String(v)) >= 0; }

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    try {
      /* 약관과 방침은 로그인 없이 누구나 볼 수 있어야 합니다.
         구글도 앱을 게시하기 전에 이 주소들을 확인합니다. */
      if (path === '/privacy' || path === '/terms') return legalPage(path.slice(1), env);

      if (path.startsWith('/auth/')) return await handleAuth(req, env, url);

      if (path === '/api/me') {
        const u = await currentUser(req, env);
        if (!u) return json({ error: 'unauthorized', login: '/auth/login' }, 401);
        return json({
          email: u.email, name: u.name, mode: 'password',
          photos: true, photoStore: env.PHOTOS ? 'r2' : 'db', admin: isAdmin(env, u),
          photoMax: env.PHOTOS ? MAX_PHOTO : MAX_PHOTO_DB,
          book: u.book, books: await myBooks(env, u.key)
        });
      }

      if (path.startsWith('/api/') || path.startsWith('/photo/')) {
        const u = await currentUser(req, env);
        if (!u) return json({ error: 'unauthorized', login: '/auth/login' }, 401);
        if (req.method !== 'GET' && !sameOrigin(req, url)) {
          return json({ error: '요청 출처가 올바르지 않습니다' }, 403);
        }
        if (path.startsWith('/api/admin/')) return await handleAdmin(req, env, url, u);
        return await handleApi(req, env, url, u);
      }

      if (path.startsWith('/join/')) return await handleJoin(req, env, url);

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
  /* 로컬 테스트용. 장부까지 붙여 줘야 API 가 돕니다. */
  if (env.ALLOW_OPEN === '1') {
    const u = { email: 'open@local', name: '공용', key: 'open@local' };
    const row = await env.DB.prepare(
      'SELECT current_book FROM users WHERE email = ?').bind(u.key).first();
    u.book = await resolveBook(env, u, row && row.current_book);
    return u;
  }

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
    'SELECT email, name, session_epoch, current_book FROM users WHERE email = ?').bind(d.e).first();
  if (!row) return null;
  if (Number(d.v || 0) !== Number(row.session_epoch)) return null;   // 비밀번호를 바꾸면 옛 세션이 끊깁니다

  const u = { email: row.email, name: row.name || row.email.split('@')[0], key: row.email };
  u.book = await resolveBook(env, u, row.current_book);
  return u;
}

/* ═══ 장부 ══════════════════════════════════
 * 한 장부를 여러 사람이 함께 씁니다. 모든 읽기와 쓰기는 book_id 로 걸리고,
 * 참여자가 아니면 아무것도 보이지 않습니다.
 */
async function resolveBook(env, u, wanted) {
  if (wanted) {
    const m = await env.DB.prepare(
      'SELECT b.id, b.name, b.owner_key, m.role FROM book_members m ' +
      'JOIN books b ON b.id = m.book_id WHERE m.book_id = ? AND m.user_key = ?'
    ).bind(wanted, u.key).first();
    if (m) return { id: m.id, name: m.name, owner: m.owner_key, role: m.role };
  }
  const any = await env.DB.prepare(
    'SELECT b.id, b.name, b.owner_key, m.role FROM book_members m ' +
    'JOIN books b ON b.id = m.book_id WHERE m.user_key = ? ORDER BY m.joined_at LIMIT 1'
  ).bind(u.key).first();
  if (any) {
    await env.DB.prepare('UPDATE users SET current_book = ? WHERE email = ?').bind(any.id, u.key).run();
    return { id: any.id, name: any.name, owner: any.owner_key, role: any.role };
  }
  return await createBook(env, u.key, (u.name || u.key.split('@')[0]) + '의 장부');
}

async function createBook(env, ownerKey, name) {
  const id = 'b_' + crypto.randomUUID().replace(/-/g, '').slice(0, 18);
  const at = nowIso();
  await env.DB.batch([
    env.DB.prepare('INSERT INTO books (id, name, owner_key, created_at) VALUES (?,?,?,?)')
      .bind(id, name, ownerKey, at),
    env.DB.prepare('INSERT INTO book_members (book_id, user_key, role, joined_at) VALUES (?,?,?,?)')
      .bind(id, ownerKey, 'owner', at),
    env.DB.prepare('UPDATE users SET current_book = ? WHERE email = ?').bind(id, ownerKey)
  ]);
  return { id, name, owner: ownerKey, role: 'owner' };
}

async function myBooks(env, key) {
  const r = await env.DB.prepare(
    'SELECT b.id, b.name, m.role, (SELECT COUNT(*) FROM book_members x WHERE x.book_id = b.id) AS people ' +
    'FROM book_members m JOIN books b ON b.id = m.book_id WHERE m.user_key = ? ORDER BY m.joined_at'
  ).bind(key).all();
  return r.results || [];
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
function isAdmin(env, u) {
  const a = String(env.ADMIN_EMAIL || '').trim().toLowerCase();
  return !!a && !!u && u.key === a;
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

  /* ── 구글로 시작하기 ──
   * 흔한 순서 그대로입니다. 여기서 임의값 세 개(state·nonce·PKCE 검증값)를 만들어
   * 서명한 쿠키에 담아 두고, 구글에 다녀온 뒤 그 쿠키와 맞춰 봅니다.
   * 쿠키는 서명돼 있으므로 남이 지어낸 값으로는 통과하지 못합니다.
   */
  if (path === '/auth/google' && req.method === 'GET') {
    if (!googleOn(env)) return redirect(url.origin + '/auth/login?e=' + encodeURIComponent('구글 로그인이 아직 켜져 있지 않습니다'));
    const st = {
      s: b64(crypto.getRandomValues(new Uint8Array(24))),
      n: b64(crypto.getRandomValues(new Uint8Array(16))),
      v: b64(crypto.getRandomValues(new Uint8Array(32))),
      next: safeNext(url.searchParams.get('next')),
      x: Date.now() + OAUTH_TTL_MS
    };
    const q = new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      redirect_uri: redirectUri(url),
      response_type: 'code',
      scope: 'openid email profile',
      state: st.s,
      nonce: st.n,
      code_challenge: await s256(st.v),
      code_challenge_method: 'S256',
      prompt: 'select_account'
    });
    const h = new Headers({ location: GOOGLE_AUTH + '?' + q.toString() });
    h.append('set-cookie', await oauthCookie(env, st, secure));
    return new Response(null, { status: 302, headers: h });
  }

  if (path === '/auth/google/callback' && req.method === 'GET') {
    const back = (msg) => {
      const h = new Headers({ location: url.origin + '/auth/login?e=' + encodeURIComponent(msg) });
      h.append('set-cookie', killCookie(OAUTH_COOKIE, secure));
      return new Response(null, { status: 302, headers: h });
    };
    if (!googleOn(env)) return back('구글 로그인이 아직 켜져 있지 않습니다');

    const st = await readOauthCookie(req, env);
    if (!st) return back('로그인이 시간을 넘겼습니다. 다시 해주세요');
    if (url.searchParams.get('error')) return back('구글 로그인을 그만두었습니다');

    const code = String(url.searchParams.get('code') || '');
    if (!code || !eqStr(String(url.searchParams.get('state') || ''), st.s)) {
      return back('로그인 정보가 맞지 않습니다. 다시 해주세요');
    }

    let claims;
    try { claims = await googleClaims(env, url, code, st); }
    catch (e) { return back((e && e.message) || '구글에서 정보를 받지 못했습니다'); }

    const email = String(claims.email || '').toLowerCase();
    if (!validEmail(email)) return back('구글 계정에서 이메일을 받지 못했습니다');
    if (claims.email_verified !== true && claims.email_verified !== 'true') {
      return back('구글에서 이메일 확인이 끝나지 않은 계정입니다');
    }

    const allow = (env.ALLOWED_EMAILS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    if (allow.length && allow.indexOf(email) < 0) return back('이 이메일은 초대 목록에 없습니다');

    /* 구글로는 초대 없이도 시작할 수 있습니다. 구글이 이미 사람을 한 번 걸러 주고,
       계정마다 자기 장부가 따로 생기므로 남의 장부가 보이지는 않습니다.
       한 곳에서 계정을 무더기로 찍어내는 것만 아이피로 막습니다.
       (이메일·비밀번호 가입은 초대 링크가 있어야 합니다 — /auth/signup) */
    const ipKey = 's:' + clientIp(req);
    const gate = (await rateBlocked(env, ipKey))
      ? { ok: false, why: '가입 시도가 너무 많습니다. 잠시 뒤에 다시 해주세요' }
      : { ok: true };

    const r = await linkGoogleUser(env, email, String(claims.sub || ''), claims.name, gate);
    if (r.error) return back(r.error);
    if (r.created) await rateFail(env, ipKey, SIGNUP_WINDOW_MS, SIGNUP_MAX, SIGNUP_WINDOW_MS);

    /* 막 만들어진 계정이면 연령대를 한 번 묻고 앱으로 보냅니다 */
    const to = r.created ? '/auth/age?next=' + encodeURIComponent(st.next) : st.next;
    const h = new Headers({ location: url.origin + to });
    h.append('set-cookie', await sessionCookie(env, email, r.epoch, secure));
    h.append('set-cookie', killCookie(OAUTH_COOKIE, secure));
    return new Response(null, { status: 302, headers: h });
  }

  /* ── 연령대 묻기 ── */
  if (path === '/auth/age' && req.method === 'GET') {
    const u = await currentUser(req, env);
    if (!u) return redirect(url.origin + '/auth/login');
    return agePage(safeNext(url.searchParams.get('next')));
  }

  if (path === '/auth/login' && req.method === 'GET') {
    const u = await currentUser(req, env);
    if (u) return redirect(url.origin + '/');
    return authPage('login', null, safeNext(url.searchParams.get('next')), false, '',
      googleOn(env), url.searchParams.get('e') || '');
  }

  if (path === '/auth/signup' && req.method === 'GET') {
    const nx = safeNext(url.searchParams.get('next'));
    const invitedTo = await inviteOk(env, nx);
    /* 초대도 없고 가입 코드도 꺼져 있으면 새로 시작할 길이 없습니다.
       빈 폼을 보여주고 다 채운 뒤에 막기보다, 먼저 알려 줍니다. */
    if (!invitedTo && !env.SIGNUP_CODE) return inviteOnlyPage(googleOn(env));
    return authPage('signup', null, nx, invitedTo,
      url.searchParams.get('code') || '', googleOn(env));
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
    /* 구글로만 들어온 계정은 pw 가 비어 있습니다. 그때도 같은 시간을 쓰게 해서,
       응답이 빨리 온다는 것만으로 "이 계정은 구글 전용"임을 알아채지 못하게 합니다. */
    const ok = (row && row.pw) ? await verifyKey(body.key, row.pw) : (await dummyWork(), false);
    if (!ok) {
      await rateFail(env, emKey, LOGIN_WINDOW_MS, LOGIN_MAX_FAIL, LOGIN_LOCK_MS);
      await rateFail(env, ipKey, LOGIN_WINDOW_MS, LOGIN_MAX_FAIL * 3, LOGIN_LOCK_MS);
      return json({ error: '이메일 또는 비밀번호가 맞지 않습니다' }, 401);
    }

    await rateClear(env, emKey);
    await env.DB.prepare('UPDATE users SET last_login = ? WHERE email = ?').bind(nowIso(), email).run();
    const h = new Headers({ 'content-type': 'application/json; charset=utf-8' });
    h.append('set-cookie', await sessionCookie(env, email, row.session_epoch, secure));
    return new Response(JSON.stringify({ ok: true, next: safeNext(body.next) }), { headers: h });
  }

  /* ── 회원가입 ── */
  if (path === '/auth/signup') {
    const ipKey = 's:' + clientIp(req);
    const blocked = await rateBlocked(env, ipKey);
    if (blocked) return json({ error: '가입 시도가 너무 많습니다. ' + minutesLeft(blocked) + '분 뒤에 다시 해주세요' }, 429);

    const invitedTo = await inviteOk(env, safeNext(body.next));
    if (!invitedTo) {
      const code = env.SIGNUP_CODE || '';
      if (!code) return json({ error: '가입이 닫혀 있습니다. 초대 링크를 받아 들어오세요' }, 403);
      if (!eqStr(String(body.code || '').trim(), code)) {
        await rateFail(env, ipKey, SIGNUP_WINDOW_MS, SIGNUP_MAX, SIGNUP_WINDOW_MS);
        return json({ error: '가입 코드가 맞지 않습니다' }, 403);
      }
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
      'INSERT INTO users (email, name, pw, session_epoch, created_at, provider, age_band) VALUES (?,?,?,1,?,?,?)'
    ).bind(email, name, pw, nowIso(), 'password', validAge(body.age) ? body.age : null).run();
    await rateFail(env, ipKey, SIGNUP_WINDOW_MS, SIGNUP_MAX, SIGNUP_WINDOW_MS);

    const h = new Headers({ 'content-type': 'application/json; charset=utf-8' });
    h.append('set-cookie', await sessionCookie(env, email, 1, secure));
    return new Response(JSON.stringify({ ok: true, next: safeNext(body.next) }), { headers: h });
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

  /* ── 연령대 저장 ──
   * 안 밝히고 넘어가도 됩니다. 그때는 age_band 가 비고, 통계에서 '안 밝힘'으로 셉니다.
   */
  if (path === '/auth/age') {
    const u = await currentUser(req, env);
    if (!u) return json({ error: '로그인이 필요합니다' }, 401);
    const age = validAge(body.age) ? body.age : null;
    await env.DB.prepare('UPDATE users SET age_band = ? WHERE email = ?').bind(age, u.key).run();
    return json({ ok: true, next: safeNext(body.next) });
  }

  return new Response('없는 경로입니다', { status: 404, headers: baseHeaders() });
}

/* ═══ 구글 로그인 ═══════════════════════════
 * 비밀은 둘 다 secret 으로 넣습니다. 하나라도 없으면 구글 버튼이 아예 안 나옵니다.
 *   npx wrangler secret put GOOGLE_CLIENT_ID
 *   npx wrangler secret put GOOGLE_CLIENT_SECRET
 */
function googleOn(env) { return !!(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET); }
function redirectUri(url) { return url.origin + '/auth/google/callback'; }

async function s256(v) {
  return b64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v))));
}

async function oauthCookie(env, st, secure) {
  const payload = enc(JSON.stringify(st));
  const sig = await sign(env, payload);
  return OAUTH_COOKIE + '=' + payload + '.' + sig +
    '; Path=/auth; Max-Age=' + Math.round(OAUTH_TTL_MS / 1000) +
    '; HttpOnly; SameSite=Lax' + (secure ? '; Secure' : '');
}
async function readOauthCookie(req, env) {
  const raw = readCookie(req, OAUTH_COOKIE);
  if (!raw) return null;
  const cut = raw.lastIndexOf('.');
  if (cut < 0) return null;
  const payload = raw.slice(0, cut);
  if (!(await sigOk(env, payload, raw.slice(cut + 1)))) return null;
  let st;
  try { st = JSON.parse(dec(payload)); } catch (e) { return null; }
  if (!st || !st.s || !st.n || !st.v || !st.x || st.x < Date.now()) return null;
  return st;
}
function killCookie(name, secure) {
  return name + '=; Path=/auth; Max-Age=0; HttpOnly; SameSite=Lax' + (secure ? '; Secure' : '');
}

/* 받은 코드를 구글에 주고 사람 정보를 받아 옵니다.
 * id_token 의 서명은 따로 확인하지 않습니다. 브라우저를 거치지 않고 구글의 토큰 창구에
 * 우리가 직접 HTTPS 로 물어봐서 받은 값이라, 중간에 누가 바꿔치기할 자리가 없습니다.
 * (OpenID Connect Core 3.1.3.7) 대신 누구에게·누가·언제 발급했는지는 모두 맞춰 봅니다.
 */
async function googleClaims(env, url, code, st) {
  const r = await fetch(GOOGLE_TOKEN, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri(url),
      grant_type: 'authorization_code',
      code_verifier: st.v
    }).toString()
  });
  if (!r.ok) throw new Error('구글이 로그인을 받아주지 않았습니다');

  const t = await r.json();
  const parts = String(t.id_token || '').split('.');
  if (parts.length !== 3) throw new Error('구글이 보낸 정보를 읽지 못했습니다');

  let c;
  try { c = JSON.parse(dec(parts[1])); } catch (e) { throw new Error('구글이 보낸 정보를 읽지 못했습니다'); }
  if (GOOGLE_ISS.indexOf(String(c.iss)) < 0) throw new Error('구글이 보낸 정보가 아닙니다');
  if (!eqStr(String(c.aud || ''), String(env.GOOGLE_CLIENT_ID))) throw new Error('다른 앱에 발급된 정보입니다');
  if (!(Number(c.exp) * 1000 > Date.now())) throw new Error('구글이 보낸 정보가 오래됐습니다');
  if (!eqStr(String(c.nonce || ''), st.n)) throw new Error('로그인 정보가 맞지 않습니다');
  return c;
}

/* 구글에서 온 사람을 계정에 잇습니다.
 * 사람을 알아보는 기준은 이메일이 아니라 구글이 주는 sub 입니다. 구글에서 이메일을
 * 바꿔도 같은 사람으로 남고, 남이 그 이메일을 새로 받아도 남의 장부로는 못 들어갑니다.
 */
async function linkGoogleUser(env, email, sub, name, gate) {
  if (!sub) return { error: '구글 계정을 알아보지 못했습니다' };
  const at = nowIso();

  const bySub = await env.DB.prepare(
    'SELECT email, session_epoch FROM users WHERE google_sub = ?').bind(sub).first();
  if (bySub) {
    await env.DB.prepare('UPDATE users SET last_login = ? WHERE email = ?').bind(at, bySub.email).run();
    return { email: bySub.email, epoch: Number(bySub.session_epoch), created: false };
  }

  /* 같은 이메일로 이미 비밀번호 계정이 있으면 한 계정으로 합칩니다.
     구글이 email_verified 를 준 뒤에만 여기까지 옵니다. */
  const byEmail = await env.DB.prepare(
    'SELECT email, session_epoch FROM users WHERE email = ?').bind(email).first();
  if (byEmail) {
    await env.DB.prepare(
      "UPDATE users SET google_sub = ?, last_login = ?, " +
      "provider = CASE WHEN pw IS NULL THEN 'google' ELSE 'both' END WHERE email = ?"
    ).bind(sub, at, email).run();
    return { email: byEmail.email, epoch: Number(byEmail.session_epoch), created: false };
  }

  /* 여기까지 왔으면 처음 보는 사람입니다. 만들어도 되는지는 부르는 쪽이 정합니다. */
  if (!gate || !gate.ok) return { error: (gate && gate.why) || '지금은 새로 시작할 수 없습니다' };

  const nm = String(name || '').trim().slice(0, 40) || email.split('@')[0];
  try {
    await env.DB.prepare(
      'INSERT INTO users (email, name, pw, session_epoch, created_at, last_login, provider, google_sub) ' +
      'VALUES (?,?,NULL,1,?,?,?,?)'
    ).bind(email, nm, at, at, 'google', sub).run();
  } catch (e) {
    return { error: '계정을 만들지 못했습니다. 잠시 뒤에 다시 해주세요' };
  }
  return { email, epoch: 1, created: true };
}

/* ═══ 로그인·가입 화면 ══════════════════════ */
/* 로그인 뒤 돌아갈 주소는 이 사이트 안이어야 한다. //evil.com 같은 값을 막는다. */
function safeNext(next) {
  if (typeof next !== 'string' || !next) return '/';
  if (next[0] !== '/' || next[1] === '/' || next[1] === '\\') return '/';
  return next;
}

function authPage(kind, email, next, invitedTo, codeHint, google, notice) {
  const nonce = b64(crypto.getRandomValues(new Uint8Array(16)));
  const T = {
    login:    { title: '하우스헌팅', lead: '로그인', btn: '로그인', path: '/auth/login' },
    signup:   { title: '하우스헌팅', lead: '회원가입', btn: '가입하고 시작하기', path: '/auth/signup' },
    password: { title: '하우스헌팅', lead: '비밀번호 변경', btn: '비밀번호 바꾸기', path: '/auth/password' }
  }[kind];

  const fields =
    kind === 'signup' ? [
      invitedTo ? '<p class="who">' + esc(invitedTo) + '에 초대받았습니다</p>' : '',
      row('email', '이메일', 'email', 'username', '', true),
      row('name', '이름 (안 써도 됩니다)', 'text', 'name'),
      row('pw', '비밀번호', 'password', 'new-password', MIN_PW + '자 이상'),
      row('pw2', '비밀번호 다시', 'password', 'new-password'),
      ageRow(),
      invitedTo ? '' : row('code', '가입 코드', 'text', 'off', '받은 코드', false, codeHint)
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

  const q = next && next !== '/' ? '?next=' + encodeURIComponent(next) : '';
  const foot =
    kind === 'login'  ? '<p class="alt">처음이신가요? <a href="/auth/signup' + q + '">시작하기</a></p>' :
    kind === 'signup' ? '<p class="alt">이미 계정이 있나요? <a href="/auth/login' + q + '">로그인</a></p>' :
                        '<p class="alt"><a href="/">장부로 돌아가기</a></p>';

  /* 구글 비밀이 들어와 있을 때만 버튼이 생깁니다. 없으면 화면에 흔적도 안 남습니다. */
  const gate = (google && kind !== 'password')
    ? '<a class="gbtn" href="/auth/google' + q + '">' + GOOGLE_MARK + '구글로 계속하기</a>' +
      '<div class="or"><span>또는 이메일로</span></div>'
    : '';

  const html = '<!doctype html><html lang="ko"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta name="color-scheme" content="light dark"><title>' + T.lead + ' · 하우스헌팅</title>' +
    '<link rel="preconnect" href="https://fonts.googleapis.com">' +
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>' +
    '<link href="https://fonts.googleapis.com/css2?family=Jua&family=IBM+Plex+Sans+KR:wght@400;500;600&display=swap" rel="stylesheet">' +
    '<style nonce="' + nonce + '">' + AUTH_CSS + '</style></head><body>' +
    '<main class="card">' +
      SCENE_SVG +
      '<h1>' + T.title + '</h1><p class="lead">' + T.lead + '</p>' +
      '<div class="prog" id="prog" aria-hidden="true"><i></i></div>' + gate +
      '<form id="f" novalidate>' + fields +
        '<p class="err" id="err"' + (notice ? '>' + esc(notice) : ' hidden>') + '</p>' +
        '<button type="submit" id="go">' + T.btn + '</button>' +
      '</form>' + foot +
      '<p class="fine"><a href="/privacy">개인정보처리방침</a> · <a href="/terms">서비스 약관</a></p>' +
    '</main>' +
    '<script nonce="' + nonce + '">' + authScript(kind, T.path, next) + '</script></body></html>';

  return new Response(html, {
    headers: Object.assign(baseHeaders(), {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': csp(nonce)
    })
  });
}
function row(id, label, type, ac, ph, autofocus, value) {
  return '<label for="' + id + '">' + label + '</label>' +
    '<input id="' + id + '" type="' + type + '" autocomplete="' + ac + '"' +
    (ph ? ' placeholder="' + esc(ph) + '"' : '') +
    (value ? ' value="' + esc(value) + '"' : '') + (autofocus ? ' autofocus' : '') + '>';
}

function ageLabel(a) { return a === '60s' ? '60대 이상' : String(a).replace('s', '') + '대'; }
function ageRow(value) {
  return '<label for="age">연령대</label><select id="age">' +
    '<option value="">밝히지 않음</option>' +
    AGE_BANDS.map(a => '<option value="' + a + '"' + (a === value ? ' selected' : '') + '>' +
      ageLabel(a) + '</option>').join('') + '</select>';
}

const GOOGLE_MARK = '<svg class="g" viewBox="0 0 48 48" width="18" height="18" aria-hidden="true">' +
  '<path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>' +
  '<path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>' +
  '<path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>' +
  '<path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>';

/* 초대 없이 가입 화면에 들어온 사람에게 보여 줍니다.
   구글로는 그냥 시작할 수 있으므로 그 길은 열어 둡니다. */
function inviteOnlyPage(google) {
  const nonce = b64(crypto.getRandomValues(new Uint8Array(16)));
  const html = '<!doctype html><html lang="ko"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta name="color-scheme" content="light dark"><title>시작하기 · 하우스헌팅</title>' +
    '<link rel="preconnect" href="https://fonts.googleapis.com">' +
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>' +
    '<link href="https://fonts.googleapis.com/css2?family=Jua&family=IBM+Plex+Sans+KR:wght@400;500;600&display=swap" rel="stylesheet">' +
    '<style nonce="' + nonce + '">' + AUTH_CSS + '</style></head><body>' +
    '<main class="card">' + SCENE_SVG +
      '<h1>하우스헌팅</h1><p class="lead">시작하기</p>' +
      (google
        ? '<a class="gbtn" href="/auth/google">' + GOOGLE_MARK + '구글로 계속하기</a>' +
          '<div class="or"><span>또는 이메일로</span></div>'
        : '') +
      '<p class="who">이메일과 비밀번호로 시작하려면 초대 링크가 필요합니다.</p>' +
      '<p class="alt">이미 계정이 있나요? <a href="/auth/login">로그인</a></p>' +
      '<p class="fine"><a href="/privacy">개인정보처리방침</a> · <a href="/terms">서비스 약관</a></p>' +
    '</main></body></html>';

  return new Response(html, {
    headers: Object.assign(baseHeaders(), {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': csp(nonce)
    })
  });
}

/* 구글로 막 들어온 사람에게 연령대만 한 번 묻습니다. 건너뛰어도 그만입니다. */
function agePage(next) {
  const nonce = b64(crypto.getRandomValues(new Uint8Array(16)));
  const html = '<!doctype html><html lang="ko"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta name="color-scheme" content="light dark"><title>시작하기 · 하우스헌팅</title>' +
    '<link rel="preconnect" href="https://fonts.googleapis.com">' +
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>' +
    '<link href="https://fonts.googleapis.com/css2?family=Jua&family=IBM+Plex+Sans+KR:wght@400;500;600&display=swap" rel="stylesheet">' +
    '<style nonce="' + nonce + '">' + AUTH_CSS + '</style></head><body>' +
    '<main class="card">' + SCENE_SVG +
      '<h1>하우스헌팅</h1><p class="lead">시작하기 전에</p>' +
      '<p class="who">연령대 하나만 골라 주세요. 또래가 어떤 집을 보고 있는지 견주는 데만 씁니다.</p>' +
      '<form id="f" novalidate>' + ageRow() +
        '<p class="err" id="err" hidden></p>' +
        '<button type="submit" id="go">시작하기</button>' +
      '</form>' +
      '<p class="alt"><a id="skip" href="' + esc(next) + '">그냥 넘어가기</a></p>' +
    '</main>' +
    '<script nonce="' + nonce + '">' + ageScript(next) + '</script></body></html>';

  return new Response(html, {
    headers: Object.assign(baseHeaders(), {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': csp(nonce)
    })
  });
}

/* ═══ 약관과 개인정보처리방침 ══════════════
 * 실제로 무엇을 받아 어디에 두는지 코드와 맞춰 적습니다.
 * 저장하는 값이나 보관 기간을 바꾸면 이 글도 같이 고쳐야 합니다.
 */
const LEGAL_FROM = '2026년 9월 16일';
const LEGAL_MAIL = 'mythe1004@gmail.com';

function legalPage(kind, env) {
  const nonce = b64(crypto.getRandomValues(new Uint8Array(16)));
  const doc = kind === 'privacy' ? privacyDoc(env) : termsDoc();
  const other = kind === 'privacy'
    ? '<a href="/terms">서비스 약관</a>'
    : '<a href="/privacy">개인정보처리방침</a>';

  const html = '<!doctype html><html lang="ko"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta name="color-scheme" content="light dark"><title>' + doc.title + ' · 하우스헌팅</title>' +
    '<link rel="preconnect" href="https://fonts.googleapis.com">' +
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>' +
    '<link href="https://fonts.googleapis.com/css2?family=Jua&family=IBM+Plex+Sans+KR:wght@400;500;600&display=swap" rel="stylesheet">' +
    '<style nonce="' + nonce + '">' + AUTH_CSS + LEGAL_CSS + '</style></head><body>' +
    '<main class="doc">' +
      '<p class="crumb"><a href="/">하우스헌팅</a></p>' +
      '<h1>' + doc.title + '</h1>' +
      '<p class="when">시행일 ' + LEGAL_FROM + '</p>' +
      doc.body +
      '<hr><p class="alt">' + other + ' · <a href="/auth/login">로그인</a></p>' +
    '</main></body></html>';

  return new Response(html, {
    headers: Object.assign(baseHeaders(), {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'public, max-age=3600',
      'content-security-policy': csp(nonce)
    })
  });
}

function privacyDoc(env) {
  const photoWhere = env && env.PHOTOS
    ? 'Cloudflare R2 저장소'
    : '데이터베이스 안(Cloudflare D1)';
  return {
    title: '개인정보처리방침',
    body: [
      '<p class="lede">하우스헌팅은 집을 고르는 동안 후보를 모아 견주어 보는 장부입니다. ' +
        '아래는 이 서비스가 무엇을 받아 어디에 두는지 그대로 적은 것입니다.</p>',

      '<h2>무엇을 받나</h2>',
      '<h3>계정을 만들 때</h3>',
      '<ul>' +
        '<li><b>이메일 주소</b> — 계정을 가려내는 값입니다. 꼭 필요합니다.</li>' +
        '<li><b>이름</b> — 안 쓰셔도 됩니다. 비우면 이메일 앞부분을 씁니다.</li>' +
        '<li><b>비밀번호</b> — 원문은 서버에 도착하지 않습니다. 브라우저가 PBKDF2로 60만 번 늘린 ' +
          '결과만 보내고, 서버는 거기에 임의의 소금을 섞어 1만 2천 번 더 늘려 저장합니다.</li>' +
        '<li><b>연령대</b> — 안 밝히셔도 됩니다. 또래끼리 어떤 조건의 집을 보는지 견주는 통계에만 씁니다.</li>' +
        '<li><b>구글로 시작하신 경우</b> — 구글이 주는 계정 고유 번호(sub)와 이메일, 이름을 받습니다. ' +
          '구글 비밀번호는 받지 않습니다.</li>' +
      '</ul>',
      '<h3>쓰시는 동안 쌓이는 것</h3>',
      '<ul>' +
        '<li>가입한 날과 마지막으로 로그인한 날</li>' +
        '<li><b>장부에 적으신 매물 내용 전부</b> — 이름, 주소, 금액, 면적, 좋은 점과 아쉬운 점, 메모, ' +
          '중개사무소 이름과 전화번호처럼 직접 넣으신 값이 그대로 들어갑니다.</li>' +
        '<li>올리신 매물 사진</li>' +
        '<li>금리나 별점 항목 같은 장부 설정</li>' +
        '<li>로그인이 거듭 실패할 때 잠시 두는 접속 아이피와 실패 횟수</li>' +
      '</ul>',

      '<h2>왜 받나</h2>',
      '<ul>' +
        '<li>장부를 보여주고, 같은 장부에 든 사람끼리 같은 내용을 보게 하려고</li>' +
        '<li>로그인을 유지하고, 남이 비밀번호를 찍어 맞히는 것을 막으려고</li>' +
        '<li>연령대별로 어떤 금액과 넓이의 집을 보고 있는지 모아 보려고. ' +
          '이 통계는 <b>합계와 평균으로만</b> 만들고, 누가 어떤 집을 봤는지 따로 드러내지 않습니다.</li>' +
      '</ul>',

      '<h2>어디에 두나</h2>',
      '<p>Cloudflare 의 데이터베이스(D1)에 둡니다. 사진은 ' + photoWhere + '에 있습니다. ' +
        '서비스도 Cloudflare 위에서 돕니다. 광고나 분석 도구는 하나도 붙어 있지 않습니다.</p>',

      '<h2>얼마나 두나</h2>',
      '<ul>' +
        '<li>계정과 매물은 <b>지우실 때까지</b> 둡니다.</li>' +
        '<li>실수로 지웠을 때를 위해 데이터베이스가 <b>30일</b> 동안 되돌릴 수 있는 기록을 갖고 있습니다.</li>' +
        '<li>매일 한 번 전체를 암호로 잠가 백업하고 <b>90일</b> 뒤 자동으로 지웁니다.</li>' +
        '<li>로그인 실패 기록은 잠금이 풀리면 지웁니다.</li>' +
      '</ul>',

      '<h2>누구에게 가나</h2>',
      '<p>팔지 않고, 광고에 쓰지 않고, 물어보지 않은 곳에 넘기지 않습니다. 다만 서비스를 돌리려면 ' +
        '아래 세 곳을 거칩니다.</p>',
      '<ul>' +
        '<li><b>Cloudflare</b> — 서비스와 데이터베이스가 올라가 있는 곳입니다.</li>' +
        '<li><b>Google</b> — 구글로 로그인하실 때만, 그 계정이 맞는지 확인하려고 오갑니다.</li>' +
        '<li><b>Google Fonts</b> — 화면 글꼴을 <code>fonts.googleapis.com</code> 과 ' +
          '<code>fonts.gstatic.com</code> 에서 받아옵니다. 이때 접속하신 아이피와 브라우저 종류가 ' +
          '구글에 전달됩니다.</li>' +
      '</ul>',

      '<h2>브라우저에 남는 것</h2>',
      '<ul>' +
        '<li><code>hh_session</code> — 로그인을 유지하는 쿠키입니다. 30일 뒤 만료되고, ' +
          '자바스크립트로는 읽을 수 없게 막아 두었습니다.</li>' +
        '<li><code>hh_oauth</code> — 구글에 다녀오는 10분 동안만 있는 쿠키입니다.</li>' +
        '<li>매물과 설정의 사본이 브라우저 저장소에 남습니다. 화면을 빨리 띄우려는 것이고, ' +
          '로그아웃하면 지웁니다.</li>' +
      '</ul>',
      '<p>광고나 추적에 쓰는 쿠키는 없습니다.</p>',

      '<h2>지우고 싶을 때</h2>',
      '<ul>' +
        '<li>매물은 장부에서 하나씩 지울 수 있습니다.</li>' +
        '<li>계정을 통째로 지우시려면 아래 주소로 알려 주세요. 계정과 주인으로 있는 장부, ' +
          '그 안의 매물·사진·설정을 함께 지웁니다.</li>' +
        '<li>지운 뒤에도 위에 적은 백업에는 최대 90일 동안 남아 있다가 사라집니다.</li>' +
      '</ul>',

      '<h2>물어보실 곳</h2>',
      '<p><a href="mailto:' + LEGAL_MAIL + '">' + LEGAL_MAIL + '</a></p>',
      '<p class="note">이 글이 바뀌면 시행일을 고치고 이 페이지에 그대로 둡니다.</p>'
    ].join('')
  };
}

function termsDoc() {
  return {
    title: '서비스 약관',
    body: [
      '<p class="lede">하우스헌팅은 개인이 무료로 만들어 두는 집 고르기 장부입니다. ' +
        '쓰시기 전에 아래를 한 번 읽어 주세요.</p>',

      '<h2>어떤 서비스인가</h2>',
      '<p>전세와 매매 후보를 모아 금액과 넓이, 점수를 견주어 보는 도구입니다. ' +
        '중개를 하지 않고, 매물을 팔거나 소개하지 않으며, 어떤 거래에도 끼지 않습니다.</p>',

      '<h2>계정</h2>',
      '<ul>' +
        '<li>본인이 쓰는 이메일로 만들어 주세요.</li>' +
        '<li>비밀번호는 본인이 지킵니다. 남과 나누지 마세요.</li>' +
        '<li>한 장부에 6명까지 초대해 함께 볼 수 있습니다. 초대한 사람은 그 장부의 매물을 ' +
          '모두 읽고 고칠 수 있으니, 아는 사람에게만 링크를 주세요.</li>' +
      '</ul>',

      '<h2>적으신 내용</h2>',
      '<ul>' +
        '<li>장부에 적으신 내용은 적으신 분의 것입니다. 서비스를 돌리는 데 필요한 만큼 ' +
          '(저장하고, 화면에 보여주고, 백업하는 것) 말고는 쓰지 않습니다.</li>' +
        '<li>남의 개인정보를 함부로 올리지 말아 주세요. 중개사무소 연락처처럼 업무로 공개된 ' +
          '정보라도 필요한 만큼만 적어 두시길 권합니다.</li>' +
      '</ul>',

      '<h2>하지 말아야 할 것</h2>',
      '<ul>' +
        '<li>자동화 도구로 계정이나 매물을 무더기로 만드는 일</li>' +
        '<li>남의 계정이나 장부에 들어가려 시도하는 일</li>' +
        '<li>법을 어기는 목적으로 쓰는 일</li>' +
      '</ul>',
      '<p>이런 일이 확인되면 계정을 막거나 지울 수 있습니다.</p>',

      '<h2>꼭 알아두실 것</h2>',
      '<ul>' +
        '<li><b>계산 값은 참고용입니다.</b> 월 환산 금액, 점수, 예산 상한은 넣으신 숫자로 ' +
          '단순하게 셈한 추정입니다. 실제 대출 조건과 금리, 세금, 중개 수수료는 이와 다릅니다.</li>' +
        '<li><b>매물 정보는 확인하지 않습니다.</b> 화면에 보이는 값은 이용자가 직접 적은 것이고 ' +
          '운영자가 맞는지 살피지 않습니다.</li>' +
        '<li><b>거래 판단은 이용자 책임입니다.</b> 이 장부를 보고 내린 결정과 그 결과에 대해 ' +
          '운영자는 책임지지 않습니다. 계약 전에는 반드시 등기부와 현장, 중개사를 통해 확인하세요.</li>' +
        '<li><b>개인이 무료로 굴리는 서비스입니다.</b> 끊김 없는 제공이나 데이터가 영원히 남는 것을 ' +
          '약속하지 않습니다. 중요한 내용은 따로 적어 두시길 권합니다.</li>' +
      '</ul>',

      '<h2>한도</h2>',
      '<p>서버가 감당할 만큼만 두려고 아래처럼 막아 두었습니다.</p>',
      '<ul>' +
        '<li>한 장부에 매물 ' + MAX_PROPS + '곳, 사람 ' + MAX_MEMBERS + '명까지</li>' +
        '<li>사진은 한 장부에 ' + MAX_PHOTOS_DB + '장까지, 한 장에 ' +
          Math.round(MAX_PHOTO_DB / 1024) + 'KB 까지</li>' +
      '</ul>',

      '<h2>바뀌거나 멈출 때</h2>',
      '<p>기능이 예고 없이 바뀌거나 서비스가 멈출 수 있습니다. 문을 아주 닫게 되면 ' +
        '데이터를 내려받으실 수 있도록 미리 알리겠습니다. 약관이 바뀌면 이 페이지를 고치고 ' +
        '시행일을 바꿉니다.</p>',

      '<h2>물어보실 곳</h2>',
      '<p><a href="mailto:' + LEGAL_MAIL + '">' + LEGAL_MAIL + '</a></p>'
    ].join('')
  };
}

const LEGAL_CSS = [
  'body{display:block;place-items:initial;min-height:0;padding:0}',
  '.doc{max-width:700px;margin:0 auto;padding:36px 22px 72px;text-align:left}',
  '.crumb{margin:0 0 22px;font-family:Jua,"Apple SD Gothic Neo",sans-serif;font-size:17px}',
  '.crumb a{color:var(--ink);text-decoration:none}',
  '.doc h1{font-size:27px;text-align:left;margin:0 0 4px}',
  '.when{margin:0 0 30px;color:var(--muted);font-size:12.5px}',
  '.lede{margin:0 0 30px;padding:14px 16px;background:var(--sun-soft);border-radius:14px;font-size:14px}',
  '.doc h2{font-family:Jua,"Apple SD Gothic Neo",sans-serif;font-size:19px;font-weight:400;',
  'margin:34px 0 10px;padding-top:16px;border-top:1.5px solid var(--line)}',
  '.doc h3{font-size:14px;font-weight:600;margin:20px 0 8px;color:var(--accent)}',
  '.doc p{margin:0 0 12px;font-size:14.5px;line-height:1.75}',
  '.doc ul{margin:0 0 14px;padding-left:19px}',
  '.doc li{margin:0 0 9px;font-size:14.5px;line-height:1.75}',
  '.doc b{font-weight:600}',
  '.doc code{background:var(--sun-soft);border-radius:5px;padding:1px 5px;font-size:12.5px}',
  '.doc hr{border:0;border-top:1.5px solid var(--line);margin:40px 0 18px}',
  '.note{color:var(--muted);font-size:12.5px;margin-top:26px}'
].join('');

function ageScript(next) {
  return [
    '(function(){',
    '  var NEXT=' + JSON.stringify(next) + ';',
    '  var f=document.getElementById("f"), go=document.getElementById("go");',
    '  f.addEventListener("submit", function(e){',
    '    e.preventDefault(); go.disabled=true;',
    '    fetch("/auth/age",{method:"POST",credentials:"same-origin",',
    '      headers:{"content-type":"application/json"},',
    '      body:JSON.stringify({age:document.getElementById("age").value,next:NEXT})})',
    '     .then(function(r){return r.json()})',
    '     .then(function(j){location.href=(j&&j.next)||NEXT})',
    '     .catch(function(){location.href=NEXT});',
    '  });',
    '})();'
  ].join('\n');
}

const SCENE_SVG = '<div class="pic" aria-hidden="true"><svg viewBox="0 0 240 152" fill="none" stroke="var(--ink)" stroke-width="2.6" stroke-linejoin="round" stroke-linecap="round"><path d="M184 40a9 9 0 0 1 0-18 12 12 0 0 1 22-4 12 12 0 0 1 6 22z" fill="var(--surface)"/><g class="mg"><path d="M67.5 47.5 78.5 58.5" stroke-width="5.5"/><circle cx="55" cy="35" r="14.5" fill="var(--surface)"/></g><rect x="5" y="126" width="230" height="17" rx="8.5" fill="var(--mint)"/><path d="M15.5 126v-16"/><circle cx="15.5" cy="103" r="11" fill="var(--leaf)"/><rect x="30" y="96" width="42" height="30" fill="var(--surface)"/><path d="M24 96 51 73l27 23" fill="var(--leaf)"/><rect x="34.5" y="101" width="9.5" height="9.5" rx="1.5" fill="var(--mint)"/><rect x="52" y="110" width="13" height="16" rx="2" fill="var(--sun)"/><path d="M140 74V57h9.5v11" fill="var(--surface)"/><rect x="92" y="82" width="62" height="44" fill="var(--surface)"/><path d="M85 82 123 51l38 31" fill="var(--sun)"/><rect x="98.5" y="90" width="15" height="15" rx="2" fill="var(--mint)"/><path d="M106 90v15M98.5 97.5h15" stroke-width="2"/><rect x="132.5" y="90" width="15" height="15" rx="2" fill="var(--mint)"/><path d="M140 90v15M132.5 97.5h15" stroke-width="2"/><rect x="113" y="104" width="20" height="22" rx="2.5" fill="var(--surface)"/><circle cx="128" cy="116" r="1.9" fill="var(--ink)" stroke="none"/><rect x="174" y="100" width="40" height="26" fill="var(--surface)"/><path d="M168 100 194 79l26 21" fill="var(--mint)"/><rect x="184" y="106" width="11" height="11" rx="1.5" fill="var(--leaf)"/><path d="M226 126v-14"/><circle cx="226" cy="105" r="9.5" fill="var(--leaf)"/></svg></div>';

const AUTH_CSS = [
':root{--bg:#FFFAF0;--surface:#fff;--ink:#2A2620;--muted:#948A7C;--line:#E4D3BB;',
'--sun:#F2643A;--sun-2:#FF7A52;--sun-ink:#fff;--sun-soft:#FFEBDD;',
'--mint:#B4E5CC;--leaf:#87CC5A;--accent:#2E7D5B;--bad:#B33A24}',
'@media (prefers-color-scheme:dark){:root{--bg:#1C1814;--surface:#252019;--ink:#F5EEE3;--muted:#9C9080;',
'--line:#4E4237;--sun:#F2643A;--sun-2:#FF7A52;--sun-ink:#fff;--sun-soft:#3E271D;',
'--mint:#6FBF9C;--leaf:#8FCB63;--accent:#5FC095;--bad:#E2846A}}',
'*{box-sizing:border-box}',
'body{margin:0;background:var(--bg);color:var(--ink);font-family:"IBM Plex Sans KR","Apple SD Gothic Neo",system-ui,sans-serif;',
'display:grid;place-items:center;min-height:100vh;padding:24px;font-size:15px;line-height:1.6}',
'.card{background:var(--surface);border:1.5px solid var(--line);border-radius:24px;padding:26px 28px 26px;width:min(394px,100%);',
'box-shadow:0 2px 6px rgba(92,70,32,.07),0 20px 46px -24px rgba(92,70,32,.5)}',
'.pic{max-width:268px;margin:0 auto 14px}',
'.pic svg{width:100%;height:auto;display:block}',
'h1{font-family:Jua,"Apple SD Gothic Neo",sans-serif;font-size:23px;font-weight:400;margin:0;line-height:1.2;text-align:center}',
'.lead{margin:2px 0 24px;color:var(--muted);font-size:13px;text-align:center}',
'.who{margin:0 0 20px;padding:9px 14px;background:var(--sun-soft);border-radius:12px;font-size:13px;color:var(--ink);text-align:center}',
'label{display:block;font-size:11.5px;color:var(--muted);font-weight:600;margin:0 0 5px}',
'input,select{width:100%;padding:10px 13px;border:1.5px solid var(--line);border-radius:12px;background:var(--surface);',
'color:var(--ink);font:inherit;font-size:14px;margin-bottom:15px}',
'input:focus,select:focus{outline:none;border-color:var(--sun);box-shadow:0 0 0 3.5px var(--sun-soft)}',
'.gbtn{display:flex;align-items:center;justify-content:center;gap:9px;width:100%;padding:11px;',
'border:1.5px solid var(--line);border-radius:999px;background:var(--surface);color:var(--ink);',
'font-weight:600;font-size:14.5px;text-decoration:none;transition:background .15s}',
'.gbtn:hover{background:var(--sun-soft)}',
'.gbtn .g{flex:none}',
'.or{display:flex;align-items:center;gap:10px;margin:17px 0 15px;color:var(--muted);font-size:12px}',
'.or::before,.or::after{content:"";flex:1;height:1.5px;background:var(--line)}',
'button{width:100%;padding:12px;border:0;border-radius:999px;background:var(--sun);color:var(--sun-ink);',
'font:inherit;font-weight:600;font-size:14.5px;cursor:pointer;margin-top:6px;',
'box-shadow:0 2px 0 color-mix(in srgb,var(--sun) 72%,#000);transition:transform .12s,background .15s}',
'button:hover:not(:disabled){background:var(--sun-2);transform:translateY(-1px)}',
'button:disabled{opacity:.6;cursor:progress}',
'.err{margin:0 0 13px;padding:10px 13px;background:color-mix(in srgb,var(--bad) 13%,transparent);',
'color:var(--bad);border-radius:12px;font-size:13px;line-height:1.5}',
'.prog{height:5px;border-radius:999px;background:var(--sun-soft);overflow:hidden;margin:0 0 16px;visibility:hidden}',
'.prog.on{visibility:visible}',
'.prog i{display:block;height:100%;width:38%;border-radius:999px;background:var(--sun);animation:slide 1.15s ease-in-out infinite}',
'@keyframes slide{0%{transform:translateX(-110%)}100%{transform:translateX(275%)}}',
'@keyframes hunt{0%,100%{transform:translate(0,0)}30%{transform:translate(24px,-3px)}62%{transform:translate(48px,5px)}}',
'.pic.busy .mg{animation:hunt 3.2s ease-in-out infinite}',
'@media (prefers-reduced-motion:reduce){.prog i,.pic.busy .mg{animation:none}}',
'.alt{margin:20px 0 0;font-size:13px;color:var(--muted);text-align:center}',
'.fine{margin:14px 0 0;font-size:11.5px;color:var(--muted);text-align:center}',
'.fine a{color:var(--muted)}',
'a{color:var(--accent);text-underline-offset:3px}',
':focus-visible{outline:2.5px solid var(--sun);outline-offset:2px}',
'@media (prefers-reduced-motion:reduce){*{transition:none!important}}'
].join('');

function authScript(kind, postPath, next) {
  return [
'(function(){',
'"use strict";',
'var ITER=' + CLIENT_ITER + ', MIN=' + MIN_PW + ', KIND=' + JSON.stringify(kind) + ', PATH=' + JSON.stringify(postPath) + ', NEXT=' + JSON.stringify(next || '/') + ';',
'var f=document.getElementById("f"), go=document.getElementById("go"), errBox=document.getElementById("err");',
'var prog=document.getElementById("prog"), pic=document.querySelector(".pic");',
'var label=go.textContent;',
'function busy(on){ prog.classList.toggle("on",on); if(pic) pic.classList.toggle("busy",on);',
' go.disabled=on; go.textContent = on ? "확인 중…" : label; }',
'function val(id){var el=document.getElementById(id);return el?el.value:"";}',
'function fail(m){errBox.textContent=m;errBox.hidden=false;busy(false);}',
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
'  if(document.getElementById("code") && !val("code").trim()) return fail("가입 코드를 넣어 주세요.");',
'  if(val("pw").toLowerCase().indexOf(email.split("@")[0].toLowerCase())>=0) return fail("비밀번호에 이메일을 그대로 쓰지 마세요.");',
' }',
' if(KIND==="password"){',
'  if(val("pw2").length<MIN) return fail("새 비밀번호는 "+MIN+"자 이상이어야 합니다.");',
'  if(val("pw2")!==val("pw3")) return fail("새 비밀번호가 서로 다릅니다.");',
'  if(val("pw")===val("pw2")) return fail("지금 쓰는 비밀번호와 같습니다.");',
' }',
' busy(true);',
' try{',
'  if(KIND==="password"){',
'   var me=document.querySelector(".who").textContent.trim();',
'   body.key=await derive(me,val("pw")); body.newKey=await derive(me,val("pw2"));',
'  }else{',
'   body.email=email; body.key=await derive(email,val("pw"));',
'   if(KIND==="signup"){ body.name=val("name").trim(); body.code=val("code").trim();',
'    var ageSel=document.getElementById("age"); if(ageSel) body.age=ageSel.value; }',
'   body.next=NEXT;',
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

/* ═══ 초대 링크로 합류 ══════════════════════ */
/* next 가 살아 있는 초대 링크면 그 장부 이름을 돌려준다.
 * 초대를 받아 들어오는 사람에게는 가입 코드를 따로 묻지 않는다. */
/* 아직 쓰지 않았고 기한도 남은 초대 링크들 */
async function liveInvites(env, bk, origin) {
  const r = await env.DB.prepare(
    'SELECT token, created_at, expires_at FROM book_invites ' +
    'WHERE book_id = ? AND used_at IS NULL AND expires_at > ? ORDER BY created_at'
  ).bind(bk, Date.now()).all();
  return (r.results || []).map(x => ({
    token: x.token,
    url: origin + '/join/' + x.token,
    createdAt: x.created_at,
    expiresAt: Number(x.expires_at)
  }));
}

async function inviteOk(env, next) {
  const m = String(next || '').match(/^\/join\/([A-Za-z0-9_-]{20,64})$/);
  if (!m) return null;
  const inv = await env.DB.prepare(
    'SELECT i.expires_at, i.used_at, b.name FROM book_invites i ' +
    'JOIN books b ON b.id = i.book_id WHERE i.token = ?'
  ).bind(m[1]).first();
  if (!inv || inv.used_at || Number(inv.expires_at) < Date.now()) return null;
  return inv.name;
}

async function handleJoin(req, env, url) {
  const token = url.pathname.slice('/join/'.length);
  if (!/^[A-Za-z0-9_-]{20,64}$/.test(token)) return joinPage('없는 초대 링크입니다.', null);

  const inv = await env.DB.prepare(
    'SELECT i.token, i.book_id, i.expires_at, i.used_at, b.name, b.owner_key ' +
    'FROM book_invites i JOIN books b ON b.id = i.book_id WHERE i.token = ?'
  ).bind(token).first();

  if (!inv) return joinPage('없는 초대 링크입니다. 장부 주인에게 새로 받아 주세요.', null);
  if (inv.used_at) return joinPage('이미 쓴 초대 링크입니다. 장부 주인에게 새로 받아 주세요.', null);
  if (Number(inv.expires_at) < Date.now()) {
    return joinPage('기한이 지난 초대 링크입니다. 장부 주인에게 새로 받아 주세요.', null);
  }

  const u = await currentUser(req, env);
  if (!u) {
    /* 로그인이 먼저다. 돌아올 곳을 기억해 둔다. */
    return redirect(url.origin + '/auth/login?next=' + encodeURIComponent('/join/' + token));
  }

  const already = await env.DB.prepare(
    'SELECT 1 AS ok FROM book_members WHERE book_id = ? AND user_key = ?').bind(inv.book_id, u.key).first();
  if (already) {
    await env.DB.prepare('UPDATE users SET current_book = ? WHERE email = ?').bind(inv.book_id, u.key).run();
    return redirect(url.origin + '/');
  }

  const count = await env.DB.prepare(
    'SELECT COUNT(*) AS n FROM book_members WHERE book_id = ?').bind(inv.book_id).first();
  if (Number(count.n) >= MAX_MEMBERS) {
    return joinPage('이 장부는 이미 ' + MAX_MEMBERS + '명이 차 있습니다.', null);
  }

  const at = nowIso();
  await env.DB.batch([
    env.DB.prepare('INSERT INTO book_members (book_id, user_key, role, joined_at) VALUES (?,?,?,?)')
      .bind(inv.book_id, u.key, 'member', at),
    env.DB.prepare('UPDATE book_invites SET used_at = ?, used_by = ? WHERE token = ?')
      .bind(at, u.key, token),
    env.DB.prepare('UPDATE users SET current_book = ? WHERE email = ?').bind(inv.book_id, u.key)
  ]);
  return joinPage(null, inv.name);
}

function joinPage(error, bookName) {
  const nonce = b64(crypto.getRandomValues(new Uint8Array(16)));
  const body = error
    ? '<h1>초대를 쓸 수 없어요</h1><p class="lead">' + esc(error) + '</p>' +
      '<a class="go" href="/">내 장부로 가기</a>'
    : '<h1>' + esc(bookName) + '에 들어왔어요</h1>' +
      '<p class="lead">이제 이 장부의 집들을 함께 보고 적을 수 있습니다.</p>' +
      '<a class="go" href="/">장부 열기</a>';
  const html = '<!doctype html><html lang="ko"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta name="color-scheme" content="light dark"><title>초대 · 하우스헌팅</title>' +
    '<link rel="preconnect" href="https://fonts.googleapis.com">' +
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>' +
    '<link href="https://fonts.googleapis.com/css2?family=Jua&family=IBM+Plex+Sans+KR:wght@400;500;600&display=swap" rel="stylesheet">' +
    '<style nonce="' + nonce + '">' + AUTH_CSS +
    '.go{display:block;text-align:center;padding:12px;border-radius:999px;background:var(--sun);' +
    'color:var(--sun-ink);font-weight:600;text-decoration:none;margin-top:20px;' +
    'box-shadow:0 2px 0 color-mix(in srgb,var(--sun) 72%,#000)}' +
    '</style></head><body><main class="card">' + SCENE_SVG + body + '</main></body></html>';
  return new Response(html, {
    status: error ? 410 : 200,
    headers: Object.assign(baseHeaders(), {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': csp(nonce)
    })
  });
}

/* ═══ API ═══════════════════════════════════ */
async function handleApi(req, env, url, u) {
  const path = url.pathname, method = req.method;
  const bk = u.book.id, uk = u.key;

  if (path === '/api/state' && method === 'GET') {
    const props = await env.DB.prepare(
      'SELECT data FROM properties WHERE book_id = ?').bind(bk).all();
    const st = await env.DB.prepare(
      'SELECT data FROM settings WHERE book_id = ?').bind(bk).first();
    return json({
      properties: (props.results || []).map(r => safeParse(r.data)).filter(Boolean),
      settings: st ? safeParse(st.data) : null,
      book: u.book,
      members: await members(env, bk),
      invites: u.book.role === 'owner' ? await liveInvites(env, bk, url.origin) : []
    });
  }

  if (path === '/api/settings' && method === 'PUT') {
    const body = await req.json();
    await env.DB.prepare(
      'INSERT INTO settings (book_id, data, updated_at) VALUES (?, ?, ?) ' +
      'ON CONFLICT(book_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at'
    ).bind(bk, JSON.stringify(body), nowIso()).run();
    return json({ ok: true });
  }

  if (path === '/api/properties' && method === 'PUT') {
    const body = await req.json();
    const items = Array.isArray(body.items) ? body.items : [];
    if (!items.length) return json({ ok: true, saved: 0 });
    if (items.length > 200) return json({ error: '한 번에 200곳까지만 저장합니다' }, 400);

    /* 이미 있는 매물을 다시 올리는 건 늘어나는 게 아닙니다. 새로 생기는 것만 셉니다. */
    const have = await env.DB.prepare('SELECT id FROM properties WHERE book_id = ?').bind(bk).all();
    const known = new Set((have.results || []).map(r => String(r.id)));
    const keep = items.filter(p => p && p.id);
    const fresh = keep.filter(p => !known.has(String(p.id))).length;
    if (known.size + fresh > MAX_PROPS) {
      return json({ error: '한 장부에는 매물 ' + MAX_PROPS + '곳까지 담을 수 있습니다' }, 409);
    }
    for (const p of keep) {
      if (JSON.stringify(p).length > MAX_PROP_LEN) return json({ error: '내용이 너무 긴 매물이 있습니다' }, 413);
    }

    const at = nowIso();
    await env.DB.batch(keep.map(p =>
      env.DB.prepare(UPSERT_PROP).bind(bk, String(p.id), JSON.stringify(p), at, uk, uk)));
    return json({ ok: true, saved: keep.length });
  }

  const one = path.match(/^\/api\/properties\/([A-Za-z0-9_-]{1,64})$/);
  if (one) {
    const id = one[1];
    if (method === 'PUT') {
      const body = await req.json();
      body.id = id;
      const doc = JSON.stringify(body);
      if (doc.length > MAX_PROP_LEN) return json({ error: '내용이 너무 깁니다' }, 413);

      /* 고쳐 쓰는 건 언제나 되고, 새로 늘리는 것만 상한에 걸립니다. */
      const c = await env.DB.prepare(
        'SELECT COUNT(*) AS n, MAX(CASE WHEN id = ? THEN 1 ELSE 0 END) AS mine ' +
        'FROM properties WHERE book_id = ?').bind(id, bk).first();
      if (!Number(c.mine) && Number(c.n) >= MAX_PROPS) {
        return json({ error: '한 장부에는 매물 ' + MAX_PROPS + '곳까지 담을 수 있습니다' }, 409);
      }

      await env.DB.prepare(UPSERT_PROP).bind(bk, id, doc, nowIso(), uk, uk).run();
      return json({ ok: true });
    }
    if (method === 'DELETE') {
      await env.DB.prepare('DELETE FROM properties WHERE book_id = ? AND id = ?').bind(bk, id).run();
      return json({ ok: true });
    }
  }

  /* ── 함께 쓰기 ── */
  if (path === '/api/book/rename' && method === 'POST') {
    const name = String((await req.json()).name || '').trim().slice(0, 40);
    if (!name) return json({ error: '장부 이름을 적어 주세요' }, 400);
    await env.DB.prepare('UPDATE books SET name = ? WHERE id = ?').bind(name, bk).run();
    return json({ ok: true, name });
  }

  /* 따로 볼 장부를 새로 만듭니다. 만든 사람이 주인이 되고, 바로 그 장부로 옮겨 갑니다.
     초대를 받아 남의 장부에 들어온 분도 이걸로 자기 장부를 가질 수 있습니다. */
  if (path === '/api/book/new' && method === 'POST') {
    const name = String((await req.json()).name || '').trim().slice(0, 40) || '새 장부';
    const mine = await env.DB.prepare(
      'SELECT COUNT(*) AS n FROM books WHERE owner_key = ?').bind(uk).first();
    if (Number(mine.n) >= MAX_BOOKS) {
      return json({ error: '장부는 ' + MAX_BOOKS + '개까지 만들 수 있습니다' }, 409);
    }
    const book = await createBook(env, uk, name);
    return json({ ok: true, book });
  }

  if (path === '/api/book/switch' && method === 'POST') {
    const to = String((await req.json()).bookId || '');
    const m = await env.DB.prepare(
      'SELECT 1 AS ok FROM book_members WHERE book_id = ? AND user_key = ?').bind(to, uk).first();
    if (!m) return json({ error: '그 장부의 참여자가 아닙니다' }, 403);
    await env.DB.prepare('UPDATE users SET current_book = ? WHERE email = ?').bind(to, uk).run();
    return json({ ok: true });
  }

  /* 부를 사람마다 링크를 하나씩 만들어 따로 보냅니다. 먼저 보낸 링크는 죽지 않습니다. */
  if (path === '/api/book/invite' && method === 'POST') {
    if (u.book.role !== 'owner') return json({ error: '장부 주인만 초대할 수 있습니다' }, 403);
    const people = await env.DB.prepare(
      'SELECT COUNT(*) AS n FROM book_members WHERE book_id = ?').bind(bk).first();
    const room = MAX_MEMBERS - Number(people.n);
    if (room <= 0) {
      return json({ error: '한 장부에는 ' + MAX_MEMBERS + '명까지 들어올 수 있습니다' }, 409);
    }

    /* 살아 있는 링크는 남은 자리 수만큼만. 링크를 뿌려만 두는 일을 막습니다. */
    const live = await env.DB.prepare(
      'SELECT COUNT(*) AS n FROM book_invites WHERE book_id = ? AND used_at IS NULL AND expires_at > ?'
    ).bind(bk, Date.now()).first();
    if (Number(live.n) >= room) {
      return json({
        error: '남은 자리 ' + room + '명만큼만 링크를 둘 수 있습니다. 안 쓰는 링크를 먼저 끄세요'
      }, 409);
    }

    const token = b64(crypto.getRandomValues(new Uint8Array(24)));
    const expires = Date.now() + INVITE_DAYS * 864e5;
    await env.DB.prepare(
      'INSERT INTO book_invites (token, book_id, created_by, created_at, expires_at) VALUES (?,?,?,?,?)'
    ).bind(token, bk, uk, nowIso(), expires).run();
    return json({
      ok: true, url: url.origin + '/join/' + token, expiresAt: expires, days: INVITE_DAYS,
      invites: await liveInvites(env, bk, url.origin)
    });
  }

  /* 링크 하나만 끄기 */
  const oneInvite = path.match(/^\/api\/book\/invite\/([A-Za-z0-9_-]{20,64})$/);
  if (oneInvite && method === 'DELETE') {
    if (u.book.role !== 'owner') return json({ error: '장부 주인만 끌 수 있습니다' }, 403);
    await env.DB.prepare(
      'DELETE FROM book_invites WHERE book_id = ? AND token = ? AND used_at IS NULL'
    ).bind(bk, oneInvite[1]).run();
    return json({ ok: true, invites: await liveInvites(env, bk, url.origin) });
  }

  /* 살아 있는 링크 모두 끄기 */
  if (path === '/api/book/invite' && method === 'DELETE') {
    if (u.book.role !== 'owner') return json({ error: '장부 주인만 끌 수 있습니다' }, 403);
    await env.DB.prepare('DELETE FROM book_invites WHERE book_id = ? AND used_at IS NULL').bind(bk).run();
    return json({ ok: true, invites: [] });
  }

  if (path === '/api/book/leave' && method === 'POST') {
    if (u.book.role === 'owner') return json({ error: '주인은 나갈 수 없습니다' }, 409);
    await env.DB.prepare('DELETE FROM book_members WHERE book_id = ? AND user_key = ?').bind(bk, uk).run();
    await env.DB.prepare('UPDATE users SET current_book = NULL WHERE email = ?').bind(uk).run();
    return json({ ok: true });
  }

  const kick = path.match(/^\/api\/members\/(.+)$/);
  if (kick && method === 'DELETE') {
    if (u.book.role !== 'owner') return json({ error: '장부 주인만 내보낼 수 있습니다' }, 403);
    const who = decodeURIComponent(kick[1]).toLowerCase();
    if (who === u.book.owner) return json({ error: '주인은 내보낼 수 없습니다' }, 409);
    await env.DB.prepare('DELETE FROM book_members WHERE book_id = ? AND user_key = ?').bind(bk, who).run();
    await env.DB.prepare('UPDATE users SET current_book = NULL WHERE email = ? AND current_book = ?')
      .bind(who, bk).run();
    return json({ ok: true });
  }

  /* ── 사진 ── */
  if (path === '/api/photos' && method === 'POST') {
    const type = req.headers.get('content-type') || 'image/jpeg';
    if (!/^image\//.test(type)) return json({ error: '이미지만 올릴 수 있습니다' }, 415);
    const buf = await req.arrayBuffer();
    if (!buf.byteLength) return json({ error: '빈 파일입니다' }, 400);
    const cap = env.PHOTOS ? MAX_PHOTO : MAX_PHOTO_DB;
    if (buf.byteLength > cap) {
      return json({ error: '사진이 너무 큽니다. ' + Math.round(cap / 1024) + 'KB 아래로 줄여 주세요' }, 413);
    }
    const id = crypto.randomUUID().replace(/-/g, '');
    const at = nowIso();

    if (env.PHOTOS) {
      await env.PHOTOS.put(bk + '/' + id, buf, { httpMetadata: { contentType: type } });
      await env.DB.prepare(
        'INSERT INTO photos (id, book_id, uploaded_by, storage, object_key, content_type, size, created_at) VALUES (?,?,?,?,?,?,?,?)'
      ).bind(id, bk, uk, 'r2', bk + '/' + id, type, buf.byteLength, at).run();
    } else {
      const count = await env.DB.prepare(
        'SELECT COUNT(*) AS n FROM photos WHERE book_id = ? AND storage = ?').bind(bk, 'db').first();
      if (Number(count.n) >= MAX_PHOTOS_DB) {
        return json({ error: '사진은 장부당 ' + MAX_PHOTOS_DB + '장까지입니다. R2를 켜면 제한이 풀립니다' }, 409);
      }
      await env.DB.batch([
        env.DB.prepare('INSERT INTO photo_blobs (id, data) VALUES (?, ?)').bind(id, [...new Uint8Array(buf)]),
        env.DB.prepare(
          'INSERT INTO photos (id, book_id, uploaded_by, storage, object_key, content_type, size, created_at) VALUES (?,?,?,?,?,?,?,?)'
        ).bind(id, bk, uk, 'db', id, type, buf.byteLength, at)
      ]);
    }
    return json({ id, url: '/photo/' + id });
  }

  const photo = path.match(/^\/photo\/([a-f0-9]{32})$/);
  if (photo && method === 'GET') {
    const row = await env.DB.prepare(
      'SELECT storage, object_key, content_type FROM photos WHERE id = ? AND book_id = ?'
    ).bind(photo[1], bk).first();
    if (!row) return new Response('없는 사진입니다', { status: 404, headers: baseHeaders() });

    const head = Object.assign(baseHeaders(), {
      'content-type': row.content_type || 'image/jpeg',
      'cache-control': 'private, max-age=86400'
    });

    if (row.storage === 'r2') {
      if (!env.PHOTOS) return new Response('사진 저장소가 없습니다', { status: 404, headers: baseHeaders() });
      const obj = await env.PHOTOS.get(row.object_key);
      if (!obj) return new Response('없는 사진입니다', { status: 404, headers: baseHeaders() });
      head.etag = obj.httpEtag;
      return new Response(obj.body, { headers: head });
    }

    const blob = await env.DB.prepare('SELECT data FROM photo_blobs WHERE id = ?').bind(photo[1]).first();
    if (!blob || !blob.data) return new Response('없는 사진입니다', { status: 404, headers: baseHeaders() });
    const bytes = blob.data instanceof ArrayBuffer ? new Uint8Array(blob.data) : new Uint8Array(blob.data);
    return new Response(bytes, { headers: head });
  }

  if (photo && method === 'DELETE') {
    const row = await env.DB.prepare(
      'SELECT storage, object_key FROM photos WHERE id = ? AND book_id = ?').bind(photo[1], bk).first();
    if (!row) return json({ ok: true });
    if (row.storage === 'r2' && env.PHOTOS) await env.PHOTOS.delete(row.object_key);
    await env.DB.batch([
      env.DB.prepare('DELETE FROM photo_blobs WHERE id = ?').bind(photo[1]),
      env.DB.prepare('DELETE FROM photos WHERE id = ? AND book_id = ?').bind(photo[1], bk)
    ]);
    return json({ ok: true });
  }

  return json({ error: '없는 경로입니다' }, 404);
}

/* ═══ 관리 ══════════════════════════════════
 * ADMIN_EMAIL 로 로그인했을 때만 열립니다. 다른 사람에게는 404 로 보입니다.
 */
async function handleAdmin(req, env, url, u) {
  if (!isAdmin(env, u)) return json({ error: '없는 경로입니다' }, 404);
  const path = url.pathname, method = req.method;

  if (path === '/api/admin/overview' && method === 'GET') {
    const users = await env.DB.prepare(
      'SELECT u.email, u.name, u.created_at, u.last_login, u.provider, u.age_band, ' +
      '(SELECT COUNT(*) FROM book_members m WHERE m.user_key = u.email) AS books, ' +
      '(SELECT COUNT(*) FROM books b WHERE b.owner_key = u.email) AS owned, ' +
      "(SELECT la.until FROM login_attempts la WHERE la.key = 'e:' || u.email) AS locked " +
      'FROM users u ORDER BY u.created_at DESC'
    ).all();
    const books = await env.DB.prepare(
      'SELECT b.id, b.name, b.owner_key, b.created_at, ' +
      '(SELECT COUNT(*) FROM book_members m WHERE m.book_id = b.id) AS people, ' +
      '(SELECT COUNT(*) FROM properties p WHERE p.book_id = b.id) AS props, ' +
      '(SELECT COUNT(*) FROM photos f WHERE f.book_id = b.id) AS photos, ' +
      '(SELECT COALESCE(SUM(f.size),0) FROM photos f WHERE f.book_id = b.id) AS bytes ' +
      'FROM books b ORDER BY b.created_at DESC'
    ).all();
    const invites = await env.DB.prepare(
      'SELECT COUNT(*) AS n FROM book_invites WHERE used_at IS NULL AND expires_at > ?'
    ).bind(Date.now()).first();
    return json({
      me: u.key,
      users: users.results || [],
      books: books.results || [],
      liveInvites: Number(invites.n) || 0,
      signupOpen: !!env.SIGNUP_CODE,
      photoStore: env.PHOTOS ? 'r2' : 'db'
    });
  }

  /* 연령대별로 어떤 집을 보고 있는지. 금액은 만원, 면적은 m² 입니다.
   * 집계는 v_prop_stats 뷰 하나만 봅니다(migrations/004-stats.sql).
   */
  if (path === '/api/admin/stats' && method === 'GET') {
    const byAge = await env.DB.prepare(
      'SELECT COALESCE(age_band, ?) AS age_band, deal_type, COUNT(*) AS n, ' +
      'ROUND(AVG(price)) AS avg_price, MIN(price) AS min_price, MAX(price) AS max_price, ' +
      'ROUND(AVG(pyeong), 1) AS avg_pyeong, ROUND(AVG(per_pyeong)) AS avg_per_pyeong ' +
      'FROM v_prop_stats WHERE price IS NOT NULL AND deal_type IS NOT NULL ' +
      'GROUP BY COALESCE(age_band, ?), deal_type ORDER BY 1, 2'
    ).bind('unknown', 'unknown').all();

    const people = await env.DB.prepare(
      'SELECT COALESCE(age_band, ?) AS age_band, COUNT(*) AS n FROM users ' +
      'GROUP BY COALESCE(age_band, ?) ORDER BY 1'
    ).bind('unknown', 'unknown').all();

    const providers = await env.DB.prepare(
      'SELECT provider, COUNT(*) AS n FROM users GROUP BY provider ORDER BY 2 DESC'
    ).all();

    const totals = await env.DB.prepare(
      'SELECT deal_type, COUNT(*) AS n, ROUND(AVG(price)) AS avg_price, ' +
      'ROUND(AVG(per_pyeong)) AS avg_per_pyeong FROM v_prop_stats ' +
      'WHERE price IS NOT NULL AND deal_type IS NOT NULL GROUP BY deal_type ORDER BY 1'
    ).all();

    return json({
      byAge: byAge.results || [],
      people: people.results || [],
      providers: providers.results || [],
      totals: totals.results || []
    });
  }

  if (path === '/api/admin/unlock' && method === 'POST') {
    const who = String((await req.json()).email || '').toLowerCase();
    await env.DB.prepare("DELETE FROM login_attempts WHERE key IN ('e:' || ?, 'p:' || ?)")
      .bind(who, who).run();
    return json({ ok: true });
  }

  if (path === '/api/admin/logout' && method === 'POST') {
    const who = String((await req.json()).email || '').toLowerCase();
    await env.DB.prepare('UPDATE users SET session_epoch = session_epoch + 1 WHERE email = ?')
      .bind(who).run();
    return json({ ok: true });
  }

  /* 매물과 장부를 통째로 내려받기. 비밀번호 해시는 넣지 않습니다. */
  if (path === '/api/admin/export' && method === 'GET') {
    const q = async (sql) => ((await env.DB.prepare(sql).all()).results || []);
    const props = await q('SELECT book_id, id, data, updated_at, updated_by FROM properties');
    const sets  = await q('SELECT book_id, data, updated_at FROM settings');
    return json({
      app: '하우스헌팅',
      exportedAt: nowIso(),
      note: '비밀번호 해시와 사진 본체는 들어 있지 않습니다. 완전 복구는 wrangler d1 export 를 쓰세요.',
      users:   await q('SELECT email, name, created_at, last_login, current_book FROM users'),
      books:   await q('SELECT id, name, owner_key, created_at FROM books'),
      members: await q('SELECT book_id, user_key, role, joined_at FROM book_members'),
      photos:  await q('SELECT id, book_id, storage, content_type, size, created_at FROM photos'),
      properties: props.map(r => ({ ...r, data: safeParse(r.data) })),
      settings:   sets.map(r => ({ ...r, data: safeParse(r.data) }))
    });
  }

  const delUser = path.match(/^\/api\/admin\/users\/(.+)$/);
  if (delUser && method === 'DELETE') {
    const who = decodeURIComponent(delUser[1]).toLowerCase();
    if (who === u.key) return json({ error: '자기 계정은 여기서 지울 수 없습니다' }, 409);
    const owned = await env.DB.prepare('SELECT id FROM books WHERE owner_key = ?').bind(who).all();
    for (const b of (owned.results || [])) await dropBook(env, b.id);
    await env.DB.batch([
      env.DB.prepare('DELETE FROM book_members WHERE user_key = ?').bind(who),
      env.DB.prepare("DELETE FROM login_attempts WHERE key IN ('e:' || ?, 'p:' || ?)").bind(who, who),
      env.DB.prepare('DELETE FROM users WHERE email = ?').bind(who)
    ]);
    return json({ ok: true, droppedBooks: (owned.results || []).length });
  }

  const delBook = path.match(/^\/api\/admin\/books\/([A-Za-z0-9_-]{1,64})$/);
  if (delBook && method === 'DELETE') {
    await dropBook(env, delBook[1]);
    return json({ ok: true });
  }

  return json({ error: '없는 경로입니다' }, 404);
}

/* 장부 하나와 그 안의 모든 것을 지웁니다 */
async function dropBook(env, id) {
  const shots = await env.DB.prepare(
    'SELECT id, storage, object_key FROM photos WHERE book_id = ?').bind(id).all();
  for (const f of (shots.results || [])) {
    if (f.storage === 'r2' && env.PHOTOS) { try { await env.PHOTOS.delete(f.object_key); } catch (e) {} }
    await env.DB.prepare('DELETE FROM photo_blobs WHERE id = ?').bind(f.id).run();
  }
  await env.DB.batch([
    env.DB.prepare('DELETE FROM photos WHERE book_id = ?').bind(id),
    env.DB.prepare('DELETE FROM properties WHERE book_id = ?').bind(id),
    env.DB.prepare('DELETE FROM settings WHERE book_id = ?').bind(id),
    env.DB.prepare('DELETE FROM book_invites WHERE book_id = ?').bind(id),
    env.DB.prepare('DELETE FROM book_members WHERE book_id = ?').bind(id),
    env.DB.prepare('UPDATE users SET current_book = NULL WHERE current_book = ?').bind(id),
    env.DB.prepare('DELETE FROM books WHERE id = ?').bind(id)
  ]);
}

async function members(env, bk) {
  const r = await env.DB.prepare(
    'SELECT m.user_key AS email, m.role, m.joined_at, u.name FROM book_members m ' +
    'LEFT JOIN users u ON u.email = m.user_key WHERE m.book_id = ? ORDER BY m.joined_at'
  ).bind(bk).all();
  return (r.results || []).map(x => ({
    email: x.email, name: x.name || x.email.split('@')[0], role: x.role
  }));
}

/* created_by 는 처음 넣은 사람 그대로 둡니다. 남이 고쳤다고 통계의 주인이 바뀌면 안 됩니다. */
const UPSERT_PROP =
  'INSERT INTO properties (book_id, id, data, updated_at, updated_by, created_by) VALUES (?, ?, ?, ?, ?, ?) ' +
  'ON CONFLICT(book_id, id) DO UPDATE SET data = excluded.data, ' +
  'updated_at = excluded.updated_at, updated_by = excluded.updated_by';

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
