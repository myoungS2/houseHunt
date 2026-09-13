/**
 * 비밀번호를 잊은 사람의 계정을 초기화합니다.
 *
 *   node tools/reset-password.mjs 배우자@gmail.com "임시비밀번호1234"
 *
 * 출력된 SQL을 그대로 실행하면 됩니다.
 *   npx wrangler d1 execute house-hunt --remote --command "<붙여넣기>"
 *
 * 실행하는 순간 그 사람의 기존 로그인은 전부 끊기고, 새 임시 비밀번호로만 들어갑니다.
 * 알려준 뒤에는 앱의 설정 화면에서 본인이 바꾸게 하세요.
 *
 * 이 숫자들은 src/worker.js 의 CLIENT_ITER, SERVER_ITER 와 반드시 같아야 합니다.
 */
const CLIENT_ITER = 600000;
const SERVER_ITER = 12000;

const [email, password] = process.argv.slice(2);
if (!email || !password) {
  console.error('쓰는 법: node tools/reset-password.mjs <이메일> <임시 비밀번호>');
  process.exit(1);
}
if (password.length < 10) {
  console.error('임시 비밀번호도 10자 이상으로 해주세요.');
  process.exit(1);
}

const subtle = globalThis.crypto.subtle;
const randomBytes = n => globalThis.crypto.getRandomValues(new Uint8Array(n));
const enc = new TextEncoder();
const b64 = b => Buffer.from(b).toString('base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function bits(material, salt, iter) {
  const k = await subtle.importKey('raw', material, 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, k, 256));
}

const mail = email.trim().toLowerCase();
// 1단계: 브라우저가 하는 것과 똑같이 늘린다
const clientKey = b64(await bits(enc.encode(password.normalize('NFC')),
  enc.encode('house-hunt|' + mail), CLIENT_ITER));
// 2단계: 워커가 하는 것과 똑같이 소금을 치고 한 번 더 늘린다
const salt = randomBytes(16);
const stored = 'pbkdf2$' + SERVER_ITER + '$' + b64(salt) + '$' +
  b64(await bits(enc.encode(clientKey), salt, SERVER_ITER));

console.log('\n아래 SQL을 실행하세요.\n');
console.log(`UPDATE users SET pw = '${stored}', session_epoch = session_epoch + 1 WHERE email = '${mail}';`);
console.log(`\n  npx wrangler d1 execute house-hunt --remote --command "위 줄"\n`);
console.log(`그다음 ${mail} 님에게 임시 비밀번호를 알려주고, 들어가서 바꾸라고 하세요.\n`);
