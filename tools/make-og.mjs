/**
 * 공유 카드 그림(assets/og.png)과 홈 화면 아이콘(assets/icon-180.png)을 다시 굽습니다.
 *
 *   node tools/make-og.mjs
 *
 * index.html 안에 들어 있는 일러스트 생성기(ILL)를 그대로 불러다 쓰기 때문에,
 * 앱 그림을 손보면 이 스크립트를 한 번 돌려 카드 그림도 같이 맞춰 주면 됩니다.
 *
 * 필요한 것 — 맥에서 한 번 굽고 결과 png 만 레포에 넣는 용도입니다.
 *   · 인터넷 (구글 폰트 Jua 와 npx sharp-cli 를 받습니다)
 *   · python3 + Pillow  (글자를 얹습니다. pip3 install pillow)
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFileSync } from 'child_process';

const ROOT = path.resolve(import.meta.dirname, '..');
const TMP  = fs.mkdtempSync(path.join(os.tmpdir(), 'house-og-'));
const JUA  = 'https://fonts.gstatic.com/s/jua/v18/co3KmW9ljjAjcw.ttf';
const GOTHIC = '/System/Library/Fonts/AppleSDGothicNeo.ttc';

/* ── 1. 앱에 있는 일러스트 생성기를 그대로 떼어 온다 ── */
const src = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
const head = src.indexOf('const ILL=(function(){');
const tail = src.indexOf('})();', src.indexOf('return {hunt,compare,budget,town,setTheme'));
if (head < 0 || tail < 0) throw new Error('index.html 에서 ILL 블록을 못 찾았습니다');
const ILL = eval(src.slice(head, tail + 5) + '\nILL');
ILL.setTheme('plain');

/* 색은 CSS 변수로 적혀 있으니 :root 의 밝은 값으로 바꿔 둔다 */
const root = src.slice(src.indexOf(':root{'), src.indexOf('@media (prefers-color-scheme: dark)'));
const tok = {};
for (const m of root.matchAll(/--([\w-]+)\s*:\s*([^;}]+)/g)) tok[m[1]] = m[2].trim();
const solid = s => { let o = s, n = 0; while (/var\(--/.test(o) && n++ < 6) o = o.replace(/var\(--([\w-]+)\)/g, (_, k) => tok[k] || '#000'); return o; };

/* ── 2. 1200×630 그림판을 짠다 ── */
const guts = s => s.replace(/^<svg[^>]*>/, '').replace(/<\/svg>$/, '');
const wrap = (s, tf) => {
  const a = (s.match(/^<svg([^>]*)>/) || ['', ''])[1];
  const keep = [...a.matchAll(/\b(fill|stroke|stroke-width|stroke-linejoin|stroke-linecap)="([^"]*)"/g)]
    .map(m => m[1] + '="' + m[2] + '"').join(' ');
  return '<g transform="' + tf + '" ' + keep + '>' + guts(s) + '</g>';
};
const hunt = solid(ILL.hunt());                                   // 0 0 300 190
/* 마을 띠의 크림색 배경판은 걷어낸다. 뒤에 놓인 장면을 가리기 때문이다 */
const town = solid(ILL.town()).replace(/<rect x="-40"[^>]*>/, '');  // 0 0 2400 150
const TS = 1200 / 857;                                            // 2400 중 857 폭만 쓴다

const mark =
  '<g transform="translate(88 84)">' +
  '<rect width="104" height="104" rx="36" fill="#F2643A"/>' +
  '<g transform="translate(23 23) scale(2.42)" fill="none" stroke="#fff" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">' +
  '<path d="M2.9 11.3 12 3.5l9.1 7.8"/>' +
  '<path d="M5 10.8V20a.9.9 0 0 0 .9.9h12.2a.9.9 0 0 0 .9-.9v-9.2"/>' +
  '<path d="M9.9 20.9v-5.3a.9.9 0 0 1 .9-.9h2.4a.9.9 0 0 1 .9.9v5.3"/></g></g>';

const og =
  '<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">' +
  '<rect width="1200" height="630" fill="' + tok.bg + '"/>' +
  wrap(hunt, 'translate(600 104) scale(2.04)') +
  wrap(town, 'translate(' + (-790 * TS).toFixed(2) + ' ' + (630 - 150 * TS).toFixed(2) + ') scale(' + TS.toFixed(4) + ')') +
  mark +
  '</svg>';
fs.writeFileSync(path.join(TMP, 'og.svg'), og);

/* 홈 화면 아이콘. iOS 가 알아서 모서리를 둥글게 깎으므로 여기서는 네모로 둔다 */
fs.writeFileSync(path.join(TMP, 'icon.svg'),
  '<svg xmlns="http://www.w3.org/2000/svg" width="180" height="180" viewBox="0 0 180 180">' +
  '<rect width="180" height="180" fill="#F2643A"/>' +
  '<g transform="translate(36 36) scale(4.5)" fill="none" stroke="#fff" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round">' +
  '<path d="M2.9 11.3 12 3.5l9.1 7.8"/>' +
  '<path d="M5 10.8V20a.9.9 0 0 0 .9.9h12.2a.9.9 0 0 0 .9-.9v-9.2"/>' +
  '<path d="M9.9 20.9v-5.3a.9.9 0 0 1 .9-.9h2.4a.9.9 0 0 1 .9.9v5.3"/></g></svg>');

/* ── 3. SVG 를 PNG 로 굽는다 ── */
const sharp = (inp, out, w, h) =>
  execFileSync('npx', ['-y', 'sharp-cli', '--input', path.join(TMP, inp), '--output', path.join(TMP, out), 'resize', String(w), String(h)],
    { stdio: 'ignore' });
sharp('og.svg', 'og-art.png', 1200, 630);
sharp('icon.svg', 'icon-180.png', 180, 180);

/* ── 4. 글자를 얹고 색 수를 줄여 저장한다 ── */
const jua = path.join(TMP, 'Jua.ttf');
execFileSync('curl', ['-sL', '-o', jua, JUA]);
const py = `
from PIL import Image, ImageDraw, ImageFont
im = Image.open(${JSON.stringify(path.join(TMP, 'og-art.png'))}).convert('RGB')
d = ImageDraw.Draw(im)
d.text((88, 268), '하우스헌팅',
       font=ImageFont.truetype(${JSON.stringify(jua)}, 104), fill='#2A2620', anchor='ls')
d.text((92, 336), '전세 · 매매 후보 비교',
       font=ImageFont.truetype(${JSON.stringify(GOTHIC)}, 38, index=2), fill='#58514A', anchor='ls')
im.quantize(colors=128, dither=Image.NONE).save(${JSON.stringify(path.join(ROOT, 'assets/og.png'))}, optimize=True)
Image.open(${JSON.stringify(path.join(TMP, 'icon-180.png'))}).convert('RGB').save(
    ${JSON.stringify(path.join(ROOT, 'assets/icon-180.png'))}, optimize=True)
`;
execFileSync('python3', ['-c', py], { stdio: 'inherit' });
fs.rmSync(TMP, { recursive: true, force: true });

for (const f of ['assets/og.png', 'assets/icon-180.png']) {
  console.log(f, Math.round(fs.statSync(path.join(ROOT, f)).size / 1024) + 'KB');
}
