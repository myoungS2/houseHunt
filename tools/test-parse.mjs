#!/usr/bin/env node
/* 네이버부동산 붙여넣기 파서 회귀 시험
 *
 *   node tools/test-parse.mjs
 *
 * 앱이 index.html 한 파일이라 파서를 따로 불러올 수 없습니다.
 * 파일에서 파서 부분만 잘라내 그 자리에서 실행합니다.
 * 네이버 화면 생김새가 바뀌어 파서를 고칠 때 이걸 먼저 돌리세요.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const src = readFileSync(join(root, 'index.html'), 'utf8');
const cut = (a, b) => {
  const i = src.indexOf(a), j = src.indexOf(b);
  if (i < 0 || j < 0) throw new Error('index.html에서 ' + a + ' ~ ' + b + ' 를 못 찾았습니다');
  return src.slice(i, j);
};
const parseNaver = new Function(
  cut('const STATUS', 'const SAMPLES') + '\n' +
  cut('const NV_FACING', 'function nvApply') + '\nreturn parseNaver;'
)();

let pass = 0, fail = 0;
const fails = [];

function check(name, got, want) {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  if (g === w) { pass++; return; }
  fail++;
  fails.push('  ' + name + '\n    바란 값: ' + w + '\n    나온 값: ' + g);
}

/* 한 건의 붙여넣기 글을 파싱해 기대한 칸들과 맞춰 봅니다.
   want 에 적은 칸만 봅니다. notes 는 부분 문자열로 확인합니다. */
function testCase(name, text, want, opts = {}) {
  const r = parseNaver(text);
  for (const k of Object.keys(want)) check(name + ' · ' + k, r.vals[k] ?? null, want[k]);
  if (opts.more != null) check(name + ' · 붙은 건수', r.more, opts.more);
  if (opts.notesHave) {
    const memo = r.notes.join(' · ');
    for (const frag of opts.notesHave) {
      if (memo.includes(frag)) pass++;
      else { fail++; fails.push('  ' + name + ' · 메모에 "' + frag + '" 없음\n    나온 메모: ' + memo); }
    }
  }
  if (opts.notesLack) {
    const memo = r.notes.join(' · ');
    for (const frag of opts.notesLack) {
      if (!memo.includes(frag)) pass++;
      else { fail++; fails.push('  ' + name + ' · 메모에 "' + frag + '" 가 새어 들어감\n    나온 메모: ' + memo); }
    }
  }
  if (opts.empty) {
    const n = Object.keys(r.vals).length;
    if (n === 0) pass++;
    else { fail++; fails.push('  ' + name + ' · 아무것도 안 채워야 하는데 ' + n + '칸이 찼습니다: ' + JSON.stringify(r.vals)); }
  }
}

/* ── 실제 화면에서 복사한 글 ─────────────────── */

const 빌라중층 = `양재동 빌라매매 5억 9,0005,582만원/3.3㎡평당가 도움말

* 알림
* 관심매물
* 공유하기

* 빌라/연립
* 2016.01(11년차)
* 공급34.94㎡ (전용28.55)
* 중/5층

면적 단위 변경평
10 우리동네 10년차 엘베 있는 준신축 풀옵션 2룸

* 확인매물 2026. 08. 31.

기본 정보

* 매매가
5억 9,000만원
* 기전세금
2억 7,300만원
* 융자금
없음
* 관리비부과기준
정액관리비
* 관리비
5만원상세보기

* 공급면적
34.94㎡면적 단위 변경평
* 전용면적
28.55㎡ (전용률 82%)
* 대지지분
18.51㎡
* 해당층/총층
중/5층
* 방수/욕실수
2/1개
* 향
(안방 기준) 남향
* 복층여부
단층
* 방구조
분리형
* 주차가능여부
가능
* 입주가능일
2027년 08월 14일
* 위반건축물 여부
해당없음
* 매물번호
2646865873`;

const 빌라고층 = `매물 소개 양재동 빌라매매 4억 5,0004,574만원/3.3㎡평당가 도움말

* 빌라/연립
* 2014.11(12년차)
* 공급32.52㎡ (전용27.72)
* 고/5층

면적 단위 변경평
급매물로 입주 갭투자 가능합니다

* 확인매물 2026. 09. 02.

기본 정보

* 매매가
4억 5,000만원
* 기전세금
2억 3,000만원
* 관리비
5만 5,000원상세보기

* 공급면적
32.52㎡면적 단위 변경평
* 전용면적
27.72㎡ (전용률 85%)
* 대지지분
16.42㎡
* 해당층/총층
고/5층
* 방수/욕실수
2/1개
* 향
(거실 기준) 남향
* 복층여부
단층
* 방구조
분리형
* 주차가능여부
가능
* 입주가능일
2026년 10월 하순 협의 가능
* 위반건축물 여부
해당없음
* 매물번호
2647361133`;

const 빌라저층 = `양재동 빌라매매 5억 5,0004,142만원/3.3㎡평당가 도움말

* 알림
* 관심매물
* 공유하기

* 빌라/연립
* 2022.12(4년차)
* 공급43.9㎡ (전용29.41)
* 저/6층

면적 단위 변경평
양재동 역세권 신축 풀옵 구해줘홈즈 방송된 최고급 이뿐 투룸

* 집주인
* 확인매물 2026. 08. 24.

기본 정보

* 매매가
5억 5,000만원
* 관리비부과기준
정액관리비
* 관리비
7만원상세보기

* 공급면적
43.9㎡면적 단위 변경평
* 전용면적
29.41㎡ (전용률 67%)
* 해당층/총층
저/6층
* 방수/욕실수
2/1개
* 향
(거실 기준) 남동향
* 복층여부
단층
* 방구조
분리형
* 주차가능여부
가능
* 입주가능일
즉시입주
* 매물번호
2645466438 `;

testCase('빌라 중층', 빌라중층, {
  name: '양재동 빌라 중층', dealType: 'sale', price: 59000, fee: 5,
  area: 28.55, floor: '중/5', rooms: 2, baths: 1, facing: '남',
  parking: '가능', moveIn: '2027-08-14',
  url: 'https://fin.land.naver.com/articles/2646865873'
}, {
  more: 0,
  notesHave: ['우리동네 10년차 엘베 있는 준신축 풀옵션 2룸', '기전세금 2억 7,300만원', '2016.01 준공'],
  notesLack: ['융자금']          // "없음" 은 메모에 넣지 않습니다
});

testCase('빌라 고층 — 원 단위 관리비, 협의 입주', 빌라고층, {
  name: '양재동 빌라 고층', price: 45000, fee: 5.5, area: 27.72,
  floor: '고/5', facing: '남', tenant: 'unknown', moveIn: null,
  url: 'https://fin.land.naver.com/articles/2647361133'
}, {
  notesHave: ['급매물로 입주 갭투자 가능합니다', '입주 2026년 10월 하순 협의 가능']
});

testCase('빌라 저층 — 집주인 꼬리표, 즉시입주', 빌라저층, {
  name: '양재동 빌라 저층', price: 55000, fee: 7, area: 29.41,
  floor: '저/6', facing: '남동', tenant: 'none',
  url: 'https://fin.land.naver.com/articles/2645466438'
}, {
  notesHave: ['양재동 역세권 신축 풀옵 구해줘홈즈 방송된 최고급 이뿐 투룸', '즉시 입주']
});

testCase('두 건을 한꺼번에 복사', 빌라중층 + '\n\n' + 빌라고층, {
  name: '양재동 빌라 중층', price: 59000, area: 28.55
}, { more: 1 });

/* ── 아파트 화면 ─────────────────────────────── */

testCase('아파트 데스크톱 매매', `래미안퍼스티지
아파트 · 114E/84㎡
매매 26억 5,000
확인매물 26.09.10.
서울시 서초구 반포동
월관리비  25만원
공급/전용면적 114.28㎡/84.97㎡
해당층/총층/주차대수 7층/22층/1대
방수/욕실수 3개/2개
방향 남향 (거실 기준)
사용승인일 2009.07.31.
입주가능일 2026.04.10 이후
신반포역 도보 5분`, {
  name: '래미안퍼스티지 7층', dealType: 'sale', price: 265000, fee: 25,
  area: 84.97,                 // 공급 114.28 이 아니라 전용 쪽
  floor: '7/22', parking: '1대', rooms: 3, baths: 2, facing: '남',
  moveIn: '2026-04-10', address: '서울시 서초구 반포동',
  station: '신반포역', walk: 5
}, {
  notesHave: ['사용승인 2009-07-31'],
  notesLack: ['래미안퍼스티지', '매매 26억']   // 제목이 메모로 새면 안 됩니다
});

testCase('아파트 모바일 전세 — 라벨과 값이 두 줄', `아파트 · 상도동 e편한세상
전세 5억 5,000
확인일자
26.09.10.
해당층/총층
7/15층
전용/공급면적
59.82㎡/84.21㎡
방수/욕실수
3/1개
월관리비
12만원 수도료 포함
방향
남동향
입주가능일
즉시입주
서울시 동작구 상도로 123
상도역 도보 8분`, {
  name: '상도동 e편한세상 7층', dealType: 'jeonse', price: 55000,
  fee: 12, feeIncludes: '수도료',
  area: 59.82,                 // 전용이 앞에 오는 차례
  floor: '7/15', rooms: 3, baths: 1, facing: '남동', tenant: 'none',
  address: '서울시 동작구 상도로 123', station: '상도역', walk: 8
});

testCase('월세 — 보증금과 월세가 빗금으로', `힐스테이트
월세 1,000/80
관리비 확인불가
전용면적 33.5㎡
해당층/총층 3/12층
방수/욕실수 1개/1개
방향 서향
입주가능일 협의가능`, {
  dealType: 'jeonse', price: 1000, fee: null, area: 33.5,
  floor: '3/12', facing: '서', tenant: 'unknown'
}, { notesHave: ['월세 80만원'] });

testCase('최소 정보만', '행복아파트\n매매 9,500\n전용면적 45㎡', {
  name: '행복아파트', dealType: 'sale', price: 9500, area: 45
});

/* ── 매물 글이 아닐 때는 아무것도 건드리지 않습니다 ── */

testCase('엉뚱한 글', '오늘 점심 뭐 먹지', {}, { empty: true });
testCase('이름만 한 줄', '래미안퍼스티지', {}, { empty: true });
testCase('빈 글', '', {}, { empty: true });
testCase('공백만', '   \n\n  ', {}, { empty: true });

/* ── 금액·날짜 읽기 ──────────────────────────── */

const money = [
  ['매매 26억 5,000', 265000],
  ['매매 5억', 50000],
  ['매매 9,500', 9500],
  ['매매 3.5억', 35000]
];
for (const [txt, want] of money) {
  testCase('금액 ' + txt, txt + '\n전용면적 45㎡', { price: want });
}

// 제목에는 매매가 뒤에 평당가가 붙어 나옵니다. 매매가 라벨이 없어도 맞아야 합니다.
const titlePrices = [
  ['양재동 빌라매매 5억 9,0005,582만원/3.3㎡평당가 도움말', 59000],
  ['양재동 빌라매매 4억 5,0004,574만원/3.3㎡평당가 도움말', 45000],
  ['양재동 빌라매매 5억 5,0004,142만원/3.3㎡평당가 도움말', 55000],
  ['상도동 아파트전세 9,5003,100만원/3.3㎡평당가', 9500]
];
for (const [txt, want] of titlePrices) {
  testCase('제목 금액 ' + txt.slice(0, 22), txt + '\n전용면적 45㎡', { price: want });
}

const fees = [
  ['5만원상세보기', 5],
  ['5만 5,000원상세보기', 5.5],
  ['250,000원', 25],
  ['12만원 수도료 포함', 12]
];
for (const [txt, want] of fees) {
  testCase('관리비 ' + txt, '집\n매매 3억\n전용면적 45㎡\n관리비\n' + txt, { fee: want });
}

const dates = [
  ['2027년 08월 14일', '2027-08-14'],
  ['2026.04.10 이후', '2026-04-10'],
  ['26.09.10.', '2026-09-10']
];
for (const [txt, want] of dates) {
  testCase('입주일 ' + txt, '집\n매매 3억\n전용면적 45㎡\n입주가능일\n' + txt, { moveIn: want });
}

/* ── 결과 ────────────────────────────────────── */

console.log('');
if (fail) {
  console.log('실패 ' + fail + '건\n');
  console.log(fails.join('\n\n'));
  console.log('');
}
console.log(fail ? '통과 ' + pass + ' · 실패 ' + fail : '모두 통과 — ' + pass + '건');
process.exit(fail ? 1 : 0);
