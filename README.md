# 집 고르기 장부

전세와 매매 후보를 금액, 입주일, 장단점, 별점으로 비교하는 한 페이지 앱.
Cloudflare Worker에 올리면 이메일과 비밀번호로 로그인하고, 사람마다 자기 매물만 봅니다.

`index.html` 한 파일이 앱 전부입니다. 시작할 때 `/api/me`를 두드려 보고 서버에 붙습니다.
서버가 없으면 브라우저 저장으로 내려가므로 파일만 열어도 동작은 합니다.

---

## 배포 순서

### 1. D1 만들기

```bash
npx wrangler d1 create house-hunt
```

출력에 나온 `database_id`를 `wrangler.toml`에 붙여넣은 뒤 테이블을 만듭니다.

```bash
npx wrangler d1 execute house-hunt --remote --file=schema.sql
```

### 2. 사진 저장소 만들기

```bash
npx wrangler r2 bucket create house-hunt-photos
```

사진을 안 쓸 거면 건너뛰고 `wrangler.toml`의 `[[r2_buckets]]` 블록을 지우세요.

### 3. 비밀값 두 개 넣기

```bash
npx wrangler secret put SIGNUP_CODE
```

가입 코드입니다. 같이 쓸 사람에게만 알려주는 암호 한 줄이면 됩니다. 이게 없으면 아무도 가입하지 못합니다.

```bash
openssl rand -base64 48
npx wrangler secret put SESSION_SECRET
```

세션 서명용 열쇠입니다. 위에서 나온 값을 붙여넣으세요.

### 4. 배포

```bash
npx wrangler deploy
```

주소가 나오면 끝입니다. 열면 로그인 화면이 뜹니다.

---

## 같이 쓸 사람 들이기

주소와 가입 코드를 알려주면 각자 가입합니다. 코드는 카톡으로 보내도 됩니다. 코드로는 자기 계정을 만들 수 있을 뿐, 남의 매물은 못 봅니다.

**다 가입하고 나면 코드를 지우세요.** 지우면 가입 창구가 닫히고 이미 만든 계정만 남습니다.

```bash
npx wrangler secret delete SIGNUP_CODE
```

나중에 한 명 더 들일 일이 생기면 새 코드를 다시 넣으면 됩니다.

**이메일까지 못 박고 싶으면** `wrangler.toml`에 한 줄 더 씁니다. 코드를 알아도 이 목록에 없으면 가입이 안 됩니다.

```toml
ALLOWED_EMAILS = "나@gmail.com,배우자@gmail.com"
```

---

## 비밀번호를 잊었을 때

비밀번호는 서버에 없어서 찾아줄 수 없습니다. 임시 비밀번호로 갈아끼웁니다.

```bash
node tools/reset-password.mjs 배우자@gmail.com "임시비밀번호1234"
```

출력된 SQL을 실행하면 그 사람의 기존 로그인이 전부 끊기고 임시 비밀번호만 통합니다.
알려준 뒤 앱의 설정 화면에서 본인이 바꾸게 하세요.

---

## 비밀번호를 어떻게 지키는가

**비밀번호는 서버에 도착하지 않습니다.** 브라우저가 PBKDF2로 60만 번 늘린 결과만 보냅니다. 워커는 거기에 임의 소금을 섞어 1만 2천 번 더 늘려 저장합니다. D1을 통째로 훔쳐도 원래 비밀번호를 캐려면 한 번 찍을 때마다 61만 번을 돌려야 합니다.

늘리는 일을 브라우저에 맡긴 이유는 Workers 무료 플랜의 요청당 CPU 한도 때문입니다. 61만 번을 워커에서 다 돌리면 한도를 넘깁니다.

**대신 서버가 비밀번호 길이를 검사하지 못합니다.** 비밀번호를 못 보기 때문입니다. 10자 제한은 화면에서 겁니다. 온라인으로 찍어보는 공격은 아래 횟수 제한이 막습니다.

| 막는 것 | 어떻게 |
|---|---|
| 무차별 대입 | 이메일당 15분에 8번, 아이피당 24번 실패하면 15분 잠금 |
| 가입 남용 | 아이피당 한 시간에 5번 |
| 계정 있는지 떠보기 | 없는 계정에도 같은 계산 시간과 같은 문구 |
| 세션 위조 | HMAC 서명, HttpOnly, SameSite=Lax, 30일 만료 |
| 비밀번호 바뀐 뒤 남은 세션 | 계정마다 세대 번호를 올려 전부 끊음 |
| 다른 사이트에서 보낸 요청 | 쓰기 요청은 Origin 검사 |
| 스크립트 주입 | 페이지마다 nonce를 새로 발급하는 CSP |
| 프레임에 끼워 넣기 | `frame-ancestors 'none'` |

---

## 사람별 분리가 걸리는 방식

모든 행이 `user_key`(로그인한 이메일)를 달고 있고, 워커는 그 키로만 질의합니다. 남의 행은 SQL 단계에서 안 걸립니다.

`properties`의 기본키가 `(user_key, id)`라 두 사람이 같은 매물 id를 써도 각자 행이 따로 생깁니다. 남의 행을 덮어쓸 방법이 없습니다.

사진은 `/photo/<id>`로 조회할 때 소유자를 확인합니다. 남의 사진 id를 넣으면 404가 납니다.

서버 모드에서는 매물을 브라우저에 캐시하지 않습니다. 한 기기를 여러 사람이 써도 로그아웃하면 남지 않습니다.

---

## 로컬에서 돌려보기

```bash
npx wrangler d1 execute house-hunt --local --file=schema.sql
printf 'SESSION_SECRET=아무거나\nSIGNUP_CODE=테스트코드\n' > .dev.vars
npx wrangler dev --local
```

`.dev.vars`에 `ALLOW_OPEN=1`을 넣으면 로그인을 건너뜁니다. 배포한 주소에서는 절대 켜지 마세요.

---

## 파일

| 파일 | 하는 일 |
|---|---|
| `index.html` | 앱 전부. 화면, 계산, 저장 계층 |
| `src/worker.js` | 로그인, 회원가입, API, 앱 서빙 |
| `schema.sql` | D1 테이블 |
| `wrangler.toml` | 바인딩과 설정 |
| `tools/reset-password.mjs` | 비밀번호 초기화 SQL 생성 |

`tools/reset-password.mjs`의 반복 횟수는 `src/worker.js`의 `CLIENT_ITER`, `SERVER_ITER`와 같아야 합니다. 한쪽만 바꾸면 기존 비밀번호가 전부 안 맞게 됩니다.
