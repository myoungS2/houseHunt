-- 집 고르기 장부 — D1 스키마
--
-- 데이터는 "장부(book)" 단위로 묶입니다. 한 장부에 여러 사람이 들어올 수
-- 있고, 들어온 사람은 그 장부의 매물을 함께 읽고 씁니다.
-- 워커는 언제나 "지금 이 사람이 이 장부의 참여자인가"를 먼저 확인하고,
-- 모든 질의를 book_id 로 겁니다. 남의 장부는 SQL 단계에서 안 걸립니다.

CREATE TABLE IF NOT EXISTS users (
  email         TEXT PRIMARY KEY,       -- 소문자로 저장
  name          TEXT,
  pw            TEXT,                   -- pbkdf2$반복수$소금$해시. 구글 전용 계정은 NULL
  session_epoch INTEGER NOT NULL DEFAULT 1,
  current_book  TEXT,                   -- 마지막으로 보던 장부
  created_at    TEXT NOT NULL,
  last_login    TEXT,
  provider      TEXT NOT NULL DEFAULT 'password',  -- password | google | both
  google_sub    TEXT,                   -- 구글이 주는 사람 고유 번호. 이메일이 바뀌어도 안 바뀝니다
  age_band      TEXT                    -- 10s | 20s | 30s | 40s | 50s | 60s | NULL(안 밝힘)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google ON users(google_sub);
CREATE INDEX IF NOT EXISTS idx_users_age ON users(age_band);

CREATE TABLE IF NOT EXISTS books (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  owner_key  TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS book_members (
  book_id   TEXT NOT NULL,
  user_key  TEXT NOT NULL,
  role      TEXT NOT NULL DEFAULT 'member',   -- owner | member
  joined_at TEXT NOT NULL,
  PRIMARY KEY (book_id, user_key)
);
CREATE INDEX IF NOT EXISTS idx_members_user ON book_members(user_key);

-- 초대 링크. 한 번 쓰면 닫히고, 기한이 지나면 안 열립니다.
CREATE TABLE IF NOT EXISTS book_invites (
  token      TEXT PRIMARY KEY,
  book_id    TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    TEXT,
  used_by    TEXT
);
CREATE INDEX IF NOT EXISTS idx_invites_book ON book_invites(book_id);

-- deal_type 아래 여섯 칸은 data 안의 JSON 을 비추기만 합니다. 값을 따로 담지 않으므로
-- 저장하는 쪽은 아무것도 신경 쓸 게 없고, 통계는 이 칸들로 바로 집계됩니다.
CREATE TABLE IF NOT EXISTS properties (
  book_id    TEXT NOT NULL,
  id         TEXT NOT NULL,
  data       TEXT NOT NULL,             -- 매물 한 곳의 JSON
  updated_at TEXT NOT NULL,
  updated_by TEXT,
  created_by TEXT,                      -- 처음 넣은 사람. 통계는 이 사람 앞으로 셉니다
  deal_type  TEXT    GENERATED ALWAYS AS (json_extract(data, '$.dealType')) VIRTUAL,
  price      INTEGER GENERATED ALWAYS AS (json_extract(data, '$.price'))    VIRTUAL,
  area       REAL    GENERATED ALWAYS AS (json_extract(data, '$.area'))     VIRTUAL,
  status     TEXT    GENERATED ALWAYS AS (json_extract(data, '$.status'))   VIRTUAL,
  rooms      INTEGER GENERATED ALWAYS AS (json_extract(data, '$.rooms'))    VIRTUAL,
  station    TEXT    GENERATED ALWAYS AS (json_extract(data, '$.station'))  VIRTUAL,
  PRIMARY KEY (book_id, id)
);
CREATE INDEX IF NOT EXISTS idx_props_deal    ON properties(deal_type);
CREATE INDEX IF NOT EXISTS idx_props_creator ON properties(created_by);

-- 연령대별 집계는 전부 이 뷰 하나를 봅니다. 금액은 만원, 면적은 m² 입니다.
CREATE VIEW IF NOT EXISTS v_prop_stats AS
SELECT
  p.book_id, p.id, p.deal_type, p.price, p.area, p.rooms, p.status, p.station,
  CASE WHEN p.area > 0 THEN ROUND(p.area / 3.305785, 2) END AS pyeong,
  CASE WHEN p.area > 0 AND p.price IS NOT NULL
       THEN ROUND(p.price / (p.area / 3.305785), 1) END AS per_pyeong,
  COALESCE(p.created_by, p.updated_by) AS finder,
  u.age_band,
  p.updated_at
FROM properties p
LEFT JOIN users u ON u.email = COALESCE(p.created_by, p.updated_by);

CREATE TABLE IF NOT EXISTS settings (
  book_id    TEXT PRIMARY KEY,
  data       TEXT NOT NULL,             -- 금리, 별점 항목과 가중치
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS photos (
  id           TEXT PRIMARY KEY,
  book_id      TEXT NOT NULL,
  uploaded_by  TEXT,
  storage      TEXT NOT NULL DEFAULT 'db',   -- r2 | db
  object_key   TEXT NOT NULL,
  content_type TEXT,
  size         INTEGER,
  created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_photos_book ON photos(book_id);

-- 로그인·가입 시도 횟수. 키는 'e:이메일' / 'i:아이피' / 's:아이피' / 'p:이메일'
CREATE TABLE IF NOT EXISTS login_attempts (
  key      TEXT PRIMARY KEY,
  count    INTEGER NOT NULL,
  first_at INTEGER NOT NULL,
  until    INTEGER
);

-- 사진 본체. R2 버킷이 연결돼 있으면 거기에 두고, 없으면 여기에 담습니다.
-- photos.storage 가 'r2' 인지 'db' 인지로 어디에 있는지 구분합니다.
CREATE TABLE IF NOT EXISTS photo_blobs (
  id   TEXT PRIMARY KEY,
  data BLOB NOT NULL
);
