-- 집 고르기 장부 — D1 스키마
--
-- 데이터는 "장부(book)" 단위로 묶입니다. 한 장부에 여러 사람이 들어올 수
-- 있고, 들어온 사람은 그 장부의 매물을 함께 읽고 씁니다.
-- 워커는 언제나 "지금 이 사람이 이 장부의 참여자인가"를 먼저 확인하고,
-- 모든 질의를 book_id 로 겁니다. 남의 장부는 SQL 단계에서 안 걸립니다.

CREATE TABLE IF NOT EXISTS users (
  email         TEXT PRIMARY KEY,       -- 소문자로 저장
  name          TEXT,
  pw            TEXT NOT NULL,          -- pbkdf2$반복수$소금$해시
  session_epoch INTEGER NOT NULL DEFAULT 1,
  current_book  TEXT,                   -- 마지막으로 보던 장부
  created_at    TEXT NOT NULL,
  last_login    TEXT
);

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

CREATE TABLE IF NOT EXISTS properties (
  book_id    TEXT NOT NULL,
  id         TEXT NOT NULL,
  data       TEXT NOT NULL,             -- 매물 한 곳의 JSON
  updated_at TEXT NOT NULL,
  updated_by TEXT,
  PRIMARY KEY (book_id, id)
);

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
