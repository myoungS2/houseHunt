-- 집 고르기 장부 — D1 스키마
-- 모든 데이터가 user_key(로그인한 이메일)를 달고 있고,
-- 워커는 로그인한 사람의 user_key로만 질의합니다. 남의 행은 SQL 단계에서 안 걸립니다.

CREATE TABLE IF NOT EXISTS users (
  email         TEXT PRIMARY KEY,       -- 소문자로 저장
  name          TEXT,
  pw            TEXT NOT NULL,          -- pbkdf2$반복수$소금$해시
  session_epoch INTEGER NOT NULL DEFAULT 1,   -- 비밀번호를 바꾸면 올라가고, 옛 세션이 끊깁니다
  created_at    TEXT NOT NULL,
  last_login    TEXT
);

-- 로그인·가입 시도 횟수. 키는 'e:이메일' / 'i:아이피' / 's:아이피' / 'p:이메일'
CREATE TABLE IF NOT EXISTS login_attempts (
  key      TEXT PRIMARY KEY,
  count    INTEGER NOT NULL,
  first_at INTEGER NOT NULL,
  until    INTEGER
);

CREATE TABLE IF NOT EXISTS properties (
  user_key   TEXT NOT NULL,
  id         TEXT NOT NULL,
  data       TEXT NOT NULL,             -- 매물 한 곳의 JSON
  updated_at TEXT NOT NULL,
  PRIMARY KEY (user_key, id)
);

CREATE TABLE IF NOT EXISTS settings (
  user_key   TEXT PRIMARY KEY,
  data       TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS photos (
  id           TEXT PRIMARY KEY,
  user_key     TEXT NOT NULL,
  object_key   TEXT NOT NULL,
  content_type TEXT,
  size         INTEGER,
  created_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_photos_user ON photos(user_key);
