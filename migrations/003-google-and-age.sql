-- 구글 로그인과 연령대를 받을 자리를 만듭니다.
-- 이미 배포된 데이터베이스에서 한 번만 실행하세요. 기존 계정은 그대로 보존되고,
-- 전부 provider='password' 로 표시됩니다.
--
-- users.pw 는 NOT NULL 이었는데, 구글로만 들어온 사람은 비밀번호가 없습니다.
-- SQLite 는 컬럼의 NOT NULL 을 나중에 풀 수 없어서 표를 새로 만들어 옮깁니다.

CREATE TABLE users_new (
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

INSERT INTO users_new
  (email, name, pw, session_epoch, current_book, created_at, last_login, provider, google_sub, age_band)
  SELECT email, name, pw, session_epoch, current_book, created_at, last_login,
         'password', NULL, NULL
  FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

-- 한 구글 계정이 여러 이메일에 붙는 일을 막습니다. NULL 은 여럿이어도 됩니다.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google ON users(google_sub);
