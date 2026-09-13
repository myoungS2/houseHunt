-- 사람별로 나뉘어 있던 데이터를 "장부" 단위로 옮깁니다.
-- 이미 배포된 데이터베이스에서 한 번만 실행하세요. 데이터는 그대로 보존됩니다.
-- 실행 뒤에는 사람마다 자기 이름의 장부 하나를 갖고, 그 장부의 주인이 됩니다.

CREATE TABLE IF NOT EXISTS books (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, owner_key TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS book_members (
  book_id TEXT NOT NULL, user_key TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member', joined_at TEXT NOT NULL,
  PRIMARY KEY (book_id, user_key)
);
CREATE INDEX IF NOT EXISTS idx_members_user ON book_members(user_key);
CREATE TABLE IF NOT EXISTS book_invites (
  token TEXT PRIMARY KEY, book_id TEXT NOT NULL, created_by TEXT NOT NULL,
  created_at TEXT NOT NULL, expires_at INTEGER NOT NULL, used_at TEXT, used_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_invites_book ON book_invites(book_id);

-- 사람마다 장부 하나를 만들고 주인으로 넣는다
INSERT INTO books (id, name, owner_key, created_at)
  SELECT 'b_' || lower(hex(randomblob(9))),
         COALESCE(NULLIF(name,''), substr(email,1,instr(email,'@')-1)) || '의 장부',
         email, created_at
  FROM users
  WHERE email NOT IN (SELECT owner_key FROM books);

INSERT OR IGNORE INTO book_members (book_id, user_key, role, joined_at)
  SELECT id, owner_key, 'owner', created_at FROM books;

-- users 에 보던 장부 칸을 더한다 (이미 있으면 이 줄만 오류가 나고 넘어갑니다)
ALTER TABLE users ADD COLUMN current_book TEXT;
UPDATE users SET current_book = (SELECT id FROM books WHERE books.owner_key = users.email)
  WHERE current_book IS NULL;

-- 매물과 설정을 장부 앞으로 옮긴다
CREATE TABLE properties_new (
  book_id TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL,
  updated_at TEXT NOT NULL, updated_by TEXT, PRIMARY KEY (book_id, id)
);
INSERT INTO properties_new (book_id, id, data, updated_at, updated_by)
  SELECT b.id, p.id, p.data, p.updated_at, p.user_key
  FROM properties p JOIN books b ON b.owner_key = p.user_key;
DROP TABLE properties;
ALTER TABLE properties_new RENAME TO properties;

CREATE TABLE settings_new (
  book_id TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at TEXT NOT NULL
);
INSERT INTO settings_new (book_id, data, updated_at)
  SELECT b.id, s.data, s.updated_at
  FROM settings s JOIN books b ON b.owner_key = s.user_key;
DROP TABLE settings;
ALTER TABLE settings_new RENAME TO settings;

-- 사진은 아직 안 쓰고 있어 새로 만든다
DROP TABLE IF EXISTS photos;
CREATE TABLE photos (
  id TEXT PRIMARY KEY, book_id TEXT NOT NULL, uploaded_by TEXT, object_key TEXT NOT NULL,
  content_type TEXT, size INTEGER, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_photos_book ON photos(book_id);
