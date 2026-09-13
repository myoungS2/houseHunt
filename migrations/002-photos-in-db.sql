-- R2를 안 켜도 사진을 쓸 수 있게, 사진 본체를 D1에 담을 자리를 만듭니다.
-- R2가 연결돼 있으면 새 사진은 계속 R2로 갑니다. photos.storage 가 어디에 있는지 알려줍니다.

ALTER TABLE photos ADD COLUMN storage TEXT NOT NULL DEFAULT 'db';

CREATE TABLE IF NOT EXISTS photo_blobs (
  id   TEXT PRIMARY KEY,
  data BLOB NOT NULL
);
