-- 연령대별 통계를 SQL 한 줄로 낼 수 있게 만듭니다.
--
-- 매물 한 곳은 properties.data 에 JSON 한 덩어리로 들어 있습니다. 이걸 복사해서
-- 따로 쌓으면 둘이 어긋나기 시작하므로, "생성 컬럼"으로 JSON 안을 그대로 비춰만 봅니다.
-- 저장하는 쪽 코드는 하나도 바뀌지 않고, 이미 들어 있는 매물도 즉시 집계됩니다.
--
-- 통계를 누구의 것으로 셀지: 장부는 여럿이 함께 쓰므로 마지막 수정자(updated_by)로 세면
-- 남이 한 번 고칠 때마다 주인이 바뀝니다. 그래서 처음 넣은 사람(created_by)을 따로 둡니다.

ALTER TABLE properties ADD COLUMN created_by TEXT;
UPDATE properties SET created_by = updated_by WHERE created_by IS NULL;

-- JSON 안을 비추는 칸들. 값을 따로 담지 않으므로 용량이 늘지 않습니다.
ALTER TABLE properties ADD COLUMN deal_type TEXT
  GENERATED ALWAYS AS (json_extract(data, '$.dealType')) VIRTUAL;
ALTER TABLE properties ADD COLUMN price INTEGER
  GENERATED ALWAYS AS (json_extract(data, '$.price')) VIRTUAL;
ALTER TABLE properties ADD COLUMN area REAL
  GENERATED ALWAYS AS (json_extract(data, '$.area')) VIRTUAL;
ALTER TABLE properties ADD COLUMN status TEXT
  GENERATED ALWAYS AS (json_extract(data, '$.status')) VIRTUAL;
ALTER TABLE properties ADD COLUMN rooms INTEGER
  GENERATED ALWAYS AS (json_extract(data, '$.rooms')) VIRTUAL;
ALTER TABLE properties ADD COLUMN station TEXT
  GENERATED ALWAYS AS (json_extract(data, '$.station')) VIRTUAL;

CREATE INDEX IF NOT EXISTS idx_props_deal    ON properties(deal_type);
CREATE INDEX IF NOT EXISTS idx_props_creator ON properties(created_by);
CREATE INDEX IF NOT EXISTS idx_users_age     ON users(age_band);

-- 집계는 전부 이 뷰 하나를 봅니다. 금액은 만원, 면적은 m² 입니다.
CREATE VIEW IF NOT EXISTS v_prop_stats AS
SELECT
  p.book_id,
  p.id,
  p.deal_type,
  p.price,
  p.area,
  p.rooms,
  p.status,
  p.station,
  CASE WHEN p.area > 0 THEN ROUND(p.area / 3.305785, 2) END AS pyeong,
  CASE WHEN p.area > 0 AND p.price IS NOT NULL
       THEN ROUND(p.price / (p.area / 3.305785), 1) END AS per_pyeong,
  COALESCE(p.created_by, p.updated_by) AS finder,
  u.age_band,
  p.updated_at
FROM properties p
LEFT JOIN users u ON u.email = COALESCE(p.created_by, p.updated_by);
