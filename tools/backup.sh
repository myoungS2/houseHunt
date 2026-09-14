#!/usr/bin/env bash
# D1을 통째로 내보내 이 컴퓨터에 보관합니다.
#
#   ./tools/backup.sh                      ~/Backups/house-hunt 에 저장
#   ./tools/backup.sh ~/Dropbox/backup     원하는 곳에 저장
#
# 최근 30개만 남기고 오래된 것은 지웁니다.
set -euo pipefail

DIR="${1:-$HOME/Backups/house-hunt}"
KEEP=30
STAMP=$(date +%Y%m%d-%H%M)
OUT="$DIR/house-hunt-$STAMP.sql"

mkdir -p "$DIR"
echo "내보내는 중…"
npx --yes wrangler@4 d1 export house-hunt --remote --output="$OUT"

SIZE=$(wc -c < "$OUT" | tr -d ' ')
if [ "$SIZE" -lt 2000 ]; then
  echo "덤프가 너무 작습니다 (${SIZE}바이트). 지우고 멈춥니다." >&2
  rm -f "$OUT"; exit 1
fi

for T in users books book_members properties settings photos; do
  grep -q "CREATE TABLE .*\"\?${T}\"\?" "$OUT" \
    || { echo "$T 테이블이 덤프에 없습니다. 지우고 멈춥니다." >&2; rm -f "$OUT"; exit 1; }
done

gzip -f "$OUT"
echo "저장했습니다: $OUT.gz  ($(( SIZE / 1024 ))KB → $(wc -c < "$OUT.gz" | tr -d ' ') 바이트)"

COUNT=$(ls -1 "$DIR"/house-hunt-*.sql.gz 2>/dev/null | wc -l | tr -d ' ')
if [ "$COUNT" -gt "$KEEP" ]; then
  ls -1t "$DIR"/house-hunt-*.sql.gz | tail -n +$((KEEP+1)) | xargs rm -f
  echo "오래된 백업 $((COUNT-KEEP))개를 지웠습니다. 지금 $KEEP개 보관 중."
else
  echo "지금 ${COUNT}개 보관 중."
fi
