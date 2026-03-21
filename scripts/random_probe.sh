#!/usr/bin/env sh
set -eu

HOST="${1:-random.test.local}"
BASE_URL="${2:-http://127.0.0.1}"

fire_probe() {
  set +e
  curl -sS -o /dev/null -H "Host: $HOST" "$1"
  status=$?
  set -e

  case "$status" in
    0) return 0 ;;
    52|56) return 0 ;;
  esac

  echo "[random-probe] unexpected warmup curl exit $status"
  exit 1
}

for path in a b c d e f g h i j; do
  fire_probe "$BASE_URL/$path?x=$path"
done

set +e
response="$(curl -i -sS --max-time 5 -H "Host: $HOST" "$BASE_URL/final?rand=12345" 2>&1)"
status=$?
set -e

echo "$response"
if [ "$status" -ne 0 ]; then
  case "$status" in
    52|56)
      echo "[random-probe] ok (connection dropped)"
      exit 0
      ;;
  esac
  echo "[random-probe] unexpected curl exit $status"
  exit 1
fi

echo "$response" | grep -Eq 'HTTP/.* (302|403|429|444)' || {
  echo "[random-probe] expected protective response"
  exit 1
}
echo "[random-probe] ok"
