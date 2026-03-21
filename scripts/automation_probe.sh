#!/usr/bin/env sh
set -eu

HOST="${1:-automation.test.local}"
BASE_URL="${2:-http://127.0.0.1}"
COUNT="${3:-20}"

fire_probe() {
  set +e
  curl -sS -o /dev/null \
    -H "Host: $HOST" \
    -H "Pragma: no-cache" \
    -H "Cache-Control: no-cache" \
    -H "Accept-Encoding: gzip, deflate" \
    -H "Accept-Language: en-US,en;q=0.9" \
    -H "X-JA3-Fingerprint: test-ja3" \
    "$1"
  status=$?
  set -e

  case "$status" in
    0) return 0 ;;
    52|56) return 0 ;;
  esac

  echo "[automation-probe] unexpected warmup curl exit $status"
  exit 1
}

i=1
while [ "$i" -le "$COUNT" ]; do
  fire_probe "$BASE_URL/probe$i"
  i=$((i + 1))
done

set +e
response="$(curl -i -sS --max-time 5 \
  -H "Host: $HOST" \
  -H "Pragma: no-cache" \
  -H "Cache-Control: no-cache" \
  -H "Accept-Encoding: gzip, deflate" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "X-JA3-Fingerprint: test-ja3" \
  "$BASE_URL/final" 2>&1)"
status=$?
set -e

echo "$response"
if [ "$status" -ne 0 ]; then
  case "$status" in
    52|56)
      echo "[automation-probe] ok (connection dropped)"
      exit 0
      ;;
  esac
  echo "[automation-probe] unexpected curl exit $status"
  exit 1
fi

echo "$response" | grep -Eq 'HTTP/.* (302|403|429|444)' || {
  echo "[automation-probe] expected protective response"
  exit 1
}
echo "[automation-probe] ok"
