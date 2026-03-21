#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"

BASE_URL="${BASE_URL:-http://127.0.0.1}"
ADMIN_API_BASE="${ADMIN_API_BASE:-$BASE_URL/safeline-admin-api}"
JWT_SECRET_VALUE="${JWT_SECRET:-}"

if [ -z "$JWT_SECRET_VALUE" ]; then
  echo "[security-smoke] JWT_SECRET is required"
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "[security-smoke] curl not found"
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "[security-smoke] node not found"
  exit 1
fi

TOKEN="$(JWT_SECRET="$JWT_SECRET_VALUE" node - <<'NODE'
const crypto = require('crypto');
const secret = process.env.JWT_SECRET || '';
const h = (s) => Buffer.from(s).toString('base64url');
const now = Math.floor(Date.now() / 1000);
const header = h(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
const payload = h(JSON.stringify({
  username: 'admin',
  role: 'administrator',
  iat: now,
  exp: now + 8 * 3600,
}));
const data = `${header}.${payload}`;
const sig = crypto.createHmac('sha256', secret).update(data).digest('base64url');
process.stdout.write(`${data}.${sig}`);
NODE
)"

auth_header="Authorization: Bearer $TOKEN"

put_site() {
  domain="$1"
  payload="$2"
  echo "[security-smoke] upserting $domain"
  response="$(curl -sS -X PUT \
    -H "$auth_header" \
    -H 'Content-Type: application/json' \
    --data "$payload" \
    "$ADMIN_API_BASE/sites/$domain")"
  echo "$response"
  echo "$response" | grep -q '"success":true' || {
    echo "[security-smoke] failed to publish $domain"
    exit 1
  }
  echo
}

assert_status_contains() {
  label="$1"
  expected_status="$2"
  expected_pattern="$3"
  shift 3

  response="$(curl -i -sS "$@")"
  echo "$response"

  echo "$response" | grep -q "HTTP/.* $expected_status" || {
    echo "[security-smoke] $label failed: expected HTTP $expected_status"
    exit 1
  }

  if [ -n "$expected_pattern" ]; then
    echo "$response" | grep -q "$expected_pattern" || {
      echo "[security-smoke] $label failed: expected pattern $expected_pattern"
      exit 1
    }
  fi
}

assert_block_or_drop() {
  label="$1"
  shift 1

  set +e
  response="$(curl -i -sS "$@" 2>&1)"
  status=$?
  set -e

  echo "$response"

  if [ "$status" -ne 0 ]; then
    case "$status" in
      52|56)
        return 0
        ;;
    esac
    echo "[security-smoke] $label failed: unexpected curl exit $status"
    exit 1
  fi

  echo "$response" | grep -Eq 'HTTP/.* (403|444)' || {
    echo "[security-smoke] $label failed: expected block/drop response"
    exit 1
  }
}

echo "[security-smoke] checking health"
health_attempt=1
while [ "$health_attempt" -le 10 ]; do
  set +e
  health_response="$(curl -sS "$ADMIN_API_BASE/health" 2>&1)"
  health_status=$?
  set -e
  if [ "$health_status" -eq 0 ] && echo "$health_response" | grep -q '"status":"ok"'; then
    echo "$health_response"
    break
  fi
  if [ "$health_attempt" -eq 10 ]; then
    echo "$health_response"
    echo "[security-smoke] health check failed"
    exit 1
  fi
  sleep 2
  health_attempt=$((health_attempt + 1))
done
echo

UI_SITE_PAYLOAD='{"domain":"ui.test.local","backend_server":"http://admin-frontend:80","backend_port_follow":false,"enabled":true,"tls":{"enabled":false},"protection":{"browser_detection_enabled":false,"environment_detection_enabled":false,"ip_blacklist_enabled":false,"global_rate_limit_enabled":false,"ddos_protection_enabled":false,"slow_ddos_protection_enabled":false,"origin_proxy_only_enabled":false,"random_attack_protection_enabled":false,"request_content_inspection_enabled":false,"anti_cc_enabled":false,"automation_detection_enabled":false,"traffic_analysis_enabled":false,"request_sampling_enabled":false,"honeypot_enabled":false,"auto_blacklist_enabled":false,"request_logging_enabled":true},"verification_methods":{"captcha_enabled":true,"slider_captcha_enabled":true,"pow_enabled":true}}'
SECURE_SITE_PAYLOAD='{"domain":"secure.test.local","backend_server":"http://admin-frontend:80","backend_port_follow":false,"enabled":true,"tls":{"enabled":true},"protection":{"browser_detection_enabled":false,"environment_detection_enabled":false,"ip_blacklist_enabled":false,"global_rate_limit_enabled":false,"ddos_protection_enabled":false,"slow_ddos_protection_enabled":false,"origin_proxy_only_enabled":false,"random_attack_protection_enabled":false,"request_content_inspection_enabled":false,"anti_cc_enabled":false,"automation_detection_enabled":false,"traffic_analysis_enabled":false,"request_sampling_enabled":false,"honeypot_enabled":false,"auto_blacklist_enabled":false,"request_logging_enabled":true},"verification_methods":{"captcha_enabled":true,"slider_captcha_enabled":true,"pow_enabled":true}}'
INJECT_SITE_PAYLOAD='{"domain":"inject.test.local","backend_server":"http://admin-frontend:80","backend_port_follow":false,"enabled":true,"tls":{"enabled":false},"protection":{"browser_detection_enabled":false,"environment_detection_enabled":false,"ip_blacklist_enabled":false,"global_rate_limit_enabled":false,"ddos_protection_enabled":false,"slow_ddos_protection_enabled":false,"origin_proxy_only_enabled":false,"random_attack_protection_enabled":false,"request_content_inspection_enabled":false,"anti_cc_enabled":false,"automation_detection_enabled":false,"traffic_analysis_enabled":false,"request_sampling_enabled":false,"honeypot_enabled":false,"auto_blacklist_enabled":false,"request_logging_enabled":true,"js_encryption_enabled":true,"prevent_browser_f12":true},"verification_methods":{"captcha_enabled":true,"slider_captcha_enabled":true,"pow_enabled":true}}'
RATE_SITE_PAYLOAD='{"domain":"rate.test.local","backend_server":"http://admin-frontend:80","backend_port_follow":false,"enabled":true,"tls":{"enabled":false},"protection":{"browser_detection_enabled":false,"environment_detection_enabled":false,"ip_blacklist_enabled":false,"global_rate_limit_enabled":true,"global_rate_limit_count":1,"global_rate_limit_window":60,"ddos_protection_enabled":false,"slow_ddos_protection_enabled":false,"origin_proxy_only_enabled":false,"random_attack_protection_enabled":false,"request_content_inspection_enabled":false,"anti_cc_enabled":false,"automation_detection_enabled":false,"traffic_analysis_enabled":false,"request_sampling_enabled":false,"honeypot_enabled":false,"auto_blacklist_enabled":false,"request_logging_enabled":true},"verification_methods":{"captcha_enabled":true,"slider_captcha_enabled":true,"pow_enabled":true}}'
PAYLOAD_SITE_PAYLOAD='{"domain":"payload.test.local","backend_server":"http://admin-frontend:80","backend_port_follow":false,"enabled":true,"tls":{"enabled":false},"protection":{"browser_detection_enabled":false,"environment_detection_enabled":false,"ip_blacklist_enabled":false,"global_rate_limit_enabled":false,"ddos_protection_enabled":false,"slow_ddos_protection_enabled":false,"origin_proxy_only_enabled":false,"random_attack_protection_enabled":false,"request_content_inspection_enabled":true,"anti_cc_enabled":false,"automation_detection_enabled":false,"traffic_analysis_enabled":false,"request_sampling_enabled":false,"honeypot_enabled":false,"auto_blacklist_enabled":false,"request_logging_enabled":true},"verification_methods":{"captcha_enabled":true,"slider_captcha_enabled":true,"pow_enabled":true}}'
PROTECT_SITE_PAYLOAD='{"domain":"protect.test.local","backend_server":"http://admin-frontend:80","backend_port_follow":false,"enabled":true,"tls":{"enabled":false},"protection":{"browser_detection_enabled":true,"environment_detection_enabled":true,"ip_blacklist_enabled":true,"global_rate_limit_enabled":false,"ddos_protection_enabled":true,"slow_ddos_protection_enabled":true,"origin_proxy_only_enabled":false,"random_attack_protection_enabled":true,"request_content_inspection_enabled":true,"anti_cc_enabled":true,"automation_detection_enabled":true,"traffic_analysis_enabled":true,"request_sampling_enabled":true,"honeypot_enabled":true,"auto_blacklist_enabled":true,"request_logging_enabled":true},"verification_methods":{"captcha_enabled":true,"slider_captcha_enabled":true,"pow_enabled":true}}'
AUTOMATION_SITE_PAYLOAD='{"domain":"automation.test.local","backend_server":"http://admin-frontend:80","backend_port_follow":false,"enabled":true,"tls":{"enabled":false},"protection":{"browser_detection_enabled":false,"environment_detection_enabled":false,"ip_blacklist_enabled":false,"global_rate_limit_enabled":false,"ddos_protection_enabled":false,"slow_ddos_protection_enabled":false,"origin_proxy_only_enabled":false,"random_attack_protection_enabled":false,"request_content_inspection_enabled":false,"anti_cc_enabled":false,"automation_detection_enabled":true,"traffic_analysis_enabled":false,"request_sampling_enabled":false,"honeypot_enabled":false,"auto_blacklist_enabled":false,"request_logging_enabled":true},"verification_methods":{"captcha_enabled":true,"slider_captcha_enabled":true,"pow_enabled":true}}'
RANDOM_SITE_PAYLOAD='{"domain":"random.test.local","backend_server":"http://admin-frontend:80","backend_port_follow":false,"enabled":true,"tls":{"enabled":false},"protection":{"browser_detection_enabled":false,"environment_detection_enabled":false,"ip_blacklist_enabled":false,"global_rate_limit_enabled":false,"ddos_protection_enabled":false,"slow_ddos_protection_enabled":false,"origin_proxy_only_enabled":false,"random_attack_protection_enabled":true,"request_content_inspection_enabled":false,"anti_cc_enabled":false,"automation_detection_enabled":false,"traffic_analysis_enabled":false,"request_sampling_enabled":false,"honeypot_enabled":false,"auto_blacklist_enabled":false,"request_logging_enabled":true},"verification_methods":{"captcha_enabled":true,"slider_captcha_enabled":true,"pow_enabled":true}}'

put_site "ui.test.local" "$UI_SITE_PAYLOAD"
put_site "secure.test.local" "$SECURE_SITE_PAYLOAD"
put_site "inject.test.local" "$INJECT_SITE_PAYLOAD"
put_site "rate.test.local" "$RATE_SITE_PAYLOAD"
put_site "payload.test.local" "$PAYLOAD_SITE_PAYLOAD"
put_site "protect.test.local" "$PROTECT_SITE_PAYLOAD"
put_site "automation.test.local" "$AUTOMATION_SITE_PAYLOAD"
put_site "random.test.local" "$RANDOM_SITE_PAYLOAD"

# Give nginx workers a brief moment to settle after the last hot reload.
sleep 1

echo "[security-smoke] ui.test.local should return frontend HTML"
assert_status_contains "ui-http" "200" "<div id=\"app\"></div>" -H 'Host: ui.test.local' "$BASE_URL/"

echo "[security-smoke] secure.test.local should redirect to HTTPS"
assert_status_contains "secure-http" "301" "Location: https://secure.test.local/" --resolve secure.test.local:80:127.0.0.1 "http://secure.test.local/"

echo "[security-smoke] secure.test.local should serve HTTPS"
assert_status_contains "secure-https" "200" "<div id=\"app\"></div>" -k --resolve secure.test.local:443:127.0.0.1 "https://secure.test.local/"

echo "[security-smoke] inject.test.local should inject JS/F12 protection"
inject_body="$(curl -sS --resolve inject.test.local:80:127.0.0.1 "http://inject.test.local/")"
echo "$inject_body" | grep -Eq 'safeline\.js\.fp|Developer Tools Detected|contextmenu|keyCode === 123' || {
  echo "[security-smoke] inject-site failed: missing injected protection script"
  exit 1
}
echo "[security-smoke] inject-site ok"

echo "[security-smoke] rate.test.local first request should pass"
assert_status_contains "rate-first" "200" "<div id=\"app\"></div>" --resolve rate.test.local:80:127.0.0.1 "http://rate.test.local/"

echo "[security-smoke] rate.test.local second request should challenge"
rate_second="$(curl -i -sS --resolve rate.test.local:80:127.0.0.1 "http://rate.test.local/")"
echo "$rate_second"
echo "$rate_second" | grep -q "HTTP/.* 302" || {
  echo "[security-smoke] rate-second failed: expected 302"
  exit 1
}
echo "$rate_second" | grep -Eq 'Location: /pow|Location: /safeline-static/verify.html' || {
  echo "[security-smoke] rate-second failed: expected challenge redirect"
  exit 1
}

echo "[security-smoke] payload.test.local should block SQLi"
assert_block_or_drop "payload-sqli" --get --resolve payload.test.local:80:127.0.0.1 --data-urlencode "q=' OR 1=1 --" "http://payload.test.local/"

echo "[security-smoke] payload.test.local should block XSS"
assert_block_or_drop "payload-xss" --get --resolve payload.test.local:80:127.0.0.1 --data-urlencode "x=<script>alert(1)</script>" "http://payload.test.local/"

echo "[security-smoke] payload.test.local should block path traversal"
assert_block_or_drop "payload-path-traversal" --get --resolve payload.test.local:80:127.0.0.1 --data-urlencode "file=../../etc/passwd" "http://payload.test.local/"

echo "[security-smoke] payload.test.local should block SSRF metadata access"
assert_block_or_drop "payload-ssrf" --get --resolve payload.test.local:80:127.0.0.1 --data-urlencode "url=http://169.254.169.254/latest/meta-data" "http://payload.test.local/"

echo "[security-smoke] payload.test.local should block OGNL/SpEL style expressions"
assert_block_or_drop "payload-expression" --get --resolve payload.test.local:80:127.0.0.1 --data-urlencode "expr=%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X','1')}" "http://payload.test.local/"

echo "[security-smoke] protect.test.local honeypot should drop connection or block"
attempt=1
protect_out=''
protect_code=1
while [ "$attempt" -le 3 ]; do
  set +e
  protect_out="$(curl -i -sS --resolve protect.test.local:80:127.0.0.1 "http://protect.test.local/wp-login.php" 2>&1)"
  protect_code=$?
  set -e

  if [ "$protect_code" -eq 0 ] && echo "$protect_out" | grep -q 'No matching site'; then
    sleep 1
    attempt=$((attempt + 1))
    continue
  fi
  break
done
echo "$protect_out"
if [ "$protect_code" -ne 0 ]; then
  case "$protect_code" in
    52|56)
      echo "[security-smoke] protect-honeypot ok (connection dropped)"
      protect_ok=1
      ;;
  esac
  if [ "${protect_ok:-0}" -ne 1 ]; then
    echo "[security-smoke] protect-honeypot failed: unexpected curl exit $protect_code"
    exit 1
  fi
fi
if [ "${protect_ok:-0}" -ne 1 ]; then
  echo "$protect_out" | grep -Eq 'HTTP/.* (403|444)' || {
    echo "[security-smoke] protect-honeypot failed: expected block status"
    exit 1
  }
fi

echo "[security-smoke] automation probe should trigger a protective response"
sh "$ROOT_DIR/scripts/automation_probe.sh" automation.test.local "$BASE_URL"

echo "[security-smoke] random probe should trigger a protective response"
sh "$ROOT_DIR/scripts/random_probe.sh" random.test.local "$BASE_URL"

echo "[security-smoke] done"
