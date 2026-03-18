#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "[doctor] project root: $ROOT_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "[doctor] docker not found in PATH"
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "[doctor] docker compose is not available"
  exit 1
fi

echo "[doctor] checking compose syntax"
docker compose config >/dev/null

echo "[doctor] checking JWT secret configuration"
JWT_SECRET_VALUE="${JWT_SECRET:-}"
if [ -z "$JWT_SECRET_VALUE" ] || [ "$JWT_SECRET_VALUE" = "change-this-jwt-secret-in-production" ]; then
  echo "[doctor] warning: JWT_SECRET is unset or using the insecure compose fallback"
elif [ "${#JWT_SECRET_VALUE}" -lt 32 ]; then
  echo "[doctor] warning: JWT_SECRET is shorter than 32 characters"
fi

echo "[doctor] container status"
docker compose ps

echo "[doctor] nginx syntax test"
docker exec safeline-waf-nginx sh -lc "openresty -t -p /usr/local/openresty/nginx/ -c conf/nginx.conf"

echo "[doctor] redis auth test"
docker exec \
  -e REDIS_PASSWORD="${REDIS_PASSWORD:-}" \
  safeline-waf-redis \
  sh -lc 'if [ -n "$REDIS_PASSWORD" ]; then redis-cli -a "$REDIS_PASSWORD" ping; else redis-cli ping; fi'

echo "[doctor] backend-triggered hot reload"
docker exec safeline-waf-admin-backend sh -lc "curl -sS http://nginx:80/_reload"

echo "[doctor] listening ports inside nginx container"
docker exec safeline-waf-nginx sh -lc "ss -lntp | grep -E ':80|:443' || true"

echo "[doctor] done"
