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

compose() {
  if [ -n "${COMPOSE_FILE:-}" ] && [ -n "${COMPOSE_ENV_FILE:-}" ]; then
    docker compose -f "$COMPOSE_FILE" --env-file "$COMPOSE_ENV_FILE" "$@"
  elif [ -n "${COMPOSE_FILE:-}" ]; then
    docker compose -f "$COMPOSE_FILE" "$@"
  elif [ -n "${COMPOSE_ENV_FILE:-}" ]; then
    docker compose --env-file "$COMPOSE_ENV_FILE" "$@"
  else
    docker compose "$@"
  fi
}

echo "[doctor] checking compose syntax"
compose config >/dev/null

echo "[doctor] checking JWT secret configuration"
JWT_SECRET_VALUE="${JWT_SECRET:-}"
if [ -z "$JWT_SECRET_VALUE" ] || [ "$JWT_SECRET_VALUE" = "change-this-jwt-secret-in-production" ]; then
  echo "[doctor] warning: JWT_SECRET is unset or using the insecure compose fallback"
elif [ "${#JWT_SECRET_VALUE}" -lt 32 ]; then
  echo "[doctor] warning: JWT_SECRET is shorter than 32 characters"
fi

echo "[doctor] container status"
compose ps

echo "[doctor] nginx syntax test"
docker exec safeline-waf-nginx sh -lc "/usr/local/openresty/bin/openresty -t -p /usr/local/openresty/nginx/ -c conf/nginx.conf"

echo "[doctor] redis auth test"
docker exec \
  -e REDIS_PASSWORD="${REDIS_PASSWORD:-}" \
  safeline-waf-redis \
  sh -lc 'if [ -n "$REDIS_PASSWORD" ]; then redis-cli -a "$REDIS_PASSWORD" ping; else redis-cli ping; fi'

echo "[doctor] backend-triggered hot reload"
docker exec \
  -e JWT_SECRET="${JWT_SECRET:-}" \
  safeline-waf-admin-backend \
  node -e "const http=require('http');const token=process.env.JWT_SECRET||'';if(!token){console.log('[doctor] warning: JWT_SECRET is empty, skipping authenticated reload check');process.exit(0);}const req=http.get('http://nginx:80/_reload',{headers:{'X-Reload-Token':token}},res=>{let body='';res.setEncoding('utf8');res.on('data',chunk=>body+=chunk);res.on('end',()=>{process.stdout.write(body);if(body&&!body.endsWith('\n'))process.stdout.write('\n');process.exit(res.statusCode>=200&&res.statusCode<300?0:1);});});req.on('error',err=>{console.error(err.message);process.exit(1);});"

echo "[doctor] listening ports inside nginx container"
docker exec safeline-waf-nginx sh -lc "ss -lntp | grep -E ':80|:443' || true"

echo "[doctor] done"
