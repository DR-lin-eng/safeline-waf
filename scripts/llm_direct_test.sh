#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"

API_ENDPOINT="${API_ENDPOINT:-https://code.linzefeng.top/responses}"
API_KEY="${API_KEY:-}"
MODEL="${MODEL:-gpt-5.4}"
TIMEOUT_MS="${TIMEOUT_MS:-30000}"

if [ -z "$API_KEY" ]; then
  echo "[llm-direct-test] API_KEY is required"
  exit 1
fi

API_ENDPOINT="$API_ENDPOINT" API_KEY="$API_KEY" MODEL="$MODEL" TIMEOUT_MS="$TIMEOUT_MS" node - <<'NODE'
const { callLLMDirect, parseVerdictDirect } = require('./admin/backend/llm_worker');

(async () => {
  const cfg = {
    provider: 'openai_responses',
    api_endpoint: process.env.API_ENDPOINT,
    model: process.env.MODEL,
    api_key: process.env.API_KEY,
    timeout_ms: Number(process.env.TIMEOUT_MS || 30000)
  };

  const testEntry = {
    ip: '1.2.3.4',
    host: 'test.example.com',
    method: 'GET',
    uri: '/test?id=1+OR+1=1--',
    ua: 'curl/7.0',
    referer: '',
    body_preview: '',
    trigger_reason: 'connectivity_test',
    ml_score: 0.8,
  };

  try {
    const text = await callLLMDirect(cfg, testEntry);
    console.log('[llm-direct-test] raw response:');
    console.log(text);
    console.log('[llm-direct-test] parsed verdict:');
    console.log(JSON.stringify(parseVerdictDirect(text), null, 2));
  } catch (error) {
    console.error('[llm-direct-test] error:', error.message);
    process.exit(1);
  }
})();
NODE
