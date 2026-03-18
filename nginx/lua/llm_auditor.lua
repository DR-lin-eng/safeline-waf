-- LLM Traffic Auditor (Lua side)
-- Queues suspicious requests for async LLM risk assessment.
-- NEVER blocks the request path – all Redis writes use fire-and-forget pattern.
local _M = {}

local cjson      = require "cjson"
local utils      = require "utils"

local cache_dict  = ngx.shared.safeline_cache
local config_dict = ngx.shared.safeline_config

-- ── Config helpers ────────────────────────────────────────────────────────

local function llm_enabled()
    -- Fast path: check shared dict first (populated by config_loader)
    local v = config_dict:get("llm:enabled")
    if v ~= nil then return v == "true" or v == true end
    return os.getenv("LLM_ENABLED") == "true"
end

local function queue_max_size()
    return tonumber(config_dict:get("llm:queue_max") or "2000") or 2000
end

local function rate_limit_window()
    -- Max entries queued per IP per window (to contain LLM API cost)
    return tonumber(config_dict:get("llm:rate_window") or "300") or 300  -- 5 minutes
end

local function rate_limit_max()
    return tonumber(config_dict:get("llm:rate_max") or "3") or 3
end

-- ── Per-IP rate limiting ───────────────────────────────────────────────────

local function check_and_incr_rate(client_ip)
    local key = "llm:rl:" .. client_ip
    local count = cache_dict:get(key) or 0
    if count >= rate_limit_max() then
        return false   -- already queued enough for this IP
    end
    cache_dict:set(key, (count + 1), rate_limit_window())
    return true
end

-- ── Cached verdict check ──────────────────────────────────────────────────
-- Nginx workers can check for a pending LLM verdict before passing traffic.
-- The Node.js worker writes  llm:verdict:{ip} = JSON  with TTL after analysis.

function _M.get_cached_verdict(client_ip)
    local raw = cache_dict:get("llm:verdict:" .. client_ip)
    if not raw then return nil end
    local ok, v = pcall(cjson.decode, raw)
    return ok and v or nil
end

-- ── Queue request for LLM review ─────────────────────────────────────────

-- trigger_reason: human-readable string that explains why this was flagged
-- ml_score: 0-1 ML confidence (optional)
-- body_preview: truncated request body (optional, max 500 chars)
function _M.queue_for_review(client_ip, uri, method, headers, body_preview, trigger_reason, ml_score)
    if not llm_enabled() then return false, "llm_disabled" end

    -- Rate-limit per IP
    if not check_and_incr_rate(client_ip) then
        return false, "rate_limited"
    end

    local ua      = (headers and headers["user-agent"]) or ""
    local referer = (headers and headers["referer"])    or ""
    local host    = (headers and headers["host"])       or (ngx.var and ngx.var.host) or ""

    -- Truncate for Redis payload size / LLM token budget
    uri = (uri or ""):sub(1, 512)
    ua  = ua:sub(1, 256)
    if type(body_preview) == "string" then
        body_preview = body_preview:sub(1, 500)
    else
        body_preview = ""
    end

    local entry = {
        ip             = client_ip,
        host           = host,
        method         = method or "GET",
        uri            = uri,
        ua             = ua,
        referer        = referer,
        body_preview   = body_preview,
        trigger_reason = trigger_reason or "suspicious_traffic",
        ml_score       = ml_score or 0,
        queued_at      = ngx.time(),
    }

    local ok_e, encoded = pcall(cjson.encode, entry)
    if not ok_e then
        return false, "encode_error"
    end

    -- Non-blocking Redis push via ngx.timer.at(0)
    local queue_key = "llm:audit:queue"
    local max_size  = queue_max_size()

    ngx.timer.at(0, function(premature)
        if premature then return end
        local red = utils.get_redis(200)
        if not red then return end
        local ok_push = pcall(function()
            -- Only push if queue is not over max to avoid unbounded growth
            local qlen = red:llen(queue_key)
            if type(qlen) == "number" and qlen < max_size then
                red:lpush(queue_key, encoded)
            end
        end)
        if not ok_push then
            ngx.log(ngx.WARN, "[LLM] Queue push failed")
        end
        utils.release_redis(red)
    end)

    return true, "queued"
end

-- ── Apply cached verdict to current request ───────────────────────────────
-- Call this in access phase BEFORE expensive checks.
-- Returns: action string or nil
--   "ban"       → block with 403
--   "challenge" → trigger CAPTCHA/POW
--   "log"       → allow but log
--   nil         → no verdict, continue normally
function _M.apply_verdict(client_ip)
    local v = _M.get_cached_verdict(client_ip)
    if not v then return nil end

    -- Only act on high-confidence verdicts
    local confidence = tonumber(v.confidence) or 0
    if confidence < 0.6 then return "log" end

    local action = v.action or "log"
    if action == "ban_permanent" or action == "ban_24h" or action == "ban_1h" then
        return "ban"
    elseif action == "challenge" then
        return "challenge"
    end
    return "log"
end

return _M
