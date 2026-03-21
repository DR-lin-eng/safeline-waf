-- LLM Traffic Auditor (Lua side)
-- Queues suspicious requests for async LLM risk assessment.
-- NEVER blocks the request path – all Redis writes use fire-and-forget pattern.
local _M = {}

local cjson      = require "cjson"
local utils      = require "utils"

local cache_dict  = ngx.shared.safeline_cache
local config_dict = ngx.shared.safeline_config
local CONFIG_REFRESH_TTL = 5

local function refresh_settings_async()
    local now = ngx.time()
    local loaded_at = tonumber(cache_dict:get("llm:settings:loaded_at") or 0) or 0
    if (now - loaded_at) < CONFIG_REFRESH_TTL then
        return
    end

    local locked, lock_err = cache_dict:add("llm:settings:refresh_lock", true, 1)
    if not locked and lock_err ~= "exists" then
        return
    end
    if not locked then
        return
    end

    ngx.timer.at(0, function(premature)
        if premature then
            cache_dict:delete("llm:settings:refresh_lock")
            return
        end

        local red = utils.get_redis(100)
        if not red then
            cache_dict:delete("llm:settings:refresh_lock")
            return
        end

        local ok = pcall(function()
            local enabled_raw = red:get("llm:enabled")
            if enabled_raw ~= ngx.null and enabled_raw ~= nil then
                cache_dict:set("llm:enabled", enabled_raw == "true" and "true" or "false", CONFIG_REFRESH_TTL * 2)
            end

            local cfg_raw = red:get("llm:config")
            if cfg_raw ~= ngx.null and type(cfg_raw) == "string" and cfg_raw ~= "" then
                local ok_cfg, cfg = pcall(cjson.decode, cfg_raw)
                if ok_cfg and type(cfg) == "table" then
                    if cfg.queue_max ~= nil then
                        cache_dict:set("llm:queue_max", tonumber(cfg.queue_max) or 2000, CONFIG_REFRESH_TTL * 2)
                    end
                    if cfg.rate_window ~= nil then
                        cache_dict:set("llm:rate_window", tonumber(cfg.rate_window) or 300, CONFIG_REFRESH_TTL * 2)
                    end
                    if cfg.rate_max ~= nil then
                        cache_dict:set("llm:rate_max", tonumber(cfg.rate_max) or 3, CONFIG_REFRESH_TTL * 2)
                    end
                end
            end

            cache_dict:set("llm:settings:loaded_at", now, CONFIG_REFRESH_TTL * 2)
        end)

        if not ok then
            ngx.log(ngx.WARN, "[LLM] Failed to refresh runtime settings")
        end

        utils.release_redis(red)
        cache_dict:delete("llm:settings:refresh_lock")
    end)
end

-- ── Config helpers ────────────────────────────────────────────────────────

local function llm_enabled()
    refresh_settings_async()

    local v = cache_dict:get("llm:enabled")
    if v ~= nil then return v == "true" or v == true end
    v = config_dict:get("llm:enabled")
    if v ~= nil then return v == "true" or v == true end
    return os.getenv("LLM_ENABLED") == "true"
end

local function queue_max_size()
    refresh_settings_async()
    return tonumber(cache_dict:get("llm:queue_max") or config_dict:get("llm:queue_max") or "2000") or 2000
end

local function rate_limit_window()
    refresh_settings_async()
    -- Max entries queued per IP per window (to contain LLM API cost)
    return tonumber(cache_dict:get("llm:rate_window") or config_dict:get("llm:rate_window") or "300") or 300  -- 5 minutes
end

local function rate_limit_max()
    refresh_settings_async()
    return tonumber(cache_dict:get("llm:rate_max") or config_dict:get("llm:rate_max") or "3") or 3
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
    local verdict_key = "llm:verdict:" .. client_ip
    local negative_key = verdict_key .. ":miss"
    local raw = cache_dict:get(verdict_key)
    if not raw and not cache_dict:get(negative_key) then
        local red = utils.get_redis(50)
        if red then
            red:init_pipeline()
            red:get(verdict_key)
            red:ttl(verdict_key)

            local res = red:commit_pipeline()
            utils.release_redis(red)

            if type(res) == "table" then
                local remote_raw = res[1]
                local remote_ttl = tonumber(res[2]) or 0
                if remote_raw and remote_raw ~= ngx.null and type(remote_raw) == "string" and remote_raw ~= "" then
                    cache_dict:set(verdict_key, remote_raw, math.max(1, math.min(remote_ttl > 0 and remote_ttl or 10, 30)))
                    cache_dict:delete(negative_key)
                    raw = remote_raw
                else
                    cache_dict:set(negative_key, true, 5)
                end
            end
        end
    end

    if not raw then return nil end
    local ok, v = pcall(cjson.decode, raw)
    return ok and v or nil
end

local function is_non_page_path(uri)
    if type(uri) ~= "string" or uri == "" then
        return false
    end

    return uri:match("^/api/")
        or uri:match("^/assets/")
        or uri == "/favicon.ico"
        or uri == "/manifest.json"
        or uri == "/site.webmanifest"
        or uri:match("^/apple%-touch%-icon")
        or uri:match("^/[a-z]+%-extension:")
        or uri:match("%.css$")
        or uri:match("%.js$")
        or uri:match("%.mjs$")
        or uri:match("%.map$")
        or uri:match("%.png$")
        or uri:match("%.jpg$")
        or uri:match("%.jpeg$")
        or uri:match("%.gif$")
        or uri:match("%.svg$")
        or uri:match("%.ico$")
        or uri:match("%.webp$")
        or uri:match("%.avif$")
        or uri:match("%.woff2?$")
        or uri:match("%.ttf$")
        or uri:match("%.otf$")
end

-- ── Queue request for LLM review ─────────────────────────────────────────

-- trigger_reason: human-readable string that explains why this was flagged
-- ml_score: 0-1 ML confidence (optional)
-- body_preview: truncated request body (optional, max 500 chars)
function _M.queue_for_review(client_ip, uri, method, headers, body_preview, trigger_reason, ml_score, metadata)
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
        metadata       = type(metadata) == "table" and metadata or nil,
        queued_at      = ngx.time(),
    }

    local ok_e, encoded = pcall(cjson.encode, entry)
    if not ok_e then
        return false, "encode_error"
    end

    -- Non-blocking Redis push via ngx.timer.at(0)
    local queue_key = "llm:audit:queue"
    local max_size  = queue_max_size()

    local scheduled, schedule_err = ngx.timer.at(0, function(premature)
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

    if not scheduled then
        ngx.log(ngx.WARN, "[LLM] Failed to schedule queue push: ", tostring(schedule_err))
        return false, "schedule_failed"
    end

    return true, "queued"
end

-- ── Apply cached verdict to current request ───────────────────────────────
-- Call this in access phase BEFORE expensive checks.
-- Returns: action string or nil
--   "ban"       → block with 403
--   "challenge" → trigger CAPTCHA/POW
--   "log"       → allow but log
--   nil         → no verdict, continue normally
function _M.apply_verdict(client_ip, host, uri)
    local v = _M.get_cached_verdict(client_ip)
    if not v then return nil end

    local request_host = type(host) == "string" and host:lower() or ""
    local verdict_host = type(v.host) == "string" and v.host:lower() or ""
    if verdict_host ~= "" and request_host ~= "" and verdict_host ~= request_host then
        return nil
    end

    if is_non_page_path(v.uri) then
        return "log"
    end

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
