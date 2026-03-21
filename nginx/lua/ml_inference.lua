-- ML Inference Engine for SafeLine WAF
-- Pure Lua Logistic Regression with Redis model storage and hot reload
local _M = {}

local cjson = require "cjson"
local utils = require "utils"

-- Shared dicts
local cache_dict  = ngx.shared.safeline_cache
local config_dict = ngx.shared.safeline_config
local ml_dict     = ngx.shared.safeline_ml
local limit_dict  = ngx.shared.safeline_limit

-- ─── Per-worker model cache ───────────────────────────────────────────────
local _model = {
    loaded      = false,
    version     = nil,
    weights     = nil,   -- float array
    intercept   = 0,
    threshold   = 0.5,
    feature_names = nil,
    scaler_mean = nil,
    scaler_std  = nil,
}

-- ─── Helpers ──────────────────────────────────────────────────────────────
local function sigmoid(x)
    if x >= 0 then
        return 1 / (1 + math.exp(-x))
    else
        local ex = math.exp(x)
        return ex / (1 + ex)
    end
end

local function safe_number(v, default)
    local n = tonumber(v)
    if n == nil or n ~= n then   -- NaN guard
        return default or 0
    end
    return n
end

local function count_char(s, ch)
    local n = 0
    for _ in s:gmatch(ch) do n = n + 1 end
    return n
end

local function entropy(counts, total)
    if total == 0 then return 0 end
    local h = 0
    for _, c in pairs(counts) do
        if c > 0 then
            local p = c / total
            h = h - p * math.log(p)
        end
    end
    return h
end

-- ─── Feature Extraction (30 features) ────────────────────────────────────
-- Returns a 30-element numeric array ready for inference.
function _M.extract_features(client_ip, uri, method, args, headers)
    local normalized_headers = {}
    if type(headers) == "table" then
        for key, value in pairs(headers) do
            if type(key) == "string" then
                normalized_headers[string.lower(key)] = value
            end
        end
    end
    headers = normalized_headers

    local f = {}

    -- 1  param_count
    local param_count = 0
    if args then for _ in pairs(args) do param_count = param_count + 1 end end
    f[1] = param_count

    -- 2  request_rate_60s  (reuse existing limit key)
    local rate_key = "req_rate:" .. client_ip
    local req60 = tonumber(limit_dict:get(rate_key) or ml_dict:get(rate_key) or cache_dict:get(rate_key) or 0) or 0
    f[2] = req60

    -- 3  request_rate_5s
    local rate5_key = "req_rate5:" .. client_ip
    local req5 = tonumber(limit_dict:get(rate5_key) or ml_dict:get(rate5_key) or cache_dict:get(rate5_key) or 0) or 0
    f[3] = req5

    -- 4  path_depth
    f[4] = count_char(uri, "/")

    -- 5  uri_length
    f[5] = #uri

    -- 6  uri_special_chars
    local spec = 0
    for _ in uri:gmatch("[^%w/%-_%.%%]") do spec = spec + 1 end
    f[6] = spec

    -- 7  uri_entropy  (character distribution entropy)
    local uc = {}
    for i = 1, #uri do
        local ch = uri:sub(i, i)
        uc[ch] = (uc[ch] or 0) + 1
    end
    f[7] = entropy(uc, #uri)

    -- 8–10  method flags
    f[8]  = method == "GET"  and 1 or 0
    f[9]  = method == "POST" and 1 or 0
    f[10] = (method ~= "GET" and method ~= "POST") and 1 or 0

    -- 11  header_count
    local hcount = 0
    for _ in pairs(headers) do hcount = hcount + 1 end
    f[11] = hcount

    -- 12  missing_standard_headers  (Accept, Accept-Language, Accept-Encoding, User-Agent)
    local missing = 0
    local std_hdrs = {"accept", "accept-language", "accept-encoding", "user-agent"}
    for _, h in ipairs(std_hdrs) do
        if not headers[h] then missing = missing + 1 end
    end
    f[12] = missing

    -- 13  has_referer
    f[13] = headers["referer"] and 1 or 0

    -- 14  ua_length
    local ua = headers["user-agent"] or ""
    f[14] = #ua

    -- 15  ua_has_mozilla
    f[15] = ua:find("Mozilla", 1, true) and 1 or 0

    -- 16  ua_has_bot
    f[16] = (ua:lower():find("bot", 1, true) or ua:lower():find("crawler", 1, true)) and 1 or 0

    -- 17  ua_entropy
    local uac = {}
    for i = 1, #ua do local ch = ua:sub(i,i); uac[ch] = (uac[ch] or 0) + 1 end
    f[17] = entropy(uac, #ua)

    -- 18  body_size_log
    local clen = safe_number(headers["content-length"], 0)
    f[18] = math.log10(clen + 1)

    -- 19  content_type_present
    f[19] = (headers["content-type"] and headers["content-type"] ~= "") and 1 or 0

    -- 20  has_json_content_type
    local ct = headers["content-type"] or ""
    f[20] = ct:find("application/json", 1, true) and 1 or 0

    -- 21  is_https
    f[21] = (ngx.var.scheme == "https") and 1 or 0

    -- 22  sni_matches_host (TLS SNI)
    local sni  = ngx.var.ssl_server_name or ""
    local host = headers["host"] or ngx.var.host or ""
    f[22] = (sni ~= "" and host:find(sni, 1, true)) and 1 or 0

    -- 23  session_age (seconds since first seen)
    local first_key = "ml:fseen:" .. client_ip
    local first_seen = tonumber(ml_dict:get(first_key) or 0) or 0
    if first_seen == 0 then
        first_seen = ngx.now()
        ml_dict:set(first_key, first_seen, 3600)
    end
    f[23] = math.min(ngx.now() - first_seen, 86400)

    -- 24  interval_mean  (mean of last 10 request intervals)
    local ikey = "ml:intervals:" .. client_ip
    local ij = ml_dict:get(ikey) or "[]"
    local ok_i, intervals = pcall(cjson.decode, ij)
    if not ok_i then intervals = {} end
    local last_t_key = "ml:last_t:" .. client_ip
    local last_t = tonumber(ml_dict:get(last_t_key) or 0) or 0
    local now = ngx.now()
    if last_t > 0 then
        local iv = now - last_t
        table.insert(intervals, iv)
        if #intervals > 10 then table.remove(intervals, 1) end
        ml_dict:set(ikey, cjson.encode(intervals), 300)
    end
    ml_dict:set(last_t_key, now, 300)
    local imean = 0
    if #intervals > 0 then
        local s = 0
        for _, v in ipairs(intervals) do s = s + v end
        imean = s / #intervals
    end
    f[24] = imean

    -- 25  interval_cv  (coefficient of variation, proxy for regularity)
    local istddev = 0
    if #intervals > 1 then
        local sq = 0
        for _, v in ipairs(intervals) do sq = sq + (v - imean)^2 end
        istddev = math.sqrt(sq / #intervals)
    end
    f[25] = (imean > 0) and (istddev / imean) or 0

    -- 26  unique_paths_ratio  (last 20 paths)
    local pkey = "ml:paths:" .. client_ip
    local pj = ml_dict:get(pkey) or "[]"
    local ok_p, paths = pcall(cjson.decode, pj)
    if not ok_p then paths = {} end
    table.insert(paths, uri)
    if #paths > 20 then table.remove(paths, 1) end
    ml_dict:set(pkey, cjson.encode(paths), 300)
    local uniq = {}
    for _, v in ipairs(paths) do uniq[v] = true end
    local uc2 = 0; for _ in pairs(uniq) do uc2 = uc2 + 1 end
    f[26] = (#paths > 0) and (uc2 / #paths) or 0

    -- 27  honeypot_hits
    local hh = tonumber(cache_dict:get("ml:honeypot:" .. client_ip) or ml_dict:get("ml:honeypot:" .. client_ip) or 0) or 0
    f[27] = hh

    -- 28  has_sql_keywords  (quick check)
    local uri_lower = uri:lower()
    local sql_kw = uri_lower:find("select", 1, true) or uri_lower:find("union", 1, true)
                   or uri_lower:find("insert", 1, true) or uri_lower:find("drop", 1, true)
    f[28] = sql_kw and 1 or 0

    -- 29  has_xss_patterns
    local xss = uri_lower:find("<script", 1, true) or uri_lower:find("javascript:", 1, true)
                or uri_lower:find("onerror=", 1, true)
    f[29] = xss and 1 or 0

    -- 30  has_path_traversal
    local pt = uri:find("../", 1, true) or uri:find("..\\", 1, true)
    f[30] = pt and 1 or 0

    return f
end

-- ─── Model Loading ────────────────────────────────────────────────────────
function _M.load_model()
    local red = utils.get_redis(500)
    if not red then
        ngx.log(ngx.WARN, "[ML] Cannot connect to Redis for model load")
        return false, "redis_unavailable"
    end

    -- Get active version
    local version, err = red:get("ml:model:active")
    if not version or version == ngx.null then
        utils.release_redis(red)
        -- No model deployed yet – this is fine, WAF continues without ML
        return false, "no_active_model"
    end

    -- Check if already on this version
    if _model.loaded and _model.version == version then
        utils.release_redis(red)
        return true, "already_current"
    end

    local weights_json, werr = red:get("ml:model:" .. version .. ":weights")
    utils.release_redis(red)

    if not weights_json or weights_json == ngx.null then
        ngx.log(ngx.ERR, "[ML] Model weights missing for version: ", version)
        return false, "weights_missing"
    end

    local ok, data = pcall(cjson.decode, weights_json)
    if not ok or type(data) ~= "table" then
        ngx.log(ngx.ERR, "[ML] Failed to decode model weights: ", tostring(data))
        return false, "decode_error"
    end

    -- Validate required fields
    if type(data.weights) ~= "table" or #data.weights == 0 then
        ngx.log(ngx.ERR, "[ML] Invalid model structure: missing weights array")
        return false, "invalid_structure"
    end

    _model.loaded       = true
    _model.version      = version
    _model.weights      = data.weights
    _model.intercept    = safe_number(data.intercept, 0)
    _model.threshold    = safe_number(data.threshold, 0.5)
    _model.feature_names = data.feature_names or {}
    _model.scaler_mean  = data.scaler_mean or {}
    _model.scaler_std   = data.scaler_std  or {}

    -- Persist active version in config dict for cross-worker visibility
    config_dict:set("ml:active_version", version)

    ngx.log(ngx.NOTICE, "[ML] Model loaded: ", version,
            " weights=", #_model.weights,
            " threshold=", _model.threshold)
    return true, version
end

-- ─── Inference ───────────────────────────────────────────────────────────
-- Returns is_attack (bool|nil), confidence (float), reason (string)
-- Returns nil, nil, reason if model not available (caller should fall through)
function _M.predict(feature_vec)
    if not _model.loaded then
        -- Try lazy load
        local ok = _M.load_model()
        if not ok then
            return nil, nil, "model_not_loaded"
        end
    end

    local w  = _model.weights
    local n  = math.min(#feature_vec, #w)
    if n == 0 then
        return nil, nil, "empty_features"
    end

    -- Z-score normalise then dot product
    local logit = _model.intercept
    for i = 1, n do
        local x = feature_vec[i]
        local mean  = _model.scaler_mean[i] or 0
        local std   = _model.scaler_std[i]  or 1
        if std < 1e-9 then std = 1 end
        local xn = (x - mean) / std
        logit = logit + w[i] * xn
    end

    local prob = sigmoid(logit)
    local is_attack = prob >= _model.threshold
    return is_attack, prob, (is_attack and "ml_attack" or "ml_benign")
end

-- ─── Cached Predict ───────────────────────────────────────────────────────
function _M.predict_with_cache(client_ip, fingerprint, feature_vec)
    -- Canary gate: only run ML for configured percentage of IPs
    local canary_pct = tonumber(ml_dict:get("ml:canary_pct") or config_dict:get("ml:canary_pct") or "100") or 100
    if canary_pct < 100 then
        local ip_hash = 0
        for i = 1, #client_ip do
            ip_hash = (ip_hash * 31 + client_ip:byte(i)) % 100
        end
        if ip_hash >= canary_pct then
            return nil, nil, "canary_skip"
        end
    end

    local cache_key = "ml:pred:" .. client_ip .. ":" .. (fingerprint or "")
    local cached = ml_dict:get(cache_key)
    if cached then
        local ok_c, cv = pcall(cjson.decode, cached)
        if ok_c and type(cv) == "table" then
            return cv.attack, cv.prob, "cached"
        end
    end

    local is_attack, prob, reason = _M.predict(feature_vec)
    if is_attack ~= nil then
        local cv = cjson.encode({ attack = is_attack, prob = prob or 0 })
        ml_dict:set(cache_key, cv, 60)
    end
    return is_attack, prob, reason
end

-- ─── Training Data Collection ─────────────────────────────────────────────
function _M.collect_training_sample(client_ip, feature_vec, label, reason)
    -- 100% attack samples, 1% benign
    if label == "benign" then
        if math.random() > 0.01 then return end
    end

    local date_str = os.date("%Y-%m-%d")
    local sample = {
        ts      = ngx.now(),
        ip_hash = ngx.md5(client_ip),
        features = feature_vec,
        label   = label,
        reason  = reason,
        version = _model.version or "unknown",
    }

    local ok_e, encoded = pcall(cjson.encode, sample)
    if not ok_e then
        return
    end

    ngx.timer.at(0, function(premature)
        if premature then
            return
        end

        local red = utils.get_redis(200)
        if not red then
            return
        end

        local ok = pcall(function()
            local rkey = "ml:samples:" .. date_str .. ":" .. label
            red:lpush(rkey, encoded)
            red:ltrim(rkey, 0, 49999)     -- Keep last 50k samples per label per day
            red:expire(rkey, 7 * 86400)   -- 7-day TTL
        end)

        if not ok then
            ngx.log(ngx.WARN, "[ML] Failed to enqueue training sample")
        end

        utils.release_redis(red)
    end)
end

-- ─── Pub/Sub Hot Reload ───────────────────────────────────────────────────
-- Blocking loop – must run inside ngx.timer.at(0, ...)
function _M.subscribe_model_reload()
    local redis_lib = require "resty.redis"
    local settings = {
        host     = os.getenv("REDIS_HOST") or "redis",
        port     = tonumber(os.getenv("REDIS_PORT") or "6379") or 6379,
        password = os.getenv("REDIS_PASSWORD"),
    }

    while true do
        local red = redis_lib:new()
        red:set_timeout(30000)  -- 30s read timeout for blocking subscribe
        local reconnect_delay = 1

        local ok, err = red:connect(settings.host, settings.port)
        if not ok then
            ngx.log(ngx.WARN, "[ML] Pub/Sub connect failed: ", err, " – retry in 5s")
            reconnect_delay = 5
        else
            if settings.password and settings.password ~= "" then
                local auth_ok, auth_err = red:auth(settings.password)
                if not auth_ok then
                    ngx.log(ngx.ERR, "[ML] Pub/Sub auth failed: ", auth_err)
                    red:close()
                    reconnect_delay = 5
                end
            end

            if reconnect_delay == 1 then
                local sub_ok, sub_err = red:subscribe("ml:model:reload")
                if not sub_ok then
                    ngx.log(ngx.ERR, "[ML] Subscribe failed: ", sub_err)
                    red:close()
                    reconnect_delay = 5
                else
                    ngx.log(ngx.NOTICE, "[ML] Pub/Sub subscriber ready on ml:model:reload")

                    while true do
                        local res, rerr = red:read_reply()
                        if not res then
                            if rerr ~= "timeout" then
                                ngx.log(ngx.WARN, "[ML] Pub/Sub read error: ", rerr, " – reconnecting")
                                break
                            end
                            -- timeout is fine – just a keepalive gap
                        else
                            if type(res) == "table" and res[1] == "message" then
                                local ok_l, lerr = pcall(_M.load_model)
                                if not ok_l then
                                    ngx.log(ngx.ERR, "[ML] Hot reload failed: ", lerr)
                                else
                                    ngx.log(ngx.NOTICE, "[ML] Model hot-reloaded via Pub/Sub")
                                end
                            end
                        end
                        ngx.sleep(0.05)
                    end

                    red:close()
                end
            end
        end

        ngx.sleep(reconnect_delay)
    end
end

-- ─── Utility: active version ──────────────────────────────────────────────
function _M.active_version()
    return _model.version
end

function _M.is_loaded()
    return _model.loaded
end

return _M
