local _M = {}

local cjson = require "cjson"

local config_dict = ngx.shared.safeline_config

local function safe_decode_table(json, fallback)
    if type(json) ~= "string" or json == "" then
        return fallback
    end

    local ok, data = pcall(cjson.decode, json)
    if ok and type(data) == "table" then
        return data
    end

    return fallback
end

local function save_table_config(key, tbl)
    if type(tbl) ~= "table" then
        return false
    end

    local ok, encoded = pcall(cjson.encode, tbl)
    if not ok then
        return false
    end

    config_dict:set(key, encoded)
    return true
end

function _M.apply_on_init()
    local adaptive = safe_decode_table(config_dict:get("adaptive_protection") or "{}", {})
    if adaptive.enabled == false then
        return false, "adaptive protection disabled"
    end

    local worker_count = tonumber(ngx.worker.count() or 0) or 0
    if worker_count < 1 then
        worker_count = 1
    end

    local ddos = safe_decode_table(config_dict:get("ddos_protection") or "{}", {})
    local base_url_threshold = tonumber(ddos.url_threshold or 60) or 60
    local base_ip_threshold = tonumber(ddos.ip_threshold or 300) or 300
    local base_global_threshold = tonumber(ddos.global_threshold or 3000) or 3000
    local base_global_hard_threshold = tonumber(ddos.global_hard_threshold or 8000) or 8000

    local scaled = {}
    local soft_core_ratio = 0.6
    scaled.url_threshold = math.max(30, math.floor(base_url_threshold * (1 + (worker_count - 1) * soft_core_ratio)))
    scaled.ip_threshold = math.max(120, math.floor(base_ip_threshold * (1 + (worker_count - 1) * soft_core_ratio)))
    scaled.global_threshold = math.max(500, base_global_threshold * worker_count)
    scaled.global_hard_threshold = math.max(1000, base_global_hard_threshold * worker_count)

    config_dict:set("runtime:worker_count", worker_count)
    config_dict:set("runtime:adaptive_enabled", true)
    config_dict:set("runtime:adaptive_ts", ngx.time())
    config_dict:set("runtime:worker_connections_target", math.floor((tonumber(adaptive.worker_connections_per_core or 8192) or 8192) * worker_count))
    config_dict:set("runtime:worker_rlimit_nofile_target", math.floor((tonumber(adaptive.worker_rlimit_nofile_per_core or 65535) or 65535) * worker_count))
    config_dict:set("runtime:shared_dict_scale", tonumber(adaptive.shared_dict_scale_per_core or 1.0) or 1.0)

    config_dict:set("runtime:ddos_url_threshold", scaled.url_threshold)
    config_dict:set("runtime:ddos_ip_threshold", scaled.ip_threshold)
    config_dict:set("runtime:ddos_global_threshold", scaled.global_threshold)
    config_dict:set("runtime:ddos_global_hard_threshold", scaled.global_hard_threshold)

    ddos.url_threshold = scaled.url_threshold
    ddos.ip_threshold = scaled.ip_threshold
    ddos.global_threshold = scaled.global_threshold
    ddos.global_hard_threshold = scaled.global_hard_threshold

    save_table_config("ddos_protection", ddos)

    -- bump config_version so per-worker local caches can refresh
    local previous_version = tonumber(config_dict:get("config_version") or 0) or 0
    config_dict:set("config_version", previous_version + 1)

    return true, scaled
end

return _M

