local _M = {}

local cjson = require "cjson"
local bit = require "bit"
local utils = require "utils"

local config_dict = ngx.shared.safeline_config
local bloom_dict = ngx.shared.safeline_bloom

local _cached_cfg_version = nil
local _cached_cfg = nil

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

local function get_config()
    local version = tonumber(config_dict:get("config_version") or 0) or 0
    if _cached_cfg_version == version and _cached_cfg then
        return _cached_cfg
    end

    _cached_cfg_version = version

    local raw = config_dict:get("blacklist_bloom") or "{}"
    local cfg = safe_decode_table(raw, {})

    cfg.enabled = cfg.enabled == true
    cfg.bits = tonumber(cfg.bits or 4194304) or 4194304
    cfg.hashes = tonumber(cfg.hashes or 7) or 7
    cfg.refresh_interval = tonumber(cfg.refresh_interval or 30) or 30
    cfg.scan_count = tonumber(cfg.scan_count or 1000) or 1000

    if cfg.bits < 1024 then
        cfg.bits = 1024
    end
    if cfg.hashes < 2 then
        cfg.hashes = 2
    end
    if cfg.refresh_interval < 5 then
        cfg.refresh_interval = 5
    end
    if cfg.scan_count < 10 then
        cfg.scan_count = 10
    end

    _cached_cfg = cfg
    return cfg
end

local function bloom_test(bits_str, m_bits, k_hashes, item)
    if type(bits_str) ~= "string" or bits_str == "" then
        return nil
    end
    if type(item) ~= "string" or item == "" then
        return nil
    end

    local m = tonumber(m_bits) or 0
    local k = tonumber(k_hashes) or 0
    if m <= 0 or k <= 0 then
        return nil
    end

    local h1 = ngx.crc32_short(item)
    local h2 = ngx.crc32_short("safeline_bf\0" .. item)
    if h2 == 0 then
        h2 = 1
    end

    for i = 0, k - 1 do
        local idx = (h1 + i * h2) % m
        local byte_pos = bit.rshift(idx, 3) + 1 -- Lua string is 1-based
        local mask = bit.lshift(1, bit.band(idx, 7))
        local b = string.byte(bits_str, byte_pos)
        if not b then
            return nil
        end
        if bit.band(b, mask) == 0 then
            return false
        end
    end

    return true
end

local _local_version = nil
local _local_bits = nil
local _local_m = nil
local _local_k = nil

local function load_local_snapshot()
    local version = tonumber(bloom_dict:get("blacklist_bloom_version") or 0) or 0
    if _local_version == version and _local_bits ~= nil then
        return
    end

    _local_version = version
    _local_bits = bloom_dict:get("blacklist_bloom_bits")
    _local_m = tonumber(bloom_dict:get("blacklist_bloom_m") or 0) or 0
    _local_k = tonumber(bloom_dict:get("blacklist_bloom_k") or 0) or 0
end

-- 返回：
--   true  => 可能在黑名单（需要进一步查Redis或共享dict确认）
--   false => 一定不在黑名单（可跳过Redis）
--   nil   => Bloom 不可用（回退到原逻辑）
function _M.maybe_contains(ip)
    local cfg = get_config()
    if not cfg.enabled then
        return nil
    end

    if type(ip) ~= "string" or ip == "" then
        return nil
    end

    load_local_snapshot()
    if type(_local_bits) ~= "string" or _local_bits == "" or _local_m <= 0 or _local_k <= 0 then
        return nil
    end

    return bloom_test(_local_bits, _local_m, _local_k, ip)
end

local function rebuild_from_redis(cfg)
    local ok_ffi, ffi = pcall(require, "ffi")
    if not ok_ffi then
        return nil, "LuaJIT FFI is required for bloom rebuild"
    end

    local m = tonumber(cfg.bits) or 0
    local k = tonumber(cfg.hashes) or 0
    if m <= 0 or k <= 0 then
        return nil, "invalid bloom config"
    end

    local byte_len = math.floor((m + 7) / 8)
    local buf = ffi.new("uint8_t[?]", byte_len)

    local function bloom_add(item)
        if type(item) ~= "string" or item == "" then
            return
        end

        local h1 = ngx.crc32_short(item)
        local h2 = ngx.crc32_short("safeline_bf\0" .. item)
        if h2 == 0 then
            h2 = 1
        end

        for i = 0, k - 1 do
            local idx = (h1 + i * h2) % m
            local byte_index = bit.rshift(idx, 3)
            local mask = bit.lshift(1, bit.band(idx, 7))
            buf[byte_index] = bit.bor(buf[byte_index], mask)
        end
    end

    local red = utils.get_redis(2000)
    if not red then
        return nil, "failed to connect redis"
    end

    local cursor = "0"
    local key_prefix = "safeline:blacklist:"
    local pattern = key_prefix .. "*"
    local total = 0
    local scan_count = tonumber(cfg.scan_count) or 1000

    repeat
        local res, err = red:scan(cursor, "MATCH", pattern, "COUNT", scan_count)
        if not res then
            utils.release_redis(red)
            return nil, "redis scan failed: " .. tostring(err)
        end

        cursor = tostring(res[1] or "0")
        local keys = res[2]
        if type(keys) == "table" then
            for _, key in ipairs(keys) do
                if type(key) == "string" and key:sub(1, #key_prefix) == key_prefix then
                    local ip = key:sub(#key_prefix + 1)
                    if ip ~= "" then
                        bloom_add(ip)
                        total = total + 1
                    end
                end
            end
        end
    until cursor == "0"

    utils.release_redis(red)

    local bits_str = ffi.string(buf, byte_len)
    return bits_str, nil, total, byte_len
end

local function do_rebuild(premature)
    if premature then
        return
    end

    local cfg = get_config()
    if not cfg.enabled then
        return
    end

    if ngx.worker.id() ~= 0 then
        return
    end

    local started = ngx.now()
    local bits_str, err, total, byte_len = rebuild_from_redis(cfg)
    if not bits_str then
        ngx.log(ngx.ERR, "Blacklist bloom rebuild failed: ", tostring(err))
        return
    end

    bloom_dict:set("blacklist_bloom_bits", bits_str)
    bloom_dict:set("blacklist_bloom_m", cfg.bits)
    bloom_dict:set("blacklist_bloom_k", cfg.hashes)
    bloom_dict:set("blacklist_bloom_updated_at", ngx.time())
    bloom_dict:set("blacklist_bloom_entry_count", tonumber(total or 0) or 0)
    bloom_dict:set("blacklist_bloom_byte_len", tonumber(byte_len or 0) or 0)
    bloom_dict:incr("blacklist_bloom_version", 1, 0)

    ngx.log(ngx.INFO, "Blacklist bloom rebuilt in ", string.format("%.3f", ngx.now() - started),
        "s, entries=", tostring(total or 0), ", bytes=", tostring(byte_len or 0))
end

function _M.start()
    local cfg = get_config()
    if not cfg.enabled then
        return true
    end

    -- 仅 worker 0 执行重建，避免多worker同时scan Redis
    if ngx.worker.id() ~= 0 then
        return true
    end

    local ok, err = ngx.timer.at(0, do_rebuild)
    if not ok then
        return nil, "failed to start bloom rebuild timer: " .. tostring(err)
    end

    local every = ngx.timer.every
    if type(every) == "function" then
        local ok_every, err_every = every(cfg.refresh_interval, do_rebuild)
        if not ok_every then
            return nil, "failed to start bloom periodic timer: " .. tostring(err_every)
        end
        return true
    end

    -- 兼容不支持 ngx.timer.every 的版本：用递归 at 实现
    local function loop(premature)
        if premature then
            return
        end
        do_rebuild(false)
        local ok_next, err_next = ngx.timer.at(cfg.refresh_interval, loop)
        if not ok_next then
            ngx.log(ngx.ERR, "Failed to schedule next bloom rebuild: ", err_next)
        end
    end

    local ok_loop, err_loop = ngx.timer.at(cfg.refresh_interval, loop)
    if not ok_loop then
        return nil, "failed to start bloom loop timer: " .. tostring(err_loop)
    end

    return true
end

return _M
