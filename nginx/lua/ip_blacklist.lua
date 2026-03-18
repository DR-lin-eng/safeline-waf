local _M = {}

-- 引入模块
local cjson = require "cjson"
local utils = require "utils"

-- 共享内存
local blacklist_dict = ngx.shared.safeline_blacklist
local config_dict = ngx.shared.safeline_config
local unpack = table.unpack or unpack

local ok_lrucache, lrucache = pcall(require, "resty.lrucache")
local _lru = nil
local _lru_size = nil

local ok_bloom, blacklist_bloom = pcall(require, "blacklist_bloom")
if not ok_bloom then
    blacklist_bloom = nil
end

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

local _cached_cfg_version = nil
local _cached_cache_cfg = nil
local _cached_ranges_raw = nil
local _cached_ranges = nil

local function get_cache_cfg()
    local version = tonumber(config_dict:get("config_version") or 0) or 0
    if _cached_cfg_version == version and _cached_cache_cfg then
        return _cached_cache_cfg
    end

    _cached_cfg_version = version

    local raw = config_dict:get("blacklist_cache") or "{}"
    local cfg = safe_decode_table(raw, {})

    cfg.lru_enabled = cfg.lru_enabled ~= false
    cfg.lru_size = tonumber(cfg.lru_size or 50000) or 50000
    cfg.negative_ttl = tonumber(cfg.negative_ttl or 5) or 5
    cfg.positive_default_ttl = tonumber(cfg.positive_default_ttl or 300) or 300
    cfg.redis_timeout_ms = tonumber(cfg.redis_timeout_ms or 120) or 120

    if cfg.lru_size < 1000 then
        cfg.lru_size = 1000
    end
    if cfg.lru_size > 200000 then
        cfg.lru_size = 200000
    end

    if cfg.negative_ttl < 1 then
        cfg.negative_ttl = 1
    end
    if cfg.negative_ttl > 60 then
        cfg.negative_ttl = 60
    end

    if cfg.positive_default_ttl < 30 then
        cfg.positive_default_ttl = 30
    end
    if cfg.positive_default_ttl > 86400 then
        cfg.positive_default_ttl = 86400
    end

    if cfg.redis_timeout_ms < 50 then
        cfg.redis_timeout_ms = 50
    end
    if cfg.redis_timeout_ms > 2000 then
        cfg.redis_timeout_ms = 2000
    end

    _cached_cache_cfg = cfg
    return cfg
end

local function get_lru(cache_cfg)
    if not ok_lrucache or not cache_cfg.lru_enabled then
        return nil
    end

    if _lru and _lru_size == cache_cfg.lru_size then
        return _lru
    end

    local new_lru, err = lrucache.new(cache_cfg.lru_size)
    if not new_lru then
        ngx.log(ngx.ERR, "Failed to create lrucache: ", err)
        return nil
    end

    _lru = new_lru
    _lru_size = cache_cfg.lru_size
    return _lru
end

local function invalidate_range_cache()
    _cached_ranges_raw = nil
    _cached_ranges = nil
end

local function bump_config_version()
    config_dict:incr("config_version", 1, 0)
end

local function parse_range_entry(entry)
    if type(entry) == "string" then
        local cidr = entry:match("^%s*(.-)%s*$")
        if cidr and cidr ~= "" then
            local parsed = utils.parse_cidr(cidr)
            if parsed then
                return {
                    type = "cidr",
                    entry = cidr:lower(),
                    cidr = cidr:lower(),
                    parsed = parsed,
                    identity = "cidr:" .. cidr:lower()
                }
            end
        end
        return nil
    end

    if type(entry) ~= "table" then
        return nil
    end

    local cidr = entry.cidr or entry.entry
    if type(cidr) == "string" and cidr ~= "" then
        local normalized = cidr:match("^%s*(.-)%s*$")
        local parsed = utils.parse_cidr(normalized)
        if parsed then
            return {
                type = "cidr",
                entry = normalized:lower(),
                cidr = normalized:lower(),
                parsed = parsed,
                identity = "cidr:" .. normalized:lower()
            }
        end
    end

    local start_num = tonumber(entry.start_num or entry.start)
    local end_num = tonumber(entry.end_num or entry.finish or entry["end"])
    local start_ip = entry.start_ip
    local end_ip = entry.end_ip

    if (not start_num) and type(start_ip) == "string" then
        start_num = utils.ip_to_number(start_ip)
    end
    if (not end_num) and type(end_ip) == "string" then
        end_num = utils.ip_to_number(end_ip)
    end

    if start_num and end_num then
        if start_num > end_num then
            start_num, end_num = end_num, start_num
            start_ip, end_ip = end_ip, start_ip
        end

        return {
            type = "range",
            start = start_num,
            finish = end_num,
            start_ip = start_ip or _M.number_to_ip(start_num),
            end_ip = end_ip or _M.number_to_ip(end_num),
            identity = "range:" .. tostring(start_num) .. "-" .. tostring(end_num)
        }
    end

    return nil
end

local function get_ip_ranges()
    local raw = config_dict:get("ip_ranges") or "[]"
    if _cached_ranges_raw == raw and _cached_ranges then
        return _cached_ranges
    end

    local decoded = safe_decode_table(raw, {})
    local parsed = {}
    for _, entry in ipairs(decoded) do
        local range = parse_range_entry(entry)
        if range then
            parsed[#parsed + 1] = range
        end
    end

    _cached_ranges_raw = raw
    _cached_ranges = parsed
    return parsed
end

local function get_raw_ip_ranges()
    return safe_decode_table(config_dict:get("ip_ranges") or "[]", {})
end

local function store_ip_ranges(entries)
    local ok = config_dict:set("ip_ranges", cjson.encode(entries))
    if ok then
        invalidate_range_cache()
        bump_config_version()
    end
    return ok
end

local function clear_redis_blacklist()
    local red = utils.get_redis()
    if not red then
        return false
    end

    local cursor = "0"
    local pattern = "safeline:blacklist:*"
    repeat
        local res, err = red:scan(cursor, "MATCH", pattern, "COUNT", 500)
        if not res then
            ngx.log(ngx.ERR, "Failed to scan Redis blacklist keys: ", tostring(err))
            utils.release_redis(red)
            return false
        end

        cursor = tostring(res[1] or "0")
        local keys = res[2]
        if type(keys) == "table" and #keys > 0 then
            local del_ok, del_err = red:del(unpack(keys))
            if not del_ok then
                ngx.log(ngx.ERR, "Failed to delete Redis blacklist keys: ", tostring(del_err))
                utils.release_redis(red)
                return false
            end
        end
    until cursor == "0"

    utils.release_redis(red)
    return true
end

-- 检查IP是否在黑名单中
function _M.is_blacklisted(ip)
    if not ip or type(ip) ~= "string" or ip == "" then
        return false
    end

    local cache_cfg = get_cache_cfg()
    local lru = get_lru(cache_cfg)

    if lru then
        local cached = lru:get(ip)
        if cached ~= nil then
            return cached == true
        end
    end

    -- 直接查找IP
    if blacklist_dict:get(ip) then
        if lru then
            lru:set(ip, true, cache_cfg.positive_default_ttl)
        end
        return true
    end

    local ip_num = _M.ip_to_number(ip)
    for _, range in ipairs(get_ip_ranges()) do
        local matched = false
        if range.type == "range" and ip_num then
            matched = ip_num >= range.start and ip_num <= range.finish
        elseif range.type == "cidr" then
            matched = utils.ip_matches_cidr(ip, range.parsed)
        end

        if matched then
            if lru then
                lru:set(ip, true, cache_cfg.positive_default_ttl)
            end
            return true
        end
    end

    -- Bloom：如果明确“不在黑名单”，可直接跳过Redis（默认关闭，避免控制面延迟导致漏拦）
    if blacklist_bloom and blacklist_bloom.maybe_contains then
        local maybe = blacklist_bloom.maybe_contains(ip)
        if maybe == false then
            if lru then
                lru:set(ip, false, cache_cfg.negative_ttl)
            end
            return false
        end
    end

    -- 检查Redis黑名单（管理后台写入）
    local red = utils.get_redis(cache_cfg.redis_timeout_ms)
    if red then
        local key = "safeline:blacklist:" .. ip
        red:init_pipeline()
        red:get(key)
        red:ttl(key)

        local res, err = red:commit_pipeline()
        if not res then
            ngx.log(ngx.ERR, "Failed to query blacklist from Redis: ", err)
            utils.release_redis(red)
            return false
        end

        local value = res[1]
        local ttl = tonumber(res[2]) or -2

        if value and value ~= ngx.null then
            local cache_ttl = cache_cfg.positive_default_ttl
            if ttl and ttl > 0 then
                cache_ttl = ttl
            end

            blacklist_dict:set(ip, true, cache_ttl)
            if lru then
                lru:set(ip, true, cache_ttl)
            end

            utils.release_redis(red)
            return true
        end

        if lru then
            lru:set(ip, false, cache_cfg.negative_ttl)
        end

        utils.release_redis(red)
    end
    
    return false
end

-- 添加IP到黑名单
function _M.add_to_blacklist(ip, expiry)
    if not ip or type(ip) ~= "string" or ip == "" then
        return false
    end

    if ip:find("/", 1, true) then
        return _M.add_range_to_blacklist(ip)
    end

    expiry = tonumber(expiry or 86400) or 86400 -- 默认1天
    if expiry > 0 and expiry < 60 then
        expiry = 60
    end

    local ok
    if expiry <= 0 or expiry == -1 then
        ok = blacklist_dict:set(ip, true)
    else
        ok = blacklist_dict:set(ip, true, expiry)
    end

    local red = utils.get_redis()
    if red then
        local key = "safeline:blacklist:" .. ip
        if expiry <= 0 or expiry == -1 then
            red:set(key, 1)
        else
            red:setex(key, expiry, 1)
        end
        utils.release_redis(red)
    end

    local cache_cfg = get_cache_cfg()
    local lru = get_lru(cache_cfg)
    if lru then
        local ttl = expiry
        if ttl == -1 or ttl == 0 then
            ttl = cache_cfg.positive_default_ttl
        end
        lru:set(ip, true, ttl)
    end

    return ok
end

-- 从黑名单中移除IP
function _M.remove_from_blacklist(ip)
    if type(ip) == "string" and ip:find("/", 1, true) then
        return _M.remove_range_from_blacklist(ip)
    end

    local ok = blacklist_dict:delete(ip)

    local red = utils.get_redis()
    if red then
        red:del("safeline:blacklist:" .. ip)
        utils.release_redis(red)
    end

    local cache_cfg = get_cache_cfg()
    local lru = get_lru(cache_cfg)
    if lru then
        lru:delete(ip)
    end

    return ok
end

-- 添加IP范围到黑名单
function _M.add_range_to_blacklist(start_ip, end_ip)
    local ranges = get_raw_ip_ranges()

    if type(start_ip) == "string" and start_ip:find("/", 1, true) and (end_ip == nil or end_ip == "") then
        local cidr = start_ip:match("^%s*(.-)%s*$")
        local parsed = parse_range_entry(cidr)
        if not parsed then
            return false, "Invalid CIDR entry"
        end

        for _, existing in ipairs(ranges) do
            local existing_range = parse_range_entry(existing)
            if existing_range and existing_range.identity == parsed.identity then
                return true
            end
        end

        table.insert(ranges, parsed.cidr)
        return store_ip_ranges(ranges)
    end

    local start_num = _M.ip_to_number(start_ip)
    local end_num = _M.ip_to_number(end_ip)
    if not start_num or not end_num then
        return false, "Invalid IP address"
    end

    if start_num > end_num then
        start_num, end_num = end_num, start_num
        start_ip, end_ip = end_ip, start_ip
    end

    local candidate = parse_range_entry({
        start = start_num,
        end_num = end_num,
        start_ip = start_ip,
        end_ip = end_ip
    })

    for _, existing in ipairs(ranges) do
        local existing_range = parse_range_entry(existing)
        if existing_range and candidate and existing_range.identity == candidate.identity then
            return true
        end
    end

    table.insert(ranges, {
        start = start_num,
        end_num = end_num,
        start_ip = start_ip,
        end_ip = end_ip
    })

    return store_ip_ranges(ranges)
end

function _M.remove_range_from_blacklist(entry_value)
    local target = parse_range_entry(entry_value)
    if not target then
        return false, "Invalid blacklist range"
    end

    local ranges = get_raw_ip_ranges()
    local updated = {}
    local removed = false

    for _, existing in ipairs(ranges) do
        local parsed = parse_range_entry(existing)
        if parsed and parsed.identity == target.identity then
            removed = true
        else
            updated[#updated + 1] = existing
        end
    end

    if not removed then
        return false, "Blacklist range not found"
    end

    return store_ip_ranges(updated)
end

-- 将IP地址转换为数字
function _M.ip_to_number(ip)
    -- 确保IP格式正确
    if not ip or type(ip) ~= "string" or ip == "" then
        return nil
    end
    
    local parts = {}
    for part in ip:gmatch("%d+") do
        table.insert(parts, tonumber(part))
    end
    
    if #parts ~= 4 then
        return nil
    end

    for i = 1, 4 do
        if not parts[i] or parts[i] < 0 or parts[i] > 255 then
            return nil
        end
    end
    
    -- 计算IP数值
    return (parts[1] * 16777216) + (parts[2] * 65536) + (parts[3] * 256) + parts[4]
end

-- 从数字转换回IP地址
function _M.number_to_ip(num)
    if not num or type(num) ~= "number" then
        return nil
    end
    
    local a = math.floor(num / 16777216) % 256
    local b = math.floor(num / 65536) % 256
    local c = math.floor(num / 256) % 256
    local d = math.floor(num) % 256
    
    return string.format("%d.%d.%d.%d", a, b, c, d)
end

-- 获取当前黑名单列表
function _M.get_blacklist()
    local keys = blacklist_dict:get_keys(0)
    local result = {}

    for _, key in ipairs(keys) do
        local ttl = blacklist_dict:ttl(key)
        -- ttl == 0: permanent entry (no expiry), ttl > 0: has remaining TTL
        -- nil means key no longer exists (race condition) — skip it
        if ttl ~= nil then
            table.insert(result, {
                ip = key,
                expires_in = (ttl > 0) and ttl or -1  -- -1 signals permanent
            })
        end
    end
    
    for _, range in ipairs(get_ip_ranges()) do
        if range.type == "cidr" then
            table.insert(result, {
                entry = range.cidr,
                cidr = range.cidr,
                type = "cidr",
                range = true,
                expires_in = -1,
                permanent = true
            })
        elseif range.type == "range" then
            table.insert(result, {
                entry = string.format("%s-%s", range.start_ip, range.end_ip),
                start_ip = range.start_ip,
                end_ip = range.end_ip,
                type = "range",
                range = true,
                expires_in = -1,
                permanent = true
            })
        end
    end
    
    return result
end

-- 清空全部黑名单
function _M.clear_blacklist()
    -- 清空单个IP黑名单
    blacklist_dict:flush_all()
    blacklist_dict:flush_expired()

    local cache_cfg = get_cache_cfg()
    local lru = get_lru(cache_cfg)
    if lru and lru.flush_all then
        lru:flush_all()
    end

    -- 清空IP范围黑名单
    store_ip_ranges({})
    local redis_cleared = clear_redis_blacklist()

    return redis_cleared ~= false
end

-- Sync blacklist from Redis cluster
function _M.sync_from_cluster()
    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeouts(1000, 1000, 1000)

    local redis_host = os.getenv("REDIS_HOST") or "redis"
    local redis_port = tonumber(os.getenv("REDIS_PORT") or "6379")
    local redis_password = os.getenv("REDIS_PASSWORD")

    local ok, err = red:connect(redis_host, redis_port)
    if not ok then
        ngx.log(ngx.ERR, "[Cluster] Failed to connect to Redis for blacklist sync: ", err)
        return false, err
    end

    if redis_password and redis_password ~= "" then
        local res, err = red:auth(redis_password)
        if not res then
            ngx.log(ngx.ERR, "[Cluster] Redis auth failed: ", err)
            return false, err
        end
    end

    -- Fetch centralized blacklist from Redis
    local entries, err = red:smembers("cluster:blacklist:permanent")
    if not entries then
        ngx.log(ngx.ERR, "[Cluster] Failed to fetch blacklist: ", err)
        red:close()
        return false, err
    end

    -- Update local shared dict
    local synced = 0
    for _, ip in ipairs(entries) do
        if type(ip) == "string" and ip ~= "" then
            blacklist_dict:set(ip, true, 0) -- 0 = permanent
            synced = synced + 1
        end
    end

    red:close()
    ngx.log(ngx.NOTICE, "[Cluster] Synced ", synced, " blacklist entries from cluster")
    return true, synced
end

-- Subscribe to blacklist sync events
function _M.subscribe_cluster_blacklist()
    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeouts(1000, 1000, 1000)

    local redis_host = os.getenv("REDIS_HOST") or "redis"
    local redis_port = tonumber(os.getenv("REDIS_PORT") or "6379")
    local redis_password = os.getenv("REDIS_PASSWORD")

    local ok, err = red:connect(redis_host, redis_port)
    if not ok then
        ngx.log(ngx.ERR, "[Cluster] Failed to connect to Redis for Pub/Sub: ", err)
        return
    end

    if redis_password and redis_password ~= "" then
        local res, err = red:auth(redis_password)
        if not res then
            ngx.log(ngx.ERR, "[Cluster] Redis auth failed: ", err)
            return
        end
    end

    local res, err = red:subscribe("cluster:blacklist:sync")
    if not res then
        ngx.log(ngx.ERR, "[Cluster] Failed to subscribe to cluster:blacklist:sync: ", err)
        return
    end

    ngx.log(ngx.NOTICE, "[Cluster] Subscribed to cluster:blacklist:sync channel")

    -- Listen for messages
    while true do
        local msg, err = red:read_reply()
        if not msg then
            if err ~= "timeout" then
                ngx.log(ngx.ERR, "[Cluster] Pub/Sub read error: ", err)
                break
            end
        else
            if type(msg) == "table" and msg[1] == "message" then
                local ok, payload = pcall(cjson.decode, msg[3])
                if ok and type(payload) == "table" then
                    ngx.log(ngx.NOTICE, "[Cluster] Received blacklist sync: ", payload.action)

                    if payload.action == "sync" and type(payload.entries) == "table" then
                        -- Full sync
                        for _, ip in ipairs(payload.entries) do
                            if type(ip) == "string" and ip ~= "" then
                                blacklist_dict:set(ip, true, 0)
                            end
                        end
                    end
                end
            end
        end

        ngx.sleep(0.1)
    end

    red:close()
end

return _M
