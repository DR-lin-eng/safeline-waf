local _M = {}

local cjson = require "cjson"

local config_dict = ngx.shared.safeline_config
local blacklist_dict = ngx.shared.safeline_blacklist

local function decode_json(content)
    local ok, data = pcall(cjson.decode, content)
    if not ok then
        return nil, "failed to parse json: " .. tostring(data)
    end

    return data
end

local function safe_decode_table(content, fallback)
    if type(content) ~= "string" or content == "" then
        return fallback
    end

    local ok, data = pcall(cjson.decode, content)
    if ok and type(data) == "table" then
        return data
    end

    return fallback
end

local function read_file(path)
    local file, err = io.open(path, "rb")
    if not file then
        return nil, "failed to open file: " .. tostring(err)
    end

    local content = file:read("*a")
    file:close()

    if not content or content == "" then
        return nil, "empty file"
    end

    return content
end

local function read_json(path)
    local content, err = read_file(path)
    if not content then
        return nil, err
    end

    local data, decode_err = decode_json(content)
    if not data then
        return nil, decode_err
    end

    return data, nil, content
end

local function is_safe_domain(domain)
    if type(domain) ~= "string" or domain == "" then
        return false
    end
    if #domain > 255 then
        return false
    end
    return domain:match("^[%w%.%-]+$") ~= nil
end

local function normalize_ip_range_entry(entry)
    if type(entry) == "string" then
        local value = entry:match("^%s*(.-)%s*$")
        if value ~= "" then
            return value:lower()
        end
        return nil
    end

    if type(entry) ~= "table" then
        return nil
    end

    local cidr = entry.cidr or entry.entry
    if type(cidr) == "string" and cidr ~= "" then
        return { cidr = cidr:match("^%s*(.-)%s*$"):lower() }
    end

    local start_num = tonumber(entry.start_num or entry.start)
    local end_num = tonumber(entry.end_num or entry.finish or entry["end"])
    local start_ip = type(entry.start_ip) == "string" and entry.start_ip or nil
    local end_ip = type(entry.end_ip) == "string" and entry.end_ip or nil

    if start_num and end_num then
        if start_num > end_num then
            start_num, end_num = end_num, start_num
            start_ip, end_ip = end_ip, start_ip
        end

        return {
            start = start_num,
            end_num = end_num,
            start_ip = start_ip,
            end_ip = end_ip
        }
    end

    return nil
end

local function ip_range_identity(entry)
    if type(entry) == "string" then
        return "cidr:" .. entry
    end

    if type(entry) ~= "table" then
        return nil
    end

    if type(entry.cidr) == "string" and entry.cidr ~= "" then
        return "cidr:" .. entry.cidr
    end

    local start_num = tonumber(entry.start_num or entry.start)
    local end_num = tonumber(entry.end_num or entry.finish or entry["end"])
    if start_num and end_num then
        return "range:" .. tostring(start_num) .. "-" .. tostring(end_num)
    end

    return nil
end

local function merge_ip_ranges(...)
    local merged = {}
    local seen = {}

    for i = 1, select("#", ...) do
        local entries = select(i, ...)
        if type(entries) == "table" then
            for _, entry in ipairs(entries) do
                local normalized = normalize_ip_range_entry(entry)
                local identity = ip_range_identity(normalized)
                if normalized and identity and not seen[identity] then
                    seen[identity] = true
                    merged[#merged + 1] = normalized
                end
            end
        end
    end

    return merged
end

function _M.load_default_config(opts)
    opts = opts or {}

    -- 读取当前配置版本（用于触发各worker内的配置缓存失效）
    -- 注意：reset_shared_state 会 flush shared dict，因此必须在 flush 之前读取
    local previous_version = tonumber(config_dict:get("config_version") or 0) or 0

    local config_path = ngx.config.prefix() .. "conf/config/default_config.json"
    local previous_signature = config_dict:get("default_config_signature")
    local config, err, raw_content = read_json(config_path)
    if not config then
        ngx.log(ngx.ERR, "Failed to load default config: ", config_path, " (", err, ")")
        return nil, err
    end
    local signature = ngx.md5(raw_content)
    local preserved_ip_ranges = {}

    if opts.reset_shared_state then
        -- 保留运行时生成的token_secret，避免reload后正在验证的用户全部失效
        local token_secret = config_dict:get("token_secret")
        local dynamic_ip_ranges = safe_decode_table(config_dict:get("ip_ranges") or "[]", {})
        preserved_ip_ranges = dynamic_ip_ranges

        -- 保留动态黑名单条目（TTL > 0 表示管理后台/自动封禁写入的临时条目）
        -- 静态配置条目是永久的(TTL == 0)，会在下面重新加载
        local dynamic_entries = {}
        local bl_keys = blacklist_dict:get_keys(0)
        for _, bl_key in ipairs(bl_keys) do
            local bl_ttl = blacklist_dict:ttl(bl_key)
            if bl_ttl and bl_ttl > 0 then
                dynamic_entries[bl_key] = bl_ttl
            end
        end

        config_dict:flush_all()
        config_dict:flush_expired()
        blacklist_dict:flush_all()
        blacklist_dict:flush_expired()

        if type(token_secret) == "string" and token_secret ~= "" then
            config_dict:set("token_secret", token_secret)
        end

        if #dynamic_ip_ranges > 0 then
            config_dict:set("ip_ranges", cjson.encode(dynamic_ip_ranges))
        end

        -- 恢复动态黑名单条目
        for ip, remaining_ttl in pairs(dynamic_entries) do
            if remaining_ttl > 1 then
                blacklist_dict:set(ip, true, remaining_ttl)
            end
        end
    end

    for key, value in pairs(config) do
        if type(value) == "table" then
            config_dict:set(key, cjson.encode(value))
        else
            config_dict:set(key, value)
        end
    end

    local configured_ip_ranges = type(config.ip_ranges) == "table" and config.ip_ranges or {}
    local cidr_entries = {}

    if config.ip_blacklist and type(config.ip_blacklist) == "table" then
        for _, ip in ipairs(config.ip_blacklist) do
            if type(ip) == "string" and ip ~= "" then
                if ip:find("/", 1, true) then
                    cidr_entries[#cidr_entries + 1] = ip
                else
                    blacklist_dict:set(ip, true)
                end
            end
        end
    end

    local merged_ip_ranges = merge_ip_ranges(configured_ip_ranges, preserved_ip_ranges, cidr_entries)
    config_dict:set("ip_ranges", cjson.encode(merged_ip_ranges))

    config_dict:set("default_config_signature", signature)
    config_dict:set("default_config_loaded_at", ngx.time())
    config_dict:set("config_version", previous_version + 1)

    return config, nil, {
        default_config_signature = signature,
        default_config_changed = previous_signature ~= signature,
        config_version = previous_version + 1
    }
end

function _M.load_site_config(domain)
    if type(domain) ~= "string" then
        return nil, "invalid domain"
    end

    domain = domain:lower()

    if not is_safe_domain(domain) then
        return nil, "invalid domain"
    end

    local site_path = ngx.config.prefix() .. "conf/config/sites/" .. domain .. ".json"
    local site, err, raw_content = read_json(site_path)
    if not site then
        return nil, err
    end

    config_dict:set("site:" .. domain, cjson.encode(site))
    config_dict:set("site_signature:" .. domain, ngx.md5(raw_content))
    return site
end

function _M.get_site_config(domain)
    if type(domain) ~= "string" then
        return nil
    end

    domain = domain:lower()

    if not is_safe_domain(domain) then
        return nil
    end

    local cached = config_dict:get("site:" .. domain)
    if cached then
        local ok, decoded = pcall(cjson.decode, cached)
        if ok and type(decoded) == "table" then
            return decoded
        end

        config_dict:delete("site:" .. domain)
    end

    local site = _M.load_site_config(domain)
    if not site then
        return nil
    end

    return site
end

function _M.reload()
    local config, err, detail = _M.load_default_config({ reset_shared_state = true })
    if not config then
        return false, err
    end
    return true, nil, detail
end

-- Subscribe to Redis Pub/Sub for cluster config reload
function _M.subscribe_cluster_reload()
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

    local res, err = red:subscribe("cluster:config:reload")
    if not res then
        ngx.log(ngx.ERR, "[Cluster] Failed to subscribe to cluster:config:reload: ", err)
        return
    end

    ngx.log(ngx.NOTICE, "[Cluster] Subscribed to cluster:config:reload channel")

    -- Listen for messages in a loop
    while true do
        local msg, err = red:read_reply()
        if not msg then
            if err ~= "timeout" then
                ngx.log(ngx.ERR, "[Cluster] Pub/Sub read error: ", err)
                break
            end
        else
            if type(msg) == "table" and msg[1] == "message" then
                ngx.log(ngx.NOTICE, "[Cluster] Received config reload signal: ", msg[3])

                -- Trigger config reload
                local success, reload_err = _M.reload()
                if success then
                    ngx.log(ngx.NOTICE, "[Cluster] Config reloaded successfully")
                else
                    ngx.log(ngx.ERR, "[Cluster] Config reload failed: ", reload_err)
                end
            end
        end

        ngx.sleep(0.1)
    end

    red:close()
end

return _M
