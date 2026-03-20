local _M = {}

-- 引入模块
local cjson = require "cjson"
local redis = require "resty.redis"
local bit = require "bit"

-- 共享内存
local cache_dict = ngx.shared.safeline_cache
local limit_dict = ngx.shared.safeline_limit
local counters_dict = ngx.shared.safeline_counters
local config_dict = ngx.shared.safeline_config

local _random_seeded = false
local function ensure_random_seeded()
    if _random_seeded then
        return
    end
    _random_seeded = true

    local pid = 0
    if ngx.worker and ngx.worker.pid then
        pid = ngx.worker.pid()
    end

    math.randomseed(ngx.now() * 1000 + pid)
    math.random()
    math.random()
    math.random()
end

ensure_random_seeded()

local function safe_incr(dict, key, value, init, ttl, fallback)
    local newval = dict:incr(key, value, init, ttl)
    if newval == nil then
        if fallback ~= nil then
            return fallback
        end
        return init or 0
    end
    return newval
end

local function base64url_encode(data)
    if data == nil then
        return nil
    end
    local b64 = ngx.encode_base64(data)
    return (b64:gsub("%+", "-"):gsub("/", "_"):gsub("=", ""))
end

local function base64url_decode(data)
    if type(data) ~= "string" or data == "" then
        return nil
    end

    local b64 = data:gsub("-", "+"):gsub("_", "/")
    local pad = #b64 % 4
    if pad == 2 then
        b64 = b64 .. "=="
    elseif pad == 3 then
        b64 = b64 .. "="
    elseif pad ~= 0 then
        return nil
    end

    return ngx.decode_base64(b64)
end

local function constant_time_equals(a, b)
    if type(a) ~= "string" or type(b) ~= "string" then
        return false
    end
    if #a ~= #b then
        return false
    end

    local diff = 0
    for i = 1, #a do
        diff = bit.bor(diff, bit.bxor(a:byte(i), b:byte(i)))
    end

    return diff == 0
end

local _cached_token_secret = nil
local _cached_redis_settings = nil
local function get_token_secret()
    if _cached_token_secret then
        return _cached_token_secret
    end

    local secret = config_dict:get("token_secret")
    if type(secret) == "string" and secret ~= "" then
        _cached_token_secret = secret
        return secret
    end

    local env_secret = os.getenv("SAFELINE_TOKEN_SECRET")
    if type(env_secret) == "string" and env_secret ~= "" then
        config_dict:set("token_secret", env_secret)
        _cached_token_secret = env_secret
        return env_secret
    end

    local generated = nil
    local ok_random, resty_random = pcall(require, "resty.random")
    local ok_string, resty_string = pcall(require, "resty.string")
    if ok_random and ok_string then
        local bytes = resty_random.bytes(32, true)
        if bytes then
            generated = resty_string.to_hex(bytes)
        end
    end

    generated = generated or ngx.md5(tostring(ngx.now()) .. ":" .. tostring(math.random()))
    config_dict:set("token_secret", generated)
    _cached_token_secret = generated
    return generated
end

local function get_redis_settings()
    if _cached_redis_settings then
        return _cached_redis_settings
    end

    local settings = {
        host = os.getenv("REDIS_HOST") or "redis",
        port = tonumber(os.getenv("REDIS_PORT") or "6379") or 6379,
        password = os.getenv("REDIS_PASSWORD"),
        database = tonumber(os.getenv("REDIS_DATABASE") or os.getenv("REDIS_DB") or "0") or 0,
        keepalive_idle_ms = tonumber(os.getenv("REDIS_KEEPALIVE_IDLE_MS") or "10000") or 10000,
        pool_size = tonumber(os.getenv("REDIS_POOL_SIZE") or "100") or 100,
        default_timeout_ms = tonumber(os.getenv("REDIS_TIMEOUT_MS") or "200") or 200
    }

    if settings.keepalive_idle_ms < 1000 then
        settings.keepalive_idle_ms = 1000
    end
    if settings.pool_size < 10 then
        settings.pool_size = 10
    end
    if settings.database < 0 then
        settings.database = 0
    end
    if settings.default_timeout_ms < 50 then
        settings.default_timeout_ms = 50
    end

    _cached_redis_settings = settings
    return settings
end

function _M.close_redis(red)
    if not red then
        return false
    end

    local ok, err = red:close()
    if not ok and err and err ~= "closed" then
        ngx.log(ngx.WARN, "Failed to close Redis connection: ", tostring(err))
        return false
    end

    return true
end

function _M.release_redis(red)
    if not red then
        return false
    end

    local settings = get_redis_settings()
    local ok, err = red:set_keepalive(settings.keepalive_idle_ms, settings.pool_size)
    if ok then
        return true
    end

    ngx.log(ngx.WARN, "Failed to set Redis keepalive: ", tostring(err))
    return _M.close_redis(red)
end

-- 连接Redis（支持密码认证）
function _M.get_redis(timeout_ms)
    local settings = get_redis_settings()
    local red = redis:new()
    red:set_timeout(timeout_ms or settings.default_timeout_ms)

    local ok, err = red:connect(settings.host, settings.port)
    if not ok then
        ngx.log(ngx.ERR, "Failed to connect to Redis: ", tostring(err))
        return nil
    end

    local reused_times = 0
    local ok_reused, reused_or_err = pcall(red.get_reused_times, red)
    if ok_reused and type(reused_or_err) == "number" then
        reused_times = reused_or_err
    end

    if reused_times == 0 then
        local password = settings.password
        if type(password) == "string" and password ~= "" then
            local auth_ok, auth_err = red:auth(password)
            if not auth_ok then
                ngx.log(ngx.ERR, "Failed to authenticate with Redis: ", tostring(auth_err))
                _M.close_redis(red)
                return nil
            end
        end

        if settings.database > 0 then
            local select_ok, select_err = red:select(settings.database)
            if not select_ok then
                ngx.log(ngx.ERR, "Failed to select Redis database: ", tostring(select_err))
                _M.close_redis(red)
                return nil
            end
        end
    end

    return red
end

-- 计算指数退避时间 (用于动态限速)
function _M.calc_exp_backoff(base, attempt, max)
    local time = base * math.pow(2, attempt)
    return math.min(time, max)
end

-- 检测自动化工具签名 (针对DDoS脚本)
function _M.detect_automation_signature(headers, uri, method, client_ip)
    local signs = {}
    
    -- 检查JA3指纹
    if headers["X-JA3-Fingerprint"] then
        table.insert(signs, "ja3_header")
    end
    
    -- 检查不常见的请求头组合
    if headers["Pragma"] and headers["Cache-Control"] and 
       headers["Accept-Encoding"] and headers["Accept-Language"] then
        -- 标准的请求头顺序和组合
        local normalized_headers = {}
        for k, _ in pairs(headers) do
            table.insert(normalized_headers, k)
        end
        table.sort(normalized_headers)
        
        -- 检查请求头是否过于一致
        local headers_key = "headers:" .. table.concat(normalized_headers, "|")
        local count = safe_incr(cache_dict, headers_key, 1, 0, 300, 0)
        if count > 10 then
            table.insert(signs, "consistent_headers")
        end
    end
    
    -- 检查请求速率和间隔
    if type(client_ip) ~= "string" or client_ip == "" then
        client_ip = ngx.var.remote_addr or "0.0.0.0"
    end
    local now = ngx.now()
    local last_req_key = "last_req:" .. client_ip
    local last_req_time = cache_dict:get(last_req_key)
    
    if last_req_time then
        local interval = now - tonumber(last_req_time)
        
        -- 存储最近的请求间隔
        local intervals_key = "intervals:" .. client_ip
        local intervals_json = cache_dict:get(intervals_key) or "[]"
        
        local success, intervals = pcall(cjson.decode, intervals_json)
        if not success then
            intervals = {}
        end
        
        table.insert(intervals, interval)
        if #intervals > 20 then
            table.remove(intervals, 1)
        end
        
        cache_dict:set(intervals_key, cjson.encode(intervals), 300)
        
        -- 分析请求间隔的规律性
        if #intervals >= 10 then
            local sum = 0
            local sq_sum = 0
            
            for _, v in ipairs(intervals) do
                sum = sum + v
                sq_sum = sq_sum + v * v
            end
            
            local mean = sum / #intervals
            local variance = (sq_sum / #intervals) - (mean * mean)
            local std_dev = math.sqrt(variance)
            
            -- 非人类用户的请求间隔往往有固定模式
            if std_dev < 0.2 and mean < 1.0 then
                table.insert(signs, "regular_intervals")
            end
            
            -- 请求频率过高
            if mean < 0.05 then  -- 平均间隔小于50毫秒
                table.insert(signs, "high_frequency")
            end
        end
    end
    
    cache_dict:set(last_req_key, now, 300)
    
    -- 检查HTTP方法分布的不自然
    local methods_key = "methods:" .. client_ip
    local methods_json = cache_dict:get(methods_key) or "{}"
    
    local success, methods = pcall(cjson.decode, methods_json)
    if not success then
        methods = {}
    end
    
    methods[method] = (methods[method] or 0) + 1
    cache_dict:set(methods_key, cjson.encode(methods), 300)
    
    -- 计算方法分布的熵
    local total = 0
    for _, count in pairs(methods) do
        total = total + count
    end
    
    if total > 20 then
        local entropy = 0
        for _, count in pairs(methods) do
            local p = count / total
            entropy = entropy - p * math.log(p)
        end
        
        -- 不自然的HTTP方法分布（太随机或太不随机）
        if entropy < 0.5 or entropy > 2.5 then
            table.insert(signs, "abnormal_method_distribution")
        end
    end
    
    -- 检查URL请求模式
    local url_key = "urls:" .. client_ip
    local urls_json = cache_dict:get(url_key) or "[]"
    
    local success, urls = pcall(cjson.decode, urls_json)
    if not success then
        urls = {}
    end
    
    -- 只保存最近20个URL
    table.insert(urls, 1, uri)
    if #urls > 20 then
        urls[21] = nil
    end
    
    cache_dict:set(url_key, cjson.encode(urls), 300)
    
    -- 检查URL的变化频率
    if #urls >= 10 then
        local unique_urls = {}
        for _, u in ipairs(urls) do
            unique_urls[u] = true
        end
        
        local unique_count = 0
        for _ in pairs(unique_urls) do
            unique_count = unique_count + 1
        end
        
        -- 如果10个连续请求中超过8个URL不同，可能是随机URL攻击
        if unique_count > 8 then
            table.insert(signs, "random_url_attack")
        end
    end
    
    -- 根据检测到的自动化迹象的数量决定置信度
    local confidence = 0
    if #signs > 0 then
        confidence = #signs / 8  -- 最多8个迹象，归一化到0-1
    end
    
    return confidence > 0.5, confidence, signs
end

-- 高级缓存函数，支持多级缓存
function _M.cached_data(cache_key, getter_func, ttl, use_redis)
    -- 先检查本地缓存
    local data = cache_dict:get(cache_key)
    if data then
        return data
    end
    
    -- 如果配置了使用Redis作为二级缓存
    if use_redis then
        local red = _M.get_redis()
        if red then
            local redis_data = red:get(cache_key)
            _M.release_redis(red)
            
            if redis_data and redis_data ~= ngx.null then
                -- 找到数据，放入本地缓存并返回
                cache_dict:set(cache_key, redis_data, ttl)
                return redis_data
            end
        end
    end
    
    -- 调用getter函数获取新数据
    local new_data = getter_func()
    
    -- 保存到本地缓存
    if new_data then
        cache_dict:set(cache_key, new_data, ttl)
        
        -- 如果配置了使用Redis，也保存到Redis
        if use_redis then
            local red = _M.get_redis()
            if red then
                red:setex(cache_key, ttl, new_data)
                _M.release_redis(red)
            end
        end
    end
    
    return new_data
end

-- 动态限速
function _M.dynamic_rate_limit(key, limit, window, increment)
    limit = tonumber(limit) or 0
    window = tonumber(window) or 0
    increment = tonumber(increment) or 1

    if window < 1 then
        window = 1
    end
    if limit < 1 then
        limit = 1
    end
    
    -- 获取当前计数
    local count = safe_incr(limit_dict, key, increment, 0, window, limit + 1)
    
    -- 获取当前限制
    local limit_key = key .. "_limit"
    local current_limit = tonumber(limit_dict:get(limit_key) or limit) or limit
    
    -- 检查是否超过限制
    if count > current_limit then
        -- 超过限制时，动态增加限制门槛
        local violations_key = key .. "_violations"
        local violations = safe_incr(limit_dict, violations_key, 1, 0, window * 5, 999)
        
        -- 根据违规次数动态调整限制
        local new_limit = math.max(1, limit - violations * 5)
        limit_dict:set(limit_key, new_limit, window * 5)
        
        return true, count, new_limit
    end
    
    return false, count, current_limit
end

-- 检测并记录异常请求
function _M.record_anomaly(client_ip, uri, reason, score)
    -- 添加异常记录
    local anomaly_key = "anomaly:" .. client_ip
    local anomalies_json = cache_dict:get(anomaly_key) or "[]"
    
    local success, anomalies = pcall(cjson.decode, anomalies_json)
    if not success then
        anomalies = {}
    end
    
    table.insert(anomalies, {
        time = ngx.time(),
        uri = uri,
        reason = reason,
        score = score
    })
    
    -- 只保留最近10条记录
    if #anomalies > 10 then
        table.remove(anomalies, 1)
    end
    
    cache_dict:set(anomaly_key, cjson.encode(anomalies), 1800)
    
    -- 计算总异常分数
    local total_score = 0
    for _, anomaly in ipairs(anomalies) do
        total_score = total_score + anomaly.score
    end
    
    -- 记录总分
    local score_key = "anomaly_score:" .. client_ip
    cache_dict:set(score_key, total_score, 1800)
    
    return total_score
end

-- 基于启发式规则检测随机参数攻击
function _M.detect_random_params_attack(args, headers, method)
    if not args or type(args) ~= "table" then
        return false, 0
    end
    
    local score = 0
    local param_count = 0
    
    -- 计算参数数量
    for _ in pairs(args) do
        param_count = param_count + 1
    end
    
    -- 参数数量多的可能性增加
    if param_count > 5 then
        score = score + (param_count - 5) * 0.3
    end
    
    -- 检查参数名称和值的熵
    local total_entropy = 0
    local random_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    
    for name, value in pairs(args) do
        -- 检查参数名称的熵
        local name_entropy = 0
        local name_len = #name
        if name_len > 0 then
            local char_counts = {}
            for i = 1, name_len do
                local char = name:sub(i, i)
                char_counts[char] = (char_counts[char] or 0) + 1
            end
            
            for _, count in pairs(char_counts) do
                local p = count / name_len
                name_entropy = name_entropy - p * math.log(p)
            end
        end
        
        -- 高熵参数名可能是随机生成的
        if name_entropy > 3.5 then
            score = score + 1
        end
        
        -- 检查值是否看起来随机
        if type(value) == "string" and #value > 5 then
            local has_pattern = false
            
            -- 检查是否符合常见模式 (id, uuid, 时间戳等)
            if value:match("^%d+$") or  -- 纯数字
               value:match("^[a-fA-F0-9%-]+$") or  -- 可能是UUID
               value:match("^%d%d%d%d%-%d%d%-%d%d") then  -- 日期格式
                has_pattern = true
            end
            
            if not has_pattern then
                local random_chars_count = 0
                for i = 1, #value do
                    local char = value:sub(i, i)
                    if random_chars:find(char, 1, true) then
                        random_chars_count = random_chars_count + 1
                    end
                end
                
                -- 如果大部分字符是随机字符集的一部分，增加分数
                if random_chars_count / #value > 0.8 then
                    score = score + 0.5
                end
            end
        end
    end
    
    -- 根据HTTP方法调整分数
    if method == "GET" and param_count > 3 and score > 2 then
        score = score * 1.5  -- GET方法带有大量随机参数更可疑
    end
    
    return score > 3, score
end

-- 基于概率的请求抽样分析
function _M.sample_request(rate)
    return math.random() < rate
end

-- 生成请求特征指纹
function _M.calculate_request_fingerprint(headers, args, method, uri)
    local parts = {
        method = method,
        uri_path = uri,
        host = headers["host"] or "",
        user_agent = headers["user-agent"] or "",
        accept = headers["accept"] or "",
        content_type = headers["content-type"] or ""
    }
    
    local fingerprint = ""
    fingerprint = fingerprint .. (parts.method or "") .. "|"
    fingerprint = fingerprint .. (parts.uri_path or "") .. "|"
    fingerprint = fingerprint .. (parts.host or "") .. "|"
    fingerprint = fingerprint .. (parts.user_agent or "") .. "|"
    fingerprint = fingerprint .. (parts.accept or "") .. "|"
    fingerprint = fingerprint .. (parts.content_type or "") .. "|"
    
    -- 添加参数名（不含值，仅结构）
    if args and type(args) == "table" then
        local param_names = {}
        for name, _ in pairs(args) do
            table.insert(param_names, name)
        end
        table.sort(param_names)
        fingerprint = fingerprint .. table.concat(param_names, ",")
    end
    
    -- 计算指纹的哈希
    local digest = ngx.md5(fingerprint)
    return digest
end

-- 检测蜜罐触发
function _M.check_honeypot_trap(uri, args, headers, traps)
    uri = type(uri) == "string" and uri or ""
    headers = type(headers) == "table" and headers or {}

    if type(traps) == "table" then
        for _, trap in ipairs(traps) do
            if type(trap) == "string" then
                local normalized_trap = trap:match("^%s*(.-)%s*$")
                if normalized_trap ~= "" then
                    if normalized_trap:sub(-1) == "/" then
                        if uri:sub(1, #normalized_trap) == normalized_trap then
                            return true, "configured_resource"
                        end
                    elseif uri == normalized_trap then
                        return true, "configured_resource"
                    end
                end
            end
        end
    end

    -- 检查是否访问了隐藏的蜜罐链接
    if uri:match("%.well%-known/safeline%-trap") or
       uri:match("/admin_access[%.%w]*$") or
       uri:match("/wp%-login%.php") and not headers["referer"] or
       uri:match("/%.git/") then
        return true, "hidden_resource"
    end
    
    -- 检查是否尝试访问常见的敏感文件
    if uri:match("%.sql$") or
       uri:match("%.bak$") or
       uri:match("%.config$") or
       uri:match("%.env$") or
       uri:match("/wp%-config%.php") then
        return true, "sensitive_file"
    end
    
    -- 检查是否包含蜜罐参数
    if args and (args["debug"] == "1" or args["test_mode"] or args["admin_override"]) then
        return true, "honeypot_param"
    end
    
    return false, nil
end

-- 提取请求模式的特征向量
function _M.extract_request_features(client_ip, uri, method, args, headers)
    local features = {}
    
    -- 基本特征
    features.param_count = 0
    if args then
        for _ in pairs(args) do
            features.param_count = features.param_count + 1
        end
    end
    
    -- 计算请求频率特征
    local rate_key = "req_rate:" .. client_ip
    local req_count = safe_incr(limit_dict, rate_key, 1, 0, 60, 0)
    features.request_rate_60s = req_count
    
    -- 计算路径深度
    features.path_depth = 0
    for _ in uri:gmatch("/") do
        features.path_depth = features.path_depth + 1
    end
    
    -- 提取HTTP方法特征
    features.is_get = method == "GET" and 1 or 0
    features.is_post = method == "POST" and 1 or 0
    features.is_other_method = (method ~= "GET" and method ~= "POST") and 1 or 0
    
    -- 提取User-Agent特征
    local ua = headers["user-agent"] or ""
    features.ua_length = #ua
    features.ua_has_mozilla = ua:find("Mozilla", 1, true) and 1 or 0
    features.ua_has_chrome = ua:find("Chrome", 1, true) and 1 or 0
    features.ua_has_bot = (ua:find("bot", 1, true) or ua:find("crawler", 1, true)) and 1 or 0
    
    -- 提取请求头特征
    features.header_count = 0
    for _ in pairs(headers) do
        features.header_count = features.header_count + 1
    end
    
    -- 统计URI长度和含有的特殊字符
    features.uri_length = #uri
    features.uri_special_chars = 0
    for _ in uri:gmatch("[^%w/%-_%.%%]") do
        features.uri_special_chars = features.uri_special_chars + 1
    end
    
    -- 计算特征向量
    local vector = {
        features.param_count,
        features.request_rate_60s,
        features.path_depth,
        features.is_get,
        features.is_post,
        features.is_other_method,
        features.ua_length,
        features.ua_has_mozilla,
        features.ua_has_chrome,
        features.ua_has_bot,
        features.header_count,
        features.uri_length,
        features.uri_special_chars
    }
    
    return vector, features
end

-- 聚类异常检测
function _M.is_anomalous_request(vector, threshold)
    -- 从缓存中获取聚类中心
    local centers_json = cache_dict:get("cluster_centers") or "[]"
    local success, centers = pcall(cjson.decode, centers_json)
    
    if not success or #centers == 0 then
        -- 如果没有聚类中心，创建第一个
        centers = {vector}
        cache_dict:set("cluster_centers", cjson.encode(centers), 3600)
        return false, 0
    end
    
    -- 计算到最近聚类中心的距离
    local min_distance = math.huge
    for _, center in ipairs(centers) do
        if #center == #vector then
            local distance = 0
            for i = 1, #vector do
                distance = distance + (vector[i] - center[i])^2
            end
            distance = math.sqrt(distance)
            
            if distance < min_distance then
                min_distance = distance
            end
        end
    end
    
    -- 如果距离小于阈值，不是异常
    if min_distance < threshold then
        return false, min_distance
    end
    
    -- 是异常，如果聚类中心数量小于最大值，添加新聚类中心
    if #centers < 20 then
        table.insert(centers, vector)
        cache_dict:set("cluster_centers", cjson.encode(centers), 3600)
    end
    
    return true, min_distance
end

local function ipv4_to_number(ip)
    if type(ip) ~= "string" or ip == "" then
        return nil
    end

    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if not a or not b or not c or not d then
        return nil
    end
    if a < 0 or a > 255 or b < 0 or b > 255 or c < 0 or c > 255 or d < 0 or d > 255 then
        return nil
    end

    return (a * 16777216) + (b * 65536) + (c * 256) + d
end

local function ipv4_to_bytes(ip)
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if not a or not b or not c or not d then
        return nil
    end
    if a < 0 or a > 255 or b < 0 or b > 255 or c < 0 or c > 255 or d < 0 or d > 255 then
        return nil
    end

    return string.char(a, b, c, d)
end

local function parse_ipv6(ip)
    if type(ip) ~= "string" or ip == "" then
        return nil
    end

    -- 去掉 [] 与 zone-id（如 fe80::1%eth0）
    ip = ip:gsub("^%[", ""):gsub("%]$", "")
    ip = ip:gsub("%%.*$", "")

    ip = ip:lower()
    if not ip:find(":", 1, true) then
        return nil
    end

    local function expand_segments(raw_segments)
        local hextets = {}
        for _, seg in ipairs(raw_segments) do
            if seg == "" then
                return nil
            end

            if seg:find("%.", 1, true) then
                -- IPv4嵌入（如 ::ffff:192.0.2.1）
                local bytes = ipv4_to_bytes(seg)
                if not bytes then
                    return nil
                end
                local b1, b2, b3, b4 = bytes:byte(1, 4)
                table.insert(hextets, b1 * 256 + b2)
                table.insert(hextets, b3 * 256 + b4)
            else
                if #seg > 4 then
                    return nil
                end
                local v = tonumber(seg, 16)
                if v == nil or v < 0 or v > 0xFFFF then
                    return nil
                end
                table.insert(hextets, v)
            end
        end
        return hextets
    end

    local function split_by_colon(str)
        local parts = {}
        if str == "" then
            return parts
        end
        for seg in str:gmatch("[^:]+") do
            table.insert(parts, seg)
        end
        return parts
    end

    local left, right = ip:match("^(.-)::(.-)$")
    local hextets = nil

    if left ~= nil then
        local left_segs = split_by_colon(left)
        local right_segs = split_by_colon(right)

        local left_hex = expand_segments(left_segs) or {}
        local right_hex = expand_segments(right_segs) or {}

        local total = #left_hex + #right_hex
        if total > 8 then
            return nil
        end

        local fill = 8 - total
        hextets = {}
        for _, v in ipairs(left_hex) do
            table.insert(hextets, v)
        end
        for _ = 1, fill do
            table.insert(hextets, 0)
        end
        for _, v in ipairs(right_hex) do
            table.insert(hextets, v)
        end
    else
        local segs = split_by_colon(ip)
        hextets = expand_segments(segs)
        if not hextets or #hextets ~= 8 then
            return nil
        end
    end

    if not hextets or #hextets ~= 8 then
        return nil
    end

    local out = {}
    for i = 1, 8 do
        local v = hextets[i]
        out[#out + 1] = string.char(bit.rshift(v, 8), bit.band(v, 0xFF))
    end

    return table.concat(out)
end

local function ipv6_in_cidr(ip_bytes, cidr_bytes, prefix)
    prefix = tonumber(prefix) or 0
    if prefix <= 0 then
        return true
    end
    if prefix > 128 then
        return false
    end

    local full_bytes = math.floor(prefix / 8)
    for i = 1, full_bytes do
        if ip_bytes:byte(i) ~= cidr_bytes:byte(i) then
            return false
        end
    end

    local rem = prefix % 8
    if rem == 0 then
        return true
    end

    local mask = bit.band(bit.lshift(0xFF, 8 - rem), 0xFF)
    return bit.band(ip_bytes:byte(full_bytes + 1), mask) == bit.band(cidr_bytes:byte(full_bytes + 1), mask)
end

local function parse_cidr(entry)
    if type(entry) ~= "string" or entry == "" then
        return nil
    end

    local ip, prefix = entry:match("^([^/]+)/(%d+)$")
    if not ip then
        ip = entry
        prefix = nil
    else
        prefix = tonumber(prefix)
    end

    -- IPv6 CIDR
    if ip:find(":", 1, true) then
        local p = tonumber(prefix or 128) or 128
        if p < 0 or p > 128 then
            return nil
        end

        local bytes = parse_ipv6(ip)
        if not bytes then
            return nil
        end

        return { family = "ipv6", bytes = bytes, prefix = p }
    end

    -- IPv4 CIDR
    local p = tonumber(prefix or 32) or 32
    if p < 0 or p > 32 then
        return nil
    end

    local ip_num = ipv4_to_number(ip)
    if not ip_num then
        return nil
    end

    local block_size = 2 ^ (32 - p)
    local start = ip_num - (ip_num % block_size)
    local finish = start + block_size - 1

    return { family = "ipv4", start = start, finish = finish }
end

local _trusted_proxy_ranges = nil
local _trusted_proxy_version = nil
local function get_trusted_proxy_ranges()
    local version = tonumber(config_dict:get("config_version") or 0) or 0
    if _trusted_proxy_version == version and _trusted_proxy_ranges then
        return _trusted_proxy_ranges
    end

    _trusted_proxy_version = version

    local raw = config_dict:get("trusted_proxies")
    local list = nil
    if raw then
        local ok, decoded = pcall(cjson.decode, raw)
        if ok and type(decoded) == "table" then
            list = decoded
        end
    end

    if not list or #list == 0 then
        list = { "127.0.0.1/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" }
    end

    local ranges = {}
    for _, entry in ipairs(list) do
        local range = parse_cidr(entry)
        if range then
            table.insert(ranges, range)
        end
    end

    _trusted_proxy_ranges = ranges
    return ranges
end

local function is_trusted_proxy(remote_ip)
    local remote_num = ipv4_to_number(remote_ip)
    local ranges = get_trusted_proxy_ranges()

    if remote_num then
        for _, r in ipairs(ranges) do
            if r.family == "ipv4" and remote_num >= r.start and remote_num <= r.finish then
                return true
            end
        end
        return false
    end

    local remote_bytes = parse_ipv6(remote_ip)
    if not remote_bytes then
        return false
    end

    for _, r in ipairs(ranges) do
        if r.family == "ipv6" and ipv6_in_cidr(remote_bytes, r.bytes, r.prefix) then
            return true
        end
    end

    return false
end

-- 判断某个remote_addr是否属于可信代理网段（用于“仅允许通过CDN/反代访问源站”等场景）
function _M.is_trusted_proxy_ip(remote_ip)
    if type(remote_ip) ~= "string" or remote_ip == "" then
        return false
    end
    return is_trusted_proxy(remote_ip)
end

function _M.ip_to_number(ip)
    return ipv4_to_number(ip)
end

function _M.parse_cidr(entry)
    return parse_cidr(entry)
end

function _M.ip_matches_cidr(ip, cidr)
    local parsed = cidr
    if type(parsed) ~= "table" then
        parsed = parse_cidr(cidr)
    end

    if type(parsed) ~= "table" then
        return false
    end

    if parsed.family == "ipv4" then
        local ip_num = ipv4_to_number(ip)
        return ip_num ~= nil and ip_num >= parsed.start and ip_num <= parsed.finish
    end

    if parsed.family == "ipv6" then
        local ip_bytes = parse_ipv6(ip)
        return ip_bytes ~= nil and ipv6_in_cidr(ip_bytes, parsed.bytes, parsed.prefix)
    end

    return false
end

local function normalize_forwarded_ip_token(token)
    if type(token) ~= "string" then
        return nil
    end

    local value = token:gsub("^%s+", ""):gsub("%s+$", "")
    if value == "" then
        return nil
    end

    if value:sub(1, 1) == "\"" and value:sub(-1) == "\"" and #value >= 2 then
        value = value:sub(2, -2)
    end

    local bracketed = value:match("^%[(.-)%]:%d+$")
    if bracketed then
        value = bracketed
    else
        local ipv4_with_port = value:match("^(%d+%.%d+%.%d+%.%d+):%d+$")
        if ipv4_with_port then
            value = ipv4_with_port
        end
    end

    value = value:gsub("^%[", ""):gsub("%]$", "")

    if ipv4_to_number(value) then
        return value
    end

    if parse_ipv6(value) then
        return value:lower()
    end

    return nil
end

local function extract_forwarded_chain(value, max_entries)
    local chain = {}
    local limit = tonumber(max_entries or 16) or 16

    local function append_from_string(raw)
        if type(raw) ~= "string" or raw == "" then
            return true
        end

        for token in raw:gmatch("[^,]+") do
            local trimmed = token:gsub("^%s+", ""):gsub("%s+$", "")
            if trimmed ~= "" then
                local normalized = normalize_forwarded_ip_token(trimmed)
                if normalized then
                    chain[#chain + 1] = normalized
                    if #chain > limit then
                        return false
                    end
                elseif trimmed:lower() ~= "unknown" then
                    return false
                end
            end
        end

        return true
    end

    if type(value) == "table" then
        for _, item in ipairs(value) do
            if not append_from_string(item) then
                return nil
            end
        end
    else
        if not append_from_string(value) then
            return nil
        end
    end

    return chain
end

local function extract_rfc_forwarded_chain(value, max_entries)
    local chain = {}
    local limit = tonumber(max_entries or 16) or 16

    local function append_from_string(raw)
        if type(raw) ~= "string" or raw == "" then
            return true
        end

        for item in raw:gmatch("[^,]+") do
            local for_value = item:match("[Ff][Oo][Rr]%s*=%s*\"([^\"]+)\"")
            if not for_value then
                for_value = item:match("[Ff][Oo][Rr]%s*=%s*([^;,%s]+)")
            end

            if for_value and for_value ~= "_" and for_value:lower() ~= "unknown" then
                local normalized = normalize_forwarded_ip_token(for_value)
                if not normalized then
                    return false
                end

                chain[#chain + 1] = normalized
                if #chain > limit then
                    return false
                end
            end
        end

        return true
    end

    if type(value) == "table" then
        for _, item in ipairs(value) do
            if not append_from_string(item) then
                return nil
            end
        end
    else
        if not append_from_string(value) then
            return nil
        end
    end

    return chain
end

-- 获取客户端IP
-- 仅当remote_addr属于可信代理网段时，才信任X-Forwarded-For / X-Real-IP / CF-Connecting-IP
function _M.get_client_ip()
    local remote = ngx.var.remote_addr
    if not remote or remote == "" then
        return "0.0.0.0"
    end

    local headers = ngx.req.get_headers()

    local function pick_single_ip(value)
        return normalize_forwarded_ip_token(value)
    end

    if is_trusted_proxy(remote) then
        local cf = pick_single_ip(headers["cf-connecting-ip"] or headers["CF-Connecting-IP"])
        if cf then
            return cf
        end

        local xri = pick_single_ip(headers["x-real-ip"] or headers["X-Real-IP"])
        if xri then
            return xri
        end

        local forwarded_chain = extract_rfc_forwarded_chain(headers["forwarded"] or headers["Forwarded"], 32)
        if forwarded_chain and #forwarded_chain > 0 then
            for i = #forwarded_chain, 1, -1 do
                if not is_trusted_proxy(forwarded_chain[i]) then
                    return forwarded_chain[i]
                end
            end
            return forwarded_chain[1]
        end

        local xff_chain = extract_forwarded_chain(headers["x-forwarded-for"] or headers["X-Forwarded-For"], 32)
        if xff_chain and #xff_chain > 0 then
            for i = #xff_chain, 1, -1 do
                if not is_trusted_proxy(xff_chain[i]) then
                    return xff_chain[i]
                end
            end
            return xff_chain[1]
        end
    end

    return remote
end

-- 简单的签名token（避免篡改），用于验证页面跳转
function _M.encrypt_token(data)
    if type(data) ~= "table" then
        return nil
    end

    local payload = cjson.encode(data)
    local payload_b64 = base64url_encode(payload)

    local secret = get_token_secret()
    local sig = ngx.hmac_sha1(secret, payload_b64)
    local sig_b64 = base64url_encode(sig)

    return payload_b64 .. "." .. sig_b64
end

function _M.decrypt_token(token)
    if type(token) ~= "string" or token == "" then
        return nil
    end

    local payload_b64, sig_b64 = token:match("^([%w%-%_]+)%.([%w%-%_]+)$")
    if not payload_b64 or not sig_b64 then
        return nil
    end

    local secret = get_token_secret()
    local expected_sig_b64 = base64url_encode(ngx.hmac_sha1(secret, payload_b64))
    if not constant_time_equals(sig_b64, expected_sig_b64) then
        return nil
    end

    local payload = base64url_decode(payload_b64)
    if not payload then
        return nil
    end

    local ok, data = pcall(cjson.decode, payload)
    if not ok then
        return nil
    end

    return data
end

-- 记录事件到Redis（供管理后台展示）
function _M.log_event(event_type, data)
    if type(event_type) ~= "string" or event_type == "" then
        return false
    end

    if data ~= nil and type(data) ~= "table" then
        return false
    end

    local event = data or {}
    event.type = event_type
    event.timestamp = event.timestamp or ngx.time()

    local ok, encoded = pcall(cjson.encode, event)
    if not ok then
        return false
    end

    local max_qps = tonumber(config_dict:get("redis_logs_max_qps") or 100) or 100
    if max_qps <= 0 then
        return false
    end

    local sec = ngx.time()
    local current = safe_incr(limit_dict, "redis_logs:" .. sec, 1, 0, 2, max_qps + 1)
    if current > max_qps then
        return false
    end

    -- 异步写入：避免在WAF路径上被Redis IO阻塞
    local ok_timer, timer_err = ngx.timer.at(0, function(premature, payload)
        if premature then
            return
        end

        local t_red = _M.get_redis()
        if not t_red then
            return
        end

        local push_ok, err = t_red:lpush("safeline:logs", payload)
        if not push_ok then
            ngx.log(ngx.ERR, "Failed to write logs to Redis: ", err)
            _M.release_redis(t_red)
            return
        end

        -- 仅保留最近1000条
        t_red:ltrim("safeline:logs", 0, 999)
        _M.release_redis(t_red)
    end, encoded)

    if not ok_timer then
        ngx.log(ngx.ERR, "Failed to schedule async log write: ", timer_err)
        return false
    end

    return true
end

-- 写入管理后台需要的统计key
function _M.update_redis_stats(host, is_blocked, reason, meta, increment)
    if type(host) ~= "string" or host == "" then
        host = "unknown"
    end

    -- 基础清洗，避免Redis key污染
    host = host:gsub("[^%w%.%-]", "_")
    if type(reason) == "string" and reason ~= "" then
        reason = reason:gsub("[^%w%-%_%.:]", "_")
    else
        reason = nil
    end

    local max_qps = tonumber(config_dict:get("redis_stats_max_qps") or 0) or 0
    if max_qps <= 0 then
        return false
    end

    local sec = ngx.time()
    local current = safe_incr(limit_dict, "redis_stats:" .. sec, 1, 0, 2, max_qps + 1)
    if current > max_qps then
        return false
    end

    local normalized_host = host
    local blocked = is_blocked == true
    local normalized_reason = reason
    local normalized_increment = tonumber(increment or 1) or 1
    if normalized_increment < 1 then
        normalized_increment = 1
    end

    local normalized_ip = nil
    local normalized_uri = nil
    local normalized_method = nil
    if type(meta) == "table" then
        if type(meta.client_ip) == "string" and meta.client_ip ~= "" then
            normalized_ip = meta.client_ip:gsub("[^%w%._:%-]", "_")
        end
        if type(meta.uri) == "string" and meta.uri ~= "" then
            normalized_uri = meta.uri:gsub("[\r\n\t]", ""):sub(1, 256)
        end
        if type(meta.method) == "string" and meta.method ~= "" then
            normalized_method = meta.method:gsub("[^A-Z]", ""):sub(1, 16)
        end
    end

    -- 异步写入：避免阻塞请求路径
    local ok_timer, timer_err = ngx.timer.at(0, function(premature, h, b, r, ip, uri, method, inc)
        if premature then
            return
        end

        local t_red = _M.get_redis()
        if not t_red then
            return
        end

        t_red:init_pipeline()
        local now = ngx.time()
        local bucket = now - (now % 10)

        t_red:incrby("safeline:stats:total_requests", inc)
        t_red:incrby("safeline:stats:site:" .. h, inc)
        t_red:zincrby("safeline:metrics:trend:requests", inc, tostring(bucket))
        t_red:expire("safeline:metrics:trend:requests", 172800)
        t_red:zincrby("safeline:metrics:top:sites", inc, h)
        t_red:expire("safeline:metrics:top:sites", 172800)

        if b then
            t_red:incrby("safeline:stats:blocked_requests", inc)
            t_red:zincrby("safeline:metrics:trend:blocked", inc, tostring(bucket))
            t_red:expire("safeline:metrics:trend:blocked", 172800)
            if r then
                t_red:incrby("safeline:stats:block_reason:" .. r, inc)
                t_red:zincrby("safeline:metrics:top:block_reasons", inc, r)
                t_red:expire("safeline:metrics:top:block_reasons", 172800)
            end
        end

        if ip then
            t_red:zincrby("safeline:metrics:top:ips", inc, ip)
            t_red:expire("safeline:metrics:top:ips", 172800)
        end

        if uri then
            local uri_key = method and (method .. " " .. uri) or uri
            t_red:zincrby("safeline:metrics:top:uris", inc, uri_key)
            t_red:expire("safeline:metrics:top:uris", 172800)
        end

        local results, err = t_red:commit_pipeline()
        if not results then
            ngx.log(ngx.ERR, "Failed to update stats in Redis: ", err)
            _M.release_redis(t_red)
            return
        end

        _M.release_redis(t_red)
    end, normalized_host, blocked, normalized_reason, normalized_ip, normalized_uri, normalized_method, normalized_increment)

    if not ok_timer then
        ngx.log(ngx.ERR, "Failed to schedule async stats write: ", timer_err)
        return false
    end

    return true
end

return _M
