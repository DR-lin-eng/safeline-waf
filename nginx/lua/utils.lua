local _M = {}

-- 引入模块
local cjson = require "cjson"
local redis = require "resty.redis"

-- 共享内存
local cache_dict = ngx.shared.safeline_cache
local limit_dict = ngx.shared.safeline_limit
local counters_dict = ngx.shared.safeline_counters

-- 连接Redis
function _M.get_redis()
    local red = redis:new()
    red:set_timeout(1000) -- 1秒超时
    
    local ok, err = red:connect("redis", 6379)
    if not ok then
        ngx.log(ngx.ERR, "Failed to connect to Redis: " .. tostring(err))
        return nil
    end
    
    return red
end

-- 计算指数退避时间 (用于动态限速)
function _M.calc_exp_backoff(base, attempt, max)
    local time = base * math.pow(2, attempt)
    return math.min(time, max)
end

-- 检测自动化工具签名 (针对DDoS脚本)
function _M.detect_automation_signature(headers, uri, method)
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
        local count = cache_dict:incr(headers_key, 1, 0, 300)
        if count > 10 then
            table.insert(signs, "consistent_headers")
        end
    end
    
    -- 检查请求速率和间隔
    local client_ip = ngx.var.remote_addr
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
            red:set_keepalive(10000, 100)
            
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
                red:set_keepalive(10000, 100)
            end
        end
    end
    
    return new_data
end

-- 动态限速
function _M.dynamic_rate_limit(key, limit, window, increment)
    increment = increment or 1
    
    -- 获取当前计数
    local count = limit_dict:incr(key, increment, 0, window)
    
    -- 获取当前限制
    local limit_key = key .. "_limit"
    local current_limit = limit_dict:get(limit_key) or limit
    
    -- 检查是否超过限制
    if count > current_limit then
        -- 超过限制时，动态增加限制门槛
        local violations_key = key .. "_violations"
        local violations = limit_dict:incr(violations_key, 1, 0, window * 5)
        
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
    for _, v in pairs(parts) do
        fingerprint = fingerprint .. v .. "|"
    end
    
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
function _M.check_honeypot_trap(uri, args, headers)
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
    local req_count = limit_dict:incr(rate_key, 1, 0, 60)
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
    local vector = {}
    for k, v in pairs(features) do
        table.insert(vector, v)
    end
    
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

return _M
