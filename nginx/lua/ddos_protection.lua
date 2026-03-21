local _M = {}

-- 引入模块
local cjson     = require "cjson"
local utils     = require "utils"
local cf_shield = require "cf_shield"

-- 共享内存
local limit_dict = ngx.shared.safeline_limit
local cache_dict = ngx.shared.safeline_cache
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

local _cached_config_version = nil
local _cached_configs = {}

local function get_cached_config(key, fallback)
    local version = tonumber(config_dict:get("config_version") or 0) or 0
    if _cached_config_version ~= version then
        _cached_config_version = version
        _cached_configs = {}
    end

    local cached = _cached_configs[key]
    if cached ~= nil then
        return cached
    end

    local decoded = safe_decode_table(config_dict:get(key) or "{}", fallback or {})
    _cached_configs[key] = decoded
    return decoded
end

local function safe_incr(dict, key, value, init, ttl, fallback)
    local newval, err = dict:incr(key, value, init, ttl)
    if newval == nil then
        if fallback ~= nil then
            return fallback, err
        end
        return init or 0, err
    end
    return newval, nil
end

-- 行为模式分析
local function analyze_behavior_pattern(client_ip)
    local key_prefix = "behavior:" .. client_ip
    local now = ngx.time()
    
    -- 获取配置
    local config = get_cached_config("behavior_analysis", {})
    
    local window_size = config.window_size or 60  -- 60秒窗口
    local min_requests = config.min_requests or 10  -- 最少请求数
    
    -- 获取当前行为数据
    local requests_key = key_prefix .. ":requests"
    local methods_key = key_prefix .. ":methods"
    local paths_key = key_prefix .. ":paths"
    local intervals_key = key_prefix .. ":intervals"
    local last_time_key = key_prefix .. ":last_time"
    
    -- 递增请求计数
    local requests = safe_incr(limit_dict, requests_key, 1, 0, window_size, math.huge)
    
    -- 记录HTTP方法分布
    local method = ngx.req.get_method()
    local methods_json = cache_dict:get(methods_key) or '{}'
    local ok_m, methods = pcall(cjson.decode, methods_json)
    if not ok_m or type(methods) ~= "table" then methods = {} end
    methods[method] = (methods[method] or 0) + 1
    -- cache_dict 写入失败（内存不足）时跳过，不影响主路径
    cache_dict:set(methods_key, cjson.encode(methods), window_size)

    -- 记录路径分布（攻击时路径分布数据可能会淹没cache_dict，跳过写入不影响核心检测）
    local uri = ngx.var.uri
    local paths_json = cache_dict:get(paths_key) or '{}'
    local ok_p, paths = pcall(cjson.decode, paths_json)
    if not ok_p or type(paths) ~= "table" then paths = {} end
    paths[uri] = (paths[uri] or 0) + 1
    cache_dict:set(paths_key, cjson.encode(paths), window_size)

    -- 记录请求间隔（cache_dict 写失败时跳过）
    local last_time = tonumber(cache_dict:get(last_time_key) or 0)
    if last_time > 0 then
        local interval = now - last_time
        local intervals_json = cache_dict:get(intervals_key) or '[]'
        local ok_i, intervals = pcall(cjson.decode, intervals_json)
        if not ok_i or type(intervals) ~= "table" then intervals = {} end
        table.insert(intervals, interval)
        
        -- 只保留最近20个间隔
        if #intervals > 20 then
            table.remove(intervals, 1)
        end
        
        cache_dict:set(intervals_key, cjson.encode(intervals), window_size)
    end
    
    -- 更新最后请求时间
    cache_dict:set(last_time_key, now, window_size)
    
    -- 只有当请求数达到最小阈值时才进行行为分析
    if requests < min_requests then
        return 0  -- 未达到分析阈值
    end
    
    -- 分析行为模式
    local anomaly_score = 0
    
    -- 1. 分析请求间隔的规律性
    local intervals_json = cache_dict:get(intervals_key) or '[]'
    local ok_iv, intervals = pcall(cjson.decode, intervals_json)
    if not ok_iv or type(intervals) ~= "table" then intervals = {} end
    
    if #intervals >= 5 then
        local sum = 0
        local sq_sum = 0
        
        for _, interval in ipairs(intervals) do
            sum = sum + interval
            sq_sum = sq_sum + interval * interval
        end
        
        local mean = sum / #intervals
        local variance = (sq_sum / #intervals) - (mean * mean)
        local std_dev = math.sqrt(variance)
        
        -- 检查间隔的规律性和频率
        if std_dev < 0.1 and mean < 1.0 then  -- 高度规律的快速请求
            anomaly_score = anomaly_score + 3
        elseif std_dev < 0.3 and mean < 2.0 then  -- 较规律的快速请求
            anomaly_score = anomaly_score + 2
        elseif mean < 0.2 then  -- 极快速请求
            anomaly_score = anomaly_score + 2
        end
    end
    
    -- 2. 分析HTTP方法分布
    local methods_json = cache_dict:get(methods_key) or '{}'
    local ok_mt, methods = pcall(cjson.decode, methods_json)
    if not ok_mt or type(methods) ~= "table" then methods = {} end
    
    local total_methods = 0
    for _, count in pairs(methods) do
        total_methods = total_methods + count
    end
    
    if total_methods > 0 then
        local method_entropy = 0
        local method_count = 0
        
        for _, count in pairs(methods) do
            method_count = method_count + 1
            local p = count / total_methods
            method_entropy = method_entropy - p * math.log(p)
        end
        
        -- 检查HTTP方法的分布异常
        if method_count >= 4 and method_entropy > 1.8 then  -- 使用了多种HTTP方法且分布均匀（高熵）
            anomaly_score = anomaly_score + 2
        elseif method_count >= 4 then  -- 使用了多种HTTP方法但分布不均匀
            anomaly_score = anomaly_score + 1
        end
    end
    
    -- 3. 分析路径分布
    local paths_json = cache_dict:get(paths_key) or '{}'
    local ok_pt, paths = pcall(cjson.decode, paths_json)
    if not ok_pt or type(paths) ~= "table" then paths = {} end
    
    local path_count = 0
    for _ in pairs(paths) do
        path_count = path_count + 1
    end
    
    -- 检查路径多样性
    if path_count > 15 and requests < 20 then  -- 短时间内访问大量不同路径
        anomaly_score = anomaly_score + 3
    elseif path_count > 10 and requests < 15 then
        anomaly_score = anomaly_score + 2
    elseif path_count > 7 and requests < 10 then
        anomaly_score = anomaly_score + 1
    end
    
    return anomaly_score
end

-- 分析请求特征
local function analyze_request_features(client_ip)
    local uri = ngx.var.uri
    local args = ngx.req.get_uri_args()
    local headers = ngx.req.get_headers()
    local method = ngx.req.get_method()
    
    -- 提取请求特征向量
    local vector, features = utils.extract_request_features(client_ip, uri, method, args, headers)
    
    -- 检查是否是异常请求
    local is_anomalous, distance = utils.is_anomalous_request(vector, 5.0)
    
    -- 检查参数异常
    local is_random_params, param_score = utils.detect_random_params_attack(args, headers, method)
    
    -- 检查自动化工具签名
    local is_automation, auto_confidence, signs = utils.detect_automation_signature(headers, uri, method, client_ip)
    
    -- 计算总异常分数
    local total_score = 0
    
    if is_anomalous then
        total_score = total_score + math.min(5, distance)
    end
    
    if is_random_params then
        total_score = total_score + param_score
    end
    
    if is_automation then
        total_score = total_score + (auto_confidence * 5)
    end
    
    -- 更新异常记录
    local reasons = {}
    if is_anomalous then table.insert(reasons, "anomalous_pattern") end
    if is_random_params then table.insert(reasons, "random_parameters") end
    if is_automation then 
        for _, sign in ipairs(signs) do
            table.insert(reasons, sign)
        end
    end
    
    if total_score > 0 then
        utils.record_anomaly(client_ip, uri, table.concat(reasons, ","), total_score)
    end
    
    return total_score
end

-- URL级DDoS防护 (增强版)
function _M.check_url_ddos(client_ip, uri)
    -- 获取配置
    local config = get_cached_config("ddos_protection", {})
    
    -- 默认配置
    local url_threshold = tonumber(config.url_threshold or 60) or 60  -- 单个URL的请求阈值
    local url_window = tonumber(config.url_window or 60) or 60       -- 时间窗口(秒)
    local ip_threshold = tonumber(config.ip_threshold or 300) or 300  -- 单个IP的总请求阈值
    local ip_window = tonumber(config.ip_window or 60) or 60         -- IP时间窗口(秒)

    -- 跨IP的集群攻击识别（浏览器 API 集群型 DDoS 常见形态）
    local global_threshold = tonumber(config.global_threshold or 0) or 0
    local global_hard_threshold = tonumber(config.global_hard_threshold or 0) or 0

    local global_burst_window = tonumber(config.global_burst_window or 0) or 0
    local global_burst_threshold = tonumber(config.global_burst_threshold or 0) or 0

    local unique_ip_window = tonumber(config.unique_ip_window or 0) or 0
    local unique_ip_threshold = tonumber(config.unique_ip_threshold or 0) or 0
    local unique_ip_track_start = tonumber(config.unique_ip_track_start or 0) or 0

    -- 兜底：避免错误配置导致窗口无意义
    if url_window < 1 then url_window = 60 end
    if ip_window < 1 then ip_window = 60 end
    if global_burst_window < 0 then global_burst_window = 0 end
    if unique_ip_window < 0 then unique_ip_window = 0 end
    local dynamic_scaling = config.dynamic_scaling
    if dynamic_scaling == nil then
        dynamic_scaling = true -- 是否启用动态扩展
    end
    
    uri = uri or ngx.var.uri or "/"

    -- 对URL进行规范化处理，忽略查询参数
    local base_uri = uri:match("^([^?]+)") or uri
    
    -- 获取URL特征
    local unique_parts = {}
    
    for part in base_uri:gmatch("([^/]+)") do
        -- 检查是否包含数字或随机字符，这些可能是攻击者为每个请求生成的随机路径
        -- 但要排除一些常见的包含数字的模式（例如日期、版本号等）
        if part:match("%d") and not part:match("^v%d+$") and not part:match("^%d%d%d%d%-%d%d%-%d%d$") then
            table.insert(unique_parts, "NUM")
        elseif #part >= 8 and part:match("[a-zA-Z0-9]") and part:match("%W") then
            table.insert(unique_parts, "RAND")
        else
            table.insert(unique_parts, part)
        end
    end
    
    -- 创建规范化的路径，将随机部分替换为占位符
    local normalized_uri = "/" .. table.concat(unique_parts, "/")
    local uri_id = ngx.md5(normalized_uri)
    
    -- 获取查询参数
    local args = ngx.req.get_uri_args()
    local has_random_params = false
    
    if args and type(args) == "table" then
        local param_count = 0
        local random_param_count = 0
        
        for name, value in pairs(args) do
            param_count = param_count + 1
            
            -- 检查参数名或值是否包含随机特征
            if (#name >= 6 and name:match("[a-zA-Z0-9]") and name:match("[^a-zA-Z0-9_]")) or
               (type(value) == "string" and #value >= 10 and value:match("[a-zA-Z0-9]") and not value:match("^%d+$")) then
                random_param_count = random_param_count + 1
            end
        end
        
        -- 如果超过30%的参数看起来是随机的，标记为随机参数
        if param_count > 0 and (random_param_count / param_count) > 0.3 then
            has_random_params = true
        end
    end
    
    -- 计数器key
    local url_key = "ddos:url:" .. uri_id .. ":" .. client_ip
    local ip_key = "ddos:ip:" .. client_ip
    local global_key = "ddos:global:" .. uri_id
    
    -- 增加计数
    local url_count, url_err = safe_incr(limit_dict, url_key, 1, 0, url_window, math.huge)
    local ip_count, ip_err = safe_incr(limit_dict, ip_key, 1, 0, ip_window, math.huge)
    local global_count, global_err = safe_incr(limit_dict, global_key, 1, 0, url_window, math.huge)

    -- shared dict 内存不足时，直接进入”全局高压”防护分支，避免继续执行复杂逻辑放大开销
    if url_err == "no memory" or ip_err == "no memory" or global_err == "no memory" then
        utils.record_anomaly(client_ip, uri, "global_hard", 6)
        cf_shield.report_attack("global_hard", nil, 15)   -- 内存耗尽 = 极高压，立即上报高权重
        return true, "global_hard", math.huge, (global_hard_threshold > 0 and global_hard_threshold or 1)
    end
    
    -- 动态调整阈值
    local url_limit = url_threshold
    local ip_limit = ip_threshold

    if dynamic_scaling then
        -- 修正：热门URL（全局请求量大）期间按原阈值保守处理，不再上调
        -- 之前的 *2 逻辑在CC攻击命中热门URL时反而放宽了保护，属于致命逻辑反转。
        -- 冷门URL降低阈值保持不变（捕获对低频路径的精准扫描）
        if global_count < 10 then  -- 冷门URL：降低阈值捕获针对性扫描
            url_limit = url_threshold / 2
        end
        -- 全局压力极高时（CC攻击典型特征）主动收紧单IP配额
        if global_threshold > 0 and global_count > global_threshold * 0.75 then
            url_limit = url_limit * 0.6
            ip_limit  = ip_limit  * 0.6
        end

        -- 如果检测到随机参数，降低阈值
        if has_random_params then
            url_limit = url_limit / 2
            ip_limit = ip_limit / 2
        end
    end

    -- 快速阈值检查：先用基础计数判断，避免在高并发下过早进入复杂分析
    if url_count > url_limit then
        -- URL级别限制触发
        ngx.log(ngx.WARN, "URL level DDoS detected for " .. normalized_uri .. 
                         " from " .. client_ip .. " (" .. url_count .. "/" .. url_limit .. ")")
        
        -- 记录异常
        utils.record_anomaly(client_ip, uri, "url_ddos", 5)
        
        return true, "url_limit", url_count, url_limit
    end
    
    if ip_count > ip_limit then
        -- IP级别限制触发
        ngx.log(ngx.WARN, "IP level DDoS detected from " .. client_ip .. 
                         " (" .. ip_count .. "/" .. ip_limit .. ")")
        
        -- 记录异常
        utils.record_anomaly(client_ip, uri, "ip_ddos", 4)
        
        return true, "ip_limit", ip_count, ip_limit
    end

    -- 跨IP全局压力识别：适配”多IP低频但总体高压”的集群攻击
    -- 注意：这些分支不应触发单IP封禁（由上层 access.lua 根据 reason 选择 challenge/限速/丢弃）
    -- 当管理员未配置全局阈值时，自动使用保守的推导值以提供兜底保护
    local effective_global_threshold      = global_threshold
    local effective_global_hard_threshold = global_hard_threshold
    if effective_global_threshold == 0 then
        -- 按”单URL单IP阈值 × 允许的最大并发攻击IP数”估算，默认假设50个攻击IP
        effective_global_threshold = url_threshold * 50
    end
    if effective_global_hard_threshold == 0 then
        effective_global_hard_threshold = effective_global_threshold * 3
    end

    if global_burst_window > 0 and global_burst_threshold > 0 then
        local burst_key = "ddos:global_burst:" .. uri_id
        local burst_count = safe_incr(limit_dict, burst_key, 1, 0, global_burst_window, math.huge)
        if burst_count > global_burst_threshold then
            utils.record_anomaly(client_ip, uri, "global_burst", 4)
            return true, "global_burst", burst_count, global_burst_threshold
        end
    end

    if unique_ip_window > 0 and unique_ip_threshold > 0 then
        local track_start = unique_ip_track_start
        if track_start <= 0 then
            -- 默认只在全局有一定压力时才开始统计唯一IP，避免正常业务占用过多shared dict空间
            track_start = math.max(200, math.floor(effective_global_threshold * 0.25))
        end

        if global_count >= track_start then
            local seen_key = "ddos:uniq_seen:" .. uri_id .. ":" .. client_ip
            local added, add_err = limit_dict:add(seen_key, 1, unique_ip_window)
            if added then
                local uniq_key = "ddos:uniq:" .. uri_id
                local uniq_count = safe_incr(limit_dict, uniq_key, 1, 0, unique_ip_window, math.huge)
                if uniq_count > unique_ip_threshold then
                    utils.record_anomaly(client_ip, uri, "global_unique_ip_surge", 3)
                    return true, "unique_ip_surge", uniq_count, unique_ip_threshold
                end
            elseif add_err == "no memory" then
                -- shared dict 已接近耗尽：视为系统处于高压状态，触发更强的全局防护
                return true, "global_hard", math.huge, effective_global_hard_threshold
            else
                local uniq_key = "ddos:uniq:" .. uri_id
                local uniq_count = tonumber(limit_dict:get(uniq_key) or 0) or 0
                if uniq_count > unique_ip_threshold then
                    utils.record_anomaly(client_ip, uri, "global_unique_ip_surge", 3)
                    return true, "unique_ip_surge", uniq_count, unique_ip_threshold
                end
            end
        end
    end

    if global_count > effective_global_hard_threshold then
        utils.record_anomaly(client_ip, uri, "global_hard", 5)
        cf_shield.report_attack("global_hard", global_count / effective_global_hard_threshold)
        return true, "global_hard", global_count, effective_global_hard_threshold
    end

    if global_count > effective_global_threshold then
        utils.record_anomaly(client_ip, uri, "global_pressure", 3)
        cf_shield.report_attack("global_pressure", global_count / effective_global_threshold)
        return true, "global_pressure", global_count, effective_global_threshold
    end

    -- 进行行为模式分析
    local behavior_score = analyze_behavior_pattern(client_ip)

    -- 进行请求特征分析
    local feature_score = analyze_request_features(client_ip)

    -- 根据行为分析和特征分析调整阈值
    local combined_score = behavior_score + feature_score
    if combined_score >= 5 then
        url_limit = url_limit * (1 - math.min(0.9, combined_score / 10))
        ip_limit = ip_limit * (1 - math.min(0.9, combined_score / 10))

        -- 阈值可能被收紧，重新检查一次
        if url_count > url_limit then
            ngx.log(ngx.WARN, "URL level DDoS detected for " .. normalized_uri ..
                             " from " .. client_ip .. " (" .. url_count .. "/" .. url_limit .. ")")
            utils.record_anomaly(client_ip, uri, "url_ddos", 5)
            return true, "url_limit", url_count, url_limit
        end

        if ip_count > ip_limit then
            ngx.log(ngx.WARN, "IP level DDoS detected from " .. client_ip ..
                             " (" .. ip_count .. "/" .. ip_limit .. ")")
            utils.record_anomaly(client_ip, uri, "ip_ddos", 4)
            return true, "ip_limit", ip_count, ip_limit
        end
    end

    -- 即使未超过硬性阈值，如果行为和特征异常分数很高，也认为是攻击
    if combined_score >= 8 then
        ngx.log(ngx.WARN, "Behavioral DDoS detected from " .. client_ip .. 
                         " with score " .. combined_score)

        -- 记录异常
        utils.record_anomaly(client_ip, uri, "behavioral_ddos", combined_score)

        return true, "behavioral", combined_score, 8
    end
    
    return false
end

-- 检查慢速DDoS攻击
function _M.check_slow_ddos(client_ip)
    -- 获取配置
    local config = get_cached_config("slow_ddos", {})
    
    -- 默认配置
    if config.enabled == false then
        return false
    end

    local connection_threshold = tonumber(config.connection_threshold or 10) or 10
    local window = tonumber(config.window or 60) or 60
    if window < 1 then
        window = 60
    end

    -- 连接维度的攻击通常表现为：短时间内创建大量连接（包括慢速连接/连接风暴）
    -- Lua无法准确获取“并发连接数”，但可以用 ngx.var.connection 统计窗口内的新连接数。
    local conn_id = ngx.var.connection
    local conn_key = "ddos:conn:" .. client_ip

    if not conn_id or conn_id == "" then
        local conn_count = safe_incr(limit_dict, conn_key, 1, 0, window, math.huge)
        if conn_count > connection_threshold then
            return true, "conn_flood", conn_count, connection_threshold
        end
        return false, nil, conn_count, connection_threshold
    end

    local seen_key = "ddos:conn_seen:" .. client_ip .. ":" .. conn_id
    local added, err = limit_dict:add(seen_key, 1, window)

    if err == "no memory" then
        local conn_count = tonumber(limit_dict:get(conn_key) or 0) or 0
        return true, "conn_hard", conn_count, connection_threshold
    end

    local conn_count = tonumber(limit_dict:get(conn_key) or 0) or 0
    if added then
        conn_count = safe_incr(limit_dict, conn_key, 1, 0, window, math.huge)
    end

    if conn_count > connection_threshold then
        return true, "conn_flood", conn_count, connection_threshold
    end

    return false, nil, conn_count, connection_threshold
end

-- Anti-CC 防护：短时间内针对同一路径/指纹的高频请求
-- 返回：is_attack, reason, count, limit
function _M.check_cc_attack(client_ip, uri)
    local config = get_cached_config("anti_cc", {})

    local window = tonumber(config.cc_time_window) or 60
    if window < 1 then
        window = 60
    end

    local uri_threshold = tonumber(config.cc_threshold) or 60
    if uri_threshold < 1 then
        uri_threshold = 60
    end

    local ip_threshold = tonumber(config.cc_request_count) or (uri_threshold * 5)

    local base_uri = (uri and uri:match("^([^?]+)")) or uri or "/"
    if base_uri:match("^/safeline%-") then
        return false
    end

    local uri_hash = ngx.md5(base_uri)

    -- 短窗口爆发（更容易拖垮连接/CPU）
    local burst_window = tonumber(config.burst_window) or 5
    if burst_window < 1 then
        burst_window = 1
    end

    local burst_threshold = tonumber(config.burst_threshold)
    if not burst_threshold or burst_threshold < 1 then
        -- 修正：之前 *3 使得单IP在5秒内可以发出 (60/60)*5*3=15 条，最大值20条。
        -- 改为 *1.5，严格按速率推导（60/60s × 5s × 1.5 = 7.5 → 8 条），
        -- 保留最小值10给合理burst场景。
        burst_threshold = math.max(10, math.floor((uri_threshold / window) * burst_window * 1.5))
    end

    local burst_key = "cc:burst:" .. client_ip .. ":" .. uri_hash
    local burst_count, burst_err = safe_incr(limit_dict, burst_key, 1, 0, burst_window, math.huge)
    -- shared dict 内存耗尽：系统在CC攻击重压下，立即进入防护状态
    if burst_err == "no memory" then
        cf_shield.report_attack("burst", nil, 8)
        return true, "burst", math.huge, burst_threshold
    end
    if burst_count > burst_threshold then
        cf_shield.report_attack("burst", burst_count / burst_threshold)
        return true, "burst", burst_count, burst_threshold
    end

    -- 同一路径计数
    local uri_key = "cc:uri:" .. client_ip .. ":" .. uri_hash
    local uri_count, uri_err = safe_incr(limit_dict, uri_key, 1, 0, window, math.huge)
    if uri_err == "no memory" then
        cf_shield.report_attack("uri", nil, 4)
        return true, "uri", math.huge, uri_threshold
    end
    if uri_count > uri_threshold then
        cf_shield.report_attack("uri", uri_count / uri_threshold)
        return true, "uri", uri_count, uri_threshold
    end

    -- 全路径总计数（防止扫全站）
    local ip_key = "cc:ip:" .. client_ip
    local ip_count, ip_err = safe_incr(limit_dict, ip_key, 1, 0, window, math.huge)
    if ip_err == "no memory" then
        cf_shield.report_attack("ip", nil, 4)
        return true, "ip", math.huge, ip_threshold
    end
    if ip_count > ip_threshold then
        cf_shield.report_attack("ip", ip_count / ip_threshold)
        return true, "ip", ip_count, ip_threshold
    end

    -- 指纹重复：同结构请求过于一致（仅在前面检查都通过时才执行，避免在高并发下浪费CPU）
    local fp_window = tonumber(config.fp_window) or math.min(10, window)
    if fp_window < 1 then
        fp_window = 5
    end

    local fp_threshold = tonumber(config.fp_threshold)
    if not fp_threshold or fp_threshold < 1 then
        fp_threshold = math.max(10, math.floor((uri_threshold / window) * fp_window * 2))
    end

    local headers = ngx.req.get_headers()
    local args = ngx.req.get_uri_args()
    local method = ngx.req.get_method()
    local fp = utils.calculate_request_fingerprint(headers, args, method, base_uri)

    local fp_key = "cc:fp:" .. client_ip .. ":" .. fp
    local fp_count, fp_err = safe_incr(limit_dict, fp_key, 1, 0, fp_window, math.huge)
    if fp_err == "no memory" then
        return true, "fingerprint", math.huge, fp_threshold
    end
    if fp_count > fp_threshold then
        return true, "fingerprint", fp_count, fp_threshold
    end

    return false
end

-- 防止随机请求方法和查询字符串攻击
function _M.check_random_requests(client_ip)
    -- 获取当前请求信息
    local method = ngx.req.get_method()
    local uri = ngx.var.uri
    local args = ngx.req.get_uri_args()
    
    -- 保存最近的请求方法历史
    local method_key = "random:methods:" .. client_ip
    local methods = safe_decode_table(cache_dict:get(method_key) or "[]", {})
    
    -- 更新方法历史
    table.insert(methods, 1, method)
    if #methods > 10 then
        table.remove(methods, 11)
    end
    
    cache_dict:set(method_key, cjson.encode(methods), 300)
    
    -- 保存最近的URI历史
    local uri_key = "uris:" .. client_ip
    local uris = safe_decode_table(cache_dict:get(uri_key) or "[]", {})

    -- 记录最近的请求指纹（忽略参数值，只看结构）
    local headers = ngx.req.get_headers()
    local fingerprint = utils.calculate_request_fingerprint(headers, args, method, uri)
    local fp_key = "fingerprints:" .. client_ip
    local fps = safe_decode_table(cache_dict:get(fp_key) or "[]", {})
    table.insert(fps, 1, fingerprint)
    if #fps > 10 then
        table.remove(fps, 11)
    end
    cache_dict:set(fp_key, cjson.encode(fps), 300)
    
    -- 更新URI历史
    table.insert(uris, 1, uri)
    if #uris > 10 then
        table.remove(uris, 11)
    end
    
    cache_dict:set(uri_key, cjson.encode(uris), 300)
    
    -- 检查方法变化频率
    if #methods >= 5 then
        local unique_methods = {}
        for _, m in ipairs(methods) do
            unique_methods[m] = true
        end
        
        -- 如果5个请求中使用了3种以上不同的方法，可能是随机方法攻击
        local unique_count = 0
        for _ in pairs(unique_methods) do
            unique_count = unique_count + 1
        end
        
        if unique_count >= 3 then
            return true, "random_methods"
        end
    end
    
    -- 检查URI变化频率
    if #uris >= 5 then
        local unique_uris = {}
        for _, u in ipairs(uris) do
            unique_uris[u] = true
        end
        
        -- 如果短时间内访问大量不同路径，可能是随机路径/扫描攻击
        local unique_count = 0
        for _ in pairs(unique_uris) do
            unique_count = unique_count + 1
        end
        
        if unique_count >= 4 then
            return true, "random_paths"
        end
    end

    -- 指纹变化过快：结构变化非常多（常见于随机参数/自动化变形）
    if #fps >= 6 then
        local unique_fps = {}
        for _, f in ipairs(fps) do
            unique_fps[f] = true
        end

        local unique_count = 0
        for _ in pairs(unique_fps) do
            unique_count = unique_count + 1
        end

        if unique_count >= 6 then
            return true, "random_fingerprints"
        end
    end
    
    -- 检查当前请求参数的随机性
    local is_random_params = false
    if args and type(args) == "table" then
        local random_attack, score = utils.detect_random_params_attack(args, headers, method)
        if random_attack and score > 3 then
            is_random_params = true
        end
    end

    if is_random_params then
        return true, "random_parameters"
    end
    
    return false, nil
end

-- 流量动态识别
function _M.analyze_traffic_pattern(client_ip)
    -- 获取各种统计数据
    local stats = {
        request_count = 0,
        method_distribution = {},
        status_distribution = {},
        url_distribution = {},
        interval_statistics = {
            mean = 0,
            std_dev = 0
        }
    }
    
    -- 获取请求计数
    local req_key = "stats:req:" .. client_ip
    stats.request_count = tonumber(cache_dict:get(req_key) or 0)
    
    -- 获取方法分布
    local methods_key = "stats:methods:" .. client_ip
    local methods_json = cache_dict:get(methods_key) or '{}'
    stats.method_distribution = safe_decode_table(methods_json, {})
    
    -- 获取状态码分布
    local status_key = "stats:status:" .. client_ip
    local status_json = cache_dict:get(status_key) or '{}'
    stats.status_distribution = safe_decode_table(status_json, {})
    
    -- 获取URL分布
    local urls_key = "stats:urls:" .. client_ip
    local urls_json = cache_dict:get(urls_key) or '{}'
    stats.url_distribution = safe_decode_table(urls_json, {})
    
    -- 获取间隔统计
    local interval_key = "stats:intervals:" .. client_ip
    local interval_json = cache_dict:get(interval_key) or '{}'
    stats.interval_statistics = safe_decode_table(interval_json, {
        mean = 0,
        std_dev = 0
    })
    
    -- 计算异常分数
    local score = 0
    
    -- 1. 检查请求频率
    if stats.request_count > 100 then
        score = score + math.min(5, stats.request_count / 100)
    end
    
    -- 2. 检查方法分布异常
    local method_count = 0
    local total_methods = 0
    for _, count in pairs(stats.method_distribution) do
        method_count = method_count + 1
        total_methods = total_methods + count
    end
    
    if method_count >= 4 and total_methods > 20 then
        score = score + 2
    end
    
    -- 3. 检查状态码分布异常
    local error_count = 0
    local total_status = 0
    for status, count in pairs(stats.status_distribution) do
        total_status = total_status + count
        if tonumber(status) >= 400 then
            error_count = error_count + count
        end
    end
    
    if total_status > 0 and (error_count / total_status) > 0.3 then
        score = score + 3
    end
    
    -- 4. 检查URL分布异常
    local url_count = 0
    for _ in pairs(stats.url_distribution) do
        url_count = url_count + 1
    end
    
    if url_count > 20 and stats.request_count < 50 then
        score = score + 4
    end
    
    -- 5. 检查请求间隔异常
    if stats.interval_statistics.mean < 1.0 and stats.interval_statistics.std_dev < 0.5 then
        score = score + 3
    end
    
    return score > 5, score
end

-- 更新流量统计信息
function _M.update_traffic_stats(client_ip, status, uri, method)
    -- 更新请求计数
    local req_key = "stats:req:" .. client_ip
    cache_dict:incr(req_key, 1, 0, 600)
    
    -- 更新方法分布
    local methods_key = "stats:methods:" .. client_ip
    local methods_json = cache_dict:get(methods_key) or '{}'
    local methods = safe_decode_table(methods_json, {})
    
    methods[method] = (methods[method] or 0) + 1
    cache_dict:set(methods_key, cjson.encode(methods), 600)
    
    -- 更新状态码分布
    local status_key = "stats:status:" .. client_ip
    local status_json = cache_dict:get(status_key) or '{}'
    local statuses = safe_decode_table(status_json, {})
    
    statuses[tostring(status)] = (statuses[tostring(status)] or 0) + 1
    cache_dict:set(status_key, cjson.encode(statuses), 600)
    
    -- 更新URL分布
    local urls_key = "stats:urls:" .. client_ip
    local urls_json = cache_dict:get(urls_key) or '{}'
    local urls = safe_decode_table(urls_json, {})
    
    urls[uri] = (urls[uri] or 0) + 1
    cache_dict:set(urls_key, cjson.encode(urls), 600)
    
    -- 更新请求间隔统计
    local now = ngx.now()
    local last_time_key = "stats:last_time:" .. client_ip
    local last_time = tonumber(cache_dict:get(last_time_key) or 0)
    
    if last_time > 0 then
        local interval = now - last_time
        
        -- 更新间隔列表
        local intervals_key = "stats:interval_list:" .. client_ip
        local intervals_json = cache_dict:get(intervals_key) or '[]'
        local intervals = safe_decode_table(intervals_json, {})
        
        table.insert(intervals, interval)
        if #intervals > 50 then
            table.remove(intervals, 1)
        end
        
        cache_dict:set(intervals_key, cjson.encode(intervals), 600)
        
        -- 计算均值和标准差
        if #intervals >= 5 then
            local sum = 0
            local sq_sum = 0
            
            for _, v in ipairs(intervals) do
                sum = sum + v
                sq_sum = sq_sum + v * v
            end
            
            local mean = sum / #intervals
            local variance = (sq_sum / #intervals) - (mean * mean)
            local std_dev = math.sqrt(variance)
            
            -- 更新统计信息
            local interval_stats = {
                mean = mean,
                std_dev = std_dev
            }
            
            local interval_key = "stats:intervals:" .. client_ip
            cache_dict:set(interval_key, cjson.encode(interval_stats), 600)
        end
    end
    
    -- 更新最后请求时间
    cache_dict:set(last_time_key, now, 600)
end

return _M
