local _M = {}

-- 引入模块
local cjson = require "cjson"
local utils = require "utils"
local utils_advanced = require "utils_advanced"

-- 共享内存
local limit_dict = ngx.shared.safeline_limit
local cache_dict = ngx.shared.safeline_cache
local config_dict = ngx.shared.safeline_config

-- 行为模式分析
local function analyze_behavior_pattern(client_ip)
    local key_prefix = "behavior:" .. client_ip
    local now = ngx.time()
    
    -- 获取配置
    local config_json = config_dict:get("behavior_analysis") or '{}'
    local config = cjson.decode(config_json)
    
    local window_size = config.window_size or 60  -- 60秒窗口
    local min_requests = config.min_requests or 10  -- 最少请求数
    
    -- 获取当前行为数据
    local requests_key = key_prefix .. ":requests"
    local methods_key = key_prefix .. ":methods"
    local paths_key = key_prefix .. ":paths"
    local intervals_key = key_prefix .. ":intervals"
    local last_time_key = key_prefix .. ":last_time"
    
    -- 递增请求计数
    local requests = limit_dict:incr(requests_key, 1, 0, window_size)
    
    -- 记录HTTP方法分布
    local method = ngx.req.get_method()
    local methods_json = cache_dict:get(methods_key) or '{}'
    local methods = cjson.decode(methods_json)
    methods[method] = (methods[method] or 0) + 1
    cache_dict:set(methods_key, cjson.encode(methods), window_size)
    
    -- 记录路径分布
    local uri = ngx.var.uri
    local paths_json = cache_dict:get(paths_key) or '{}'
    local paths = cjson.decode(paths_json)
    paths[uri] = (paths[uri] or 0) + 1
    cache_dict:set(paths_key, cjson.encode(paths), window_size)
    
    -- 记录请求间隔
    local last_time = tonumber(cache_dict:get(last_time_key) or 0)
    if last_time > 0 then
        local interval = now - last_time
        local intervals_json = cache_dict:get(intervals_key) or '[]'
        local intervals = cjson.decode(intervals_json)
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
    local intervals = cjson.decode(intervals_json)
    
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
    local methods = cjson.decode(methods_json)
    
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
    local paths = cjson.decode(paths_json)
    
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
    local vector, features = utils_advanced.extract_request_features(client_ip, uri, method, args, headers)
    
    -- 检查是否是异常请求
    local is_anomalous, distance = utils_advanced.is_anomalous_request(vector, 5.0)
    
    -- 检查参数异常
    local is_random_params, param_score = utils_advanced.detect_random_params_attack(args, headers, method)
    
    -- 检查自动化工具签名
    local is_automation, auto_confidence, signs = utils_advanced.detect_automation_signature(headers, uri, method)
    
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
        utils_advanced.record_anomaly(client_ip, uri, table.concat(reasons, ","), total_score)
    end
    
    return total_score
end

-- URL级DDoS防护 (增强版)
function _M.check_url_ddos(client_ip, uri)
    -- 获取配置
    local config_json = config_dict:get("ddos_protection") or '{}'
    local config = cjson.decode(config_json)
    
    -- 默认配置
    local url_threshold = config.url_threshold or 60  -- 单个URL的请求阈值
    local url_window = config.url_window or 60       -- 时间窗口(秒)
    local ip_threshold = config.ip_threshold or 300  -- 单个IP的总请求阈值
    local ip_window = config.ip_window or 60         -- IP时间窗口(秒)
    local dynamic_scaling = config.dynamic_scaling or true  -- 是否启用动态扩展
    
    -- 对URL进行规范化处理，忽略查询参数
    local base_uri = uri:match("^([^?]+)")
    
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
    local url_key = "ddos:url:" .. normalized_uri .. ":" .. client_ip
    local ip_key = "ddos:ip:" .. client_ip
    local global_key = "ddos:global:" .. normalized_uri
    
    -- 增加计数
    local url_count = limit_dict:incr(url_key, 1, 0, url_window)
    local ip_count = limit_dict:incr(ip_key, 1, 0, ip_window)
    local global_count = limit_dict:incr(global_key, 1, 0, url_window)
    
    -- 动态调整阈值
    local url_limit = url_threshold
    local ip_limit = ip_threshold
    
    if dynamic_scaling then
        -- 根据全局URL请求量调整单个IP的URL阈值
        if global_count > 1000 then  -- 热门URL
            url_limit = url_threshold * 2  -- 提高限制
        elseif global_count < 10 then  -- 冷门URL
            url_limit = url_threshold / 2  -- 降低限制
        end
        
        -- 如果检测到随机参数，降低阈值
        if has_random_params then
            url_limit = url_limit / 2
            ip_limit = ip_limit / 2
        end
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
    end
    
    -- 检查是否超过阈值
    if url_count > url_limit then
        -- URL级别限制触发
        ngx.log(ngx.WARN, "URL level DDoS detected for " .. normalized_uri .. 
                         " from " .. client_ip .. " (" .. url_count .. "/" .. url_limit .. ")")
        
        -- 记录异常
        utils_advanced.record_anomaly(client_ip, uri, "url_ddos", 5)
        
        return true, "url_limit", url_count, url_limit
    end
    
    if ip_count > ip_limit then
        -- IP级别限制触发
        ngx.log(ngx.WARN, "IP level DDoS detected from " .. client_ip .. 
                         " (" .. ip_count .. "/" .. ip_limit .. ")")
        
        -- 记录异常
        utils_advanced.record_anomaly(client_ip, uri, "ip_ddos", 4)
        
        return true, "ip_limit", ip_count, ip_limit
    end
    
    -- 即使未超过硬性阈值，如果行为和特征异常分数很高，也认为是攻击
    if combined_score >= 8 then
        ngx.log(ngx.WARN, "Behavioral DDoS detected from " .. client_ip .. 
                         " with score " .. combined_score)
        
        -- 记录异常
        utils_advanced.record_anomaly(client_ip, uri, "behavioral_ddos", combined_score)
        
        return true, "behavioral", combined_score, 8
    end
    
    return false
end

-- 检查慢速DDoS攻击
function _M.check_slow_ddos(client_ip)
    -- 获取配置
    local config_json = config_dict:get("slow_ddos") or '{}'
    local config = cjson.decode(config_json)
    
    -- 默认配置
    local connection_threshold = config.connection_threshold or 10
    local window = config.window or 60
    
    -- 增加连接计数
    local conn_key = "ddos:conn:" .. client_ip
    local conn_count = limit_dict:incr(conn_key, 1, 0, window)
    
    -- 检查连接数是否过多
    if conn_count > connection_threshold then
        return true, conn_count
    end
    
    return false, conn_count
end

-- 防止随机请求方法和查询字符串攻击
function _M.check_random_requests(client_ip)
    -- 获取当前请求信息
    local method = ngx.req.get_method()
    local uri = ngx.var.uri
    local args = ngx.req.get_uri_args()
    
    -- 保存最近的请求方法历史
    local method_key = "methods:" .. client_ip
    local methods_json = cache_dict:get(method_key) or '[]'
    local methods = cjson.decode(methods_json)
    
    -- 更新方法历史
    table.insert(methods, 1, method)
    if #methods > 10 then
        table.remove(methods, 11)
    end
    
    cache_dict:set(method_key, cjson.encode(methods), 300)
    
    -- 保存最近的URI历史
    local uri_key = "uris:" .. client_ip
    local uris_json = cache_dict:get(uri_key) or '[]'
    local uris = cjson.decode(uris_json)
    
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
        
        -- 如果5个请求中访问了5个不同的URI，且都包含查询参数，可能是随机路径攻击
        local unique_count = 0
        for _ in pairs(unique_uris) do
            unique_count = unique_count + 1
        end
        
        if unique_count >= 5 then
            -- 检查是否都包含查询参数
            local all_have_args = true
            
            for i = 1, 5 do
                if not uris[i]:find("?") then
                    all_have_args = false
                    break
                end
            end
            
            if all_have_args then
                return true, "random_paths_with_args"
            end
        end
    end
    
    -- 检查当前请求参数的随机性
    if args and type(args) == "table" then
        local param_count = 0
        for _ in pairs(args) do
            param_count = param_count + 1
        end
        
        -- 如果参数数量大于5，检查参数名和值的特征
        if param_count > 5 then
            local random_param_names = 0
            local random_param_values = 0
            
            for name, value in pairs(args) do
                -- 检查参数名是否看起来是随机生成的
                if #name >= 6 and name:match("[a-zA-Z0-9]") and name:match("[^a-zA-Z0-9_]") then
                    random_param_names = random_param_names + 1
                end
                
                -- 检查参数值是否看起来是随机生成的
                if type(value) == "string" and #value >= 8 and 
                   value:match("[a-zA-Z0-9]") and 
                   not value:match("^%d+$") and not value:match("^[a-fA-F0-9%-]+$") then
                    random_param_values = random_param_values + 1
                end
            end
            
            -- 如果超过50%的参数名或值看起来是随机的，可能是随机参数攻击
            if (random_param_names / param_count) > 0.5 or (random_param_values / param_count) > 0.5 then
                return true, "random_parameters"
            end
        end
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
    stats.method_distribution = cjson.decode(methods_json)
    
    -- 获取状态码分布
    local status_key = "stats:status:" .. client_ip
    local status_json = cache_dict:get(status_key) or '{}'
    stats.status_distribution = cjson.decode(status_json)
    
    -- 获取URL分布
    local urls_key = "stats:urls:" .. client_ip
    local urls_json = cache_dict:get(urls_key) or '{}'
    stats.url_distribution = cjson.decode(urls_json)
    
    -- 获取间隔统计
    local interval_key = "stats:intervals:" .. client_ip
    local interval_json = cache_dict:get(interval_key) or '{}'
    stats.interval_statistics = cjson.decode(interval_json)
    
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
    local methods = cjson.decode(methods_json)
    
    methods[method] = (methods[method] or 0) + 1
    cache_dict:set(methods_key, cjson.encode(methods), 600)
    
    -- 更新状态码分布
    local status_key = "stats:status:" .. client_ip
    local status_json = cache_dict:get(status_key) or '{}'
    local statuses = cjson.decode(status_json)
    
    statuses[tostring(status)] = (statuses[tostring(status)] or 0) + 1
    cache_dict:set(status_key, cjson.encode(statuses), 600)
    
    -- 更新URL分布
    local urls_key = "stats:urls:" .. client_ip
    local urls_json = cache_dict:get(urls_key) or '{}'
    local urls = cjson.decode(urls_json)
    
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
        local intervals = cjson.decode(intervals_json)
        
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
