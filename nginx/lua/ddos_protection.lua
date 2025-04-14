local _M = {}

-- 引入需要的模块
local cjson = require "cjson"

-- 共享内存
local limit_dict = ngx.shared.safeline_limit
local cache_dict = ngx.shared.safeline_cache
local config_dict = ngx.shared.safeline_config

-- URL级DDoS检测
function _M.check_url_ddos(uri, client_ip)
    -- 获取配置
    local config_json = config_dict:get("ddos_protection")
    local config = {}
    
    if config_json then
        local success, parsed_config = pcall(cjson.decode, config_json)
        if success then
            config = parsed_config
        end
    end
    
    -- 默认配置
    local request_threshold = config.request_threshold or 30    -- 30秒内
    local time_window = config.time_window or 60               -- 60秒
    local url_threshold = config.url_threshold or 20           -- 对同一URL的请求
    local burst_threshold = config.burst_threshold or 15       -- 突发阈值
    
    -- 检查总体请求速率
    local ip_rate_key = "ip_rate:" .. client_ip
    local current_rate = limit_dict:incr(ip_rate_key, 1, 0, time_window)
    
    if current_rate > request_threshold then
        -- 检查URL特定请求速率
        local url_rate_key = "url_rate:" .. client_ip .. ":" .. uri
        local url_rate = limit_dict:incr(url_rate_key, 1, 0, time_window)
        
        if url_rate > url_threshold then
            -- 检测到URL级DDoS尝试
            return true
        end
    end
    
    -- 检查突发请求
    local now = ngx.time()
    local burst_key = "burst:" .. client_ip
    local last_time = tonumber(cache_dict:get(burst_key)) or 0
    
    if now - last_time <= 1 and current_rate > burst_threshold then
        -- 检测到突发请求
        return true
    end
    
    cache_dict:set(burst_key, now, 10) -- 更新最后请求时间
    
    -- 检查随机查询参数和不同请求方法
    if _M.check_random_params_and_methods(client_ip, uri) then
        return true
    end
    
    return false
end

-- 检查随机查询参数和请求方法变化
function _M.check_random_params_and_methods(client_ip, uri)
    -- 获取请求信息
    local method = ngx.req.get_method()
    local args = ngx.req.get_uri_args()
    
    -- 计算查询参数数量
    local param_count = 0
    for _ in pairs(args) do
        param_count = param_count + 1
    end
    
    -- 随机参数指纹
    local param_keys = {}
    for k, _ in pairs(args) do
        table.insert(param_keys, k)
    end
    table.sort(param_keys)
    local param_signature = table.concat(param_keys, ",")
    
    -- 存储最近的参数模式
    local params_key = "params:" .. client_ip .. ":" .. uri
    local methods_key = "methods:" .. client_ip .. ":" .. uri
    
    -- 获取历史数据
    local param_patterns = cache_dict:get(params_key)
    local method_patterns = cache_dict:get(methods_key)
    
    local param_pattern_list = {}
    local method_pattern_list = {}
    
    if param_patterns then
        local success, patterns = pcall(cjson.decode, param_patterns)
        if success then
            param_pattern_list = patterns
        end
    end
    
    if method_patterns then
        local success, patterns = pcall(cjson.decode, method_patterns)
        if success then
            method_pattern_list = patterns
        end
    end
    
    -- 添加当前模式
    local found_param = false
    for _, p in ipairs(param_pattern_list) do
        if p == param_signature then
            found_param = true
            break
        end
    end
    
    if not found_param then
        table.insert(param_pattern_list, param_signature)
    end
    
    local found_method = false
    for _, m in ipairs(method_pattern_list) do
        if m == method then
            found_method = true
            break
        end
    end
    
    if not found_method then
        table.insert(method_pattern_list, method)
    end
    
    -- 更新缓存
    cache_dict:set(params_key, cjson.encode(param_pattern_list), 300)  -- 5分钟
    cache_dict:set(methods_key, cjson.encode(method_pattern_list), 300) -- 5分钟
    
    -- 检测随机参数攻击
    if #param_pattern_list > 5 and param_count > 2 then
        return true
    end
    
    -- 检测请求方法变化
    if #method_pattern_list > 3 then
        return true
    end
    
    return false
end

-- CC攻击检测
function _M.check_cc_attack(client_ip, uri)
    -- 获取配置
    local config_json = config_dict:get("anti_cc")
    local config = {}
    
    if config_json then
        local success, parsed_config = pcall(cjson.decode, config_json)
        if success then
            config = parsed_config
        end
    end
    
    -- 默认配置
    local cc_threshold = config.cc_threshold or 60       -- 60秒内
    local cc_time_window = config.cc_time_window or 60   -- 60秒窗口
    local cc_request_count = config.cc_request_count or 60 -- 60次请求
    
    -- 检查请求速率
    local cc_key = "cc:" .. client_ip
    local req_count = limit_dict:incr(cc_key, 1, 0, cc_time_window)
    
    if req_count > cc_request_count then
        -- 检测URL模式
        local url_pattern_key = "url_pattern:" .. client_ip
        local url_patterns = cache_dict:get(url_pattern_key)
        
        local pattern_list = {}
        if url_patterns then
            local success, patterns = pcall(cjson.decode, url_patterns)
            if success then
                pattern_list = patterns
            end
        end
        
        -- 添加当前URI
        local found = false
        for _, p in ipairs(pattern_list) do
            if p == uri then
                found = true
                break
            end
        end
        
        if not found then
            table.insert(pattern_list, uri)
            cache_dict:set(url_pattern_key, cjson.encode(pattern_list), cc_time_window)
        end
        
        -- 如果短时间内访问多个不同URL，可能是CC攻击
        if #pattern_list > 10 then
            return true
        end
        
        -- 如果单一URL请求过多，也可能是CC攻击
        local uri_key = "uri_count:" .. client_ip .. ":" .. uri
        local uri_count = limit_dict:incr(uri_key, 1, 0, cc_time_window)
        
        if uri_count > cc_threshold then
            return true
        end
    end
    
    return false
end

-- 流量动态识别
function _M.analyze_traffic_pattern()
    -- 这里可以实现更复杂的流量分析算法
    -- 例如，基于请求间隔、请求分布、请求特征等
    
    -- 示例实现：检查请求间隔的规律性
    local client_ip = ngx.var.remote_addr
    local now = ngx.now() -- 精确到毫秒
    
    local interval_key = "req_intervals:" .. client_ip
    local last_time = cache_dict:get(interval_key)
    
    if last_time then
        local interval = now - tonumber(last_time)
        local intervals_key = "intervals:" .. client_ip
        local intervals_json = cache_dict:get(intervals_key) or "[]"
        
        local success, intervals = pcall(cjson.decode, intervals_json)
        if not success then
            intervals = {}
        end
        
        -- 保存最近10次请求的间隔
        table.insert(intervals, interval)
        if #intervals > 10 then
            table.remove(intervals, 1)
        end
        
        cache_dict:set(intervals_key, cjson.encode(intervals), 300)
        
        -- 检查间隔的规律性
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
            
            -- 如果标准差很小，说明请求间隔很规律，可能是机器人
            if std_dev < 0.1 and mean < 2 then
                return true
            end
        end
    end
    
    cache_dict:set(interval_key, now, 300)
    return false
end

return _M
