local _M = {}

-- 引入模块
local cjson = require "cjson"

-- 共享内存
local blacklist_dict = ngx.shared.safeline_blacklist
local config_dict = ngx.shared.safeline_config

-- 检查IP是否在黑名单中
function _M.is_blacklisted(ip)
    -- 直接查找IP
    if blacklist_dict:get(ip) then
        return true
    end
    
    -- 检查IP范围
    local ranges_json = config_dict:get("ip_ranges")
    if ranges_json then
        local success, ranges = pcall(cjson.decode, ranges_json)
        if success then
            -- 将IP转换为数字
            local ip_num = _M.ip_to_number(ip)
            if not ip_num then
                return false
            end
            
            -- 检查所有IP范围
            for _, range in ipairs(ranges) do
                if ip_num >= range.start and ip_num <= range.end_ip then
                    return true
                end
            end
        end
    end
    
    return false
end

-- 添加IP到黑名单
function _M.add_to_blacklist(ip, expiry)
    expiry = expiry or 86400 -- 默认1天
    return blacklist_dict:set(ip, true, expiry)
end

-- 从黑名单中移除IP
function _M.remove_from_blacklist(ip)
    return blacklist_dict:delete(ip)
end

-- 添加IP范围到黑名单
function _M.add_range_to_blacklist(start_ip, end_ip)
    local ranges_json = config_dict:get("ip_ranges") or "[]"
    local success, ranges = pcall(cjson.decode, ranges_json)
    
    if not success then
        ranges = {}
    end
    
    -- 转换IP为数字
    local start_num = _M.ip_to_number(start_ip)
    local end_num = _M.ip_to_number(end_ip)
    
    if not start_num or not end_num then
        return false, "Invalid IP address"
    end
    
    -- 确保开始IP小于结束IP
    if start_num > end_num then
        start_num, end_num = end_num, start_num
    end
    
    -- 添加新范围
    table.insert(ranges, {
        start = start_num,
        end_ip = end_num,
        start_ip = start_ip,
        end_ip = end_ip
    })
    
    -- 更新配置
    return config_dict:set("ip_ranges", cjson.encode(ranges))
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
    local keys = blacklist_dict:get_keys(0) -- 获取所有键
    local result = {}
    
    for _, key in ipairs(keys) do
        local ttl = blacklist_dict:ttl(key)
        if ttl > 0 then
            table.insert(result, {
                ip = key,
                expires_in = ttl
            })
        end
    end
    
    -- 获取IP范围
    local ranges_json = config_dict:get("ip_ranges")
    if ranges_json then
        local success, ranges = pcall(cjson.decode, ranges_json)
        if success then
            for _, range in ipairs(ranges) do
                table.insert(result, {
                    start_ip = range.start_ip,
                    end_ip = range.end_ip,
                    range = true
                })
            end
        end
    end
    
    return result
end

-- 清空全部黑名单
function _M.clear_blacklist()
    -- 清空单个IP黑名单
    blacklist_dict:flush_all()
    
    -- 清空IP范围黑名单
    config_dict:set("ip_ranges", "[]")
    
    return true
end

return _M
