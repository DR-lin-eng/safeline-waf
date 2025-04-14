local _M = {}

-- 引入模块
local cjson = require "cjson"
local encode_base64 = ngx.encode_base64
local decode_base64 = ngx.decode_base64

-- 加密密钥和初始向量 (在实际应用中应当安全存储)
local DEFAULT_KEY = "SafeLineWAF2025!"
local DEFAULT_IV = "SafeLineWAF2025!"

-- 简单的XOR加密
local function xor_encrypt(text, key)
    local result = {}
    for i = 1, #text do
        local byte = string.byte(text, i)
        local key_byte = string.byte(key, (i - 1) % #key + 1)
        table.insert(result, string.char(bit.bxor(byte, key_byte)))
    end
    return table.concat(result)
end

-- 简单的XOR解密 (与加密相同)
local function xor_decrypt(text, key)
    return xor_encrypt(text, key)
end

-- 加密令牌 (JSON数据)
function _M.encrypt_token(data)
    -- 将数据转换为JSON
    local json_data = cjson.encode(data)
    
    -- 加密JSON数据
    local encrypted = xor_encrypt(json_data, DEFAULT_KEY)
    
    -- Base64编码
    local base64_encrypted = encode_base64(encrypted)
    
    -- 替换可能在URL中引起问题的字符
    base64_encrypted = base64_encrypted:gsub("%+", "-"):gsub("/", "_"):gsub("=", "")
    
    return base64_encrypted
end

-- 解密令牌
function _M.decrypt_token(token)
    -- 恢复可能被替换的字符
    token = token:gsub("-", "+"):gsub("_", "/")
    
    -- 添加可能缺失的填充字符
    local padding = 4 - ((#token % 4) > 0 and #token % 4 or 4)
    token = token .. string.rep("=", padding)
    
    -- Base64解码
    local decoded = decode_base64(token)
    
    if not decoded then
        return nil
    end
    
    -- 解密数据
    local decrypted = xor_decrypt(decoded, DEFAULT_KEY)
    
    -- 解析JSON数据
    local success, data = pcall(cjson.decode, decrypted)
    
    if not success then
        return nil
    end
    
    return data
end

-- 检查CIDR IP范围
function _M.is_ip_in_cidr(ip, cidr)
    local function ip_to_binary(ip_addr)
        local binary = ""
        for part in ip_addr:gmatch("%d+") do
            binary = binary .. string.format("%08d", tonumber(string.format("%b", part)))
        end
        return binary
    end
    
    -- 分割CIDR
    local network_ip, prefix = cidr:match("([^/]+)/(%d+)")
    prefix = tonumber(prefix)
    
    if not network_ip or not prefix then
        return false
    end
    
    -- 转换为二进制
    local ip_binary = ip_to_binary(ip)
    local network_binary = ip_to_binary(network_ip)
    
    -- 比较前缀位
    return ip_binary:sub(1, prefix) == network_binary:sub(1, prefix)
end

-- 检查是否是有效的IPv4地址
function _M.is_valid_ipv4(ip)
    if not ip then
        return false
    end
    
    -- 检查IPv4格式
    local chunks = {ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")}
    
    if #chunks ~= 4 then
        return false
    end
    
    for _, v in pairs(chunks) do
        local num = tonumber(v)
        if not num or num < 0 or num > 255 then
            return false
        end
    end
    
    return true
end

-- 获取客户端真实IP地址
function _M.get_client_ip()
    local headers = ngx.req.get_headers()
    
    -- 检查常见的代理头
    local ip = headers["X-Forwarded-For"] or 
               headers["X-Real-IP"] or 
               headers["CF-Connecting-IP"] or
               ngx.var.remote_addr
    
    -- 如果是X-Forwarded-For，取第一个IP
    if headers["X-Forwarded-For"] then
        ip = string.match(ip, "^[^,]+")
    end
    
    return ip
end

-- 随机字符串生成
function _M.random_string(length)
    local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local str = ""
    for i = 1, length do
        local rand = math.random(1, #chars)
        str = str .. string.sub(chars, rand, rand)
    end
    return str
end

-- 记录日志到Redis
function _M.log_event(event_type, data)
    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeout(1000) -- 1秒超时
    
    local ok, err = red:connect("redis", 6379)
    if not ok then
        ngx.log(ngx.ERR, "Failed to connect to Redis: " .. tostring(err))
        return false
    end
    
    -- 创建日志事件
    local event = {
        type = event_type,
        timestamp = ngx.time(),
        client_ip = ngx.var.remote_addr,
        user_agent = ngx.var.http_user_agent or "",
        uri = ngx.var.uri,
        host = ngx.var.host,
        data = data
    }
    
    -- 将事件添加到Redis列表
    local json_event = cjson.encode(event)
    local res, err = red:lpush("safeline:logs", json_event)
    
    if not res then
        ngx.log(ngx.ERR, "Failed to push log to Redis: " .. tostring(err))
        return false
    end
    
    -- 保持日志列表在合理大小
    red:ltrim("safeline:logs", 0, 9999) -- 保留最近10000条日志
    
    -- 将连接放回连接池
    red:set_keepalive(10000, 100)
    
    return true
end

-- 判断请求是否为静态资源
function _M.is_static_resource(uri)
    if not uri then
        return false
    end
    
    local extensions = {
        ".js", ".css", ".jpg", ".jpeg", ".png", ".gif",
        ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot"
    }
    
    for _, ext in ipairs(extensions) do
        if uri:sub(-#ext) == ext then
            return true
        end
    end
    
    return false
end

-- 检查请求是否来自搜索引擎
function _M.is_search_engine(user_agent)
    if not user_agent then
        return false
    end
    
    local search_engines = {
        "Googlebot", "Bingbot", "Slurp", "DuckDuckBot", "Baiduspider",
        "YandexBot", "Sogou", "Exabot", "facebot", "ia_archiver"
    }
    
    for _, bot in ipairs(search_engines) do
        if user_agent:find(bot) then
            return true
        end
    end
    
    return false
end

return _M
