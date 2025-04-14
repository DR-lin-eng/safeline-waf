local _M = {}

-- 引入模块
local resty_sha256 = require "resty.sha256"
local str = require "resty.string"
local cjson = require "cjson"

-- 共享内存
local cache_dict = ngx.shared.safeline_cache
local config_dict = ngx.shared.safeline_config

-- 生成随机字符串
local function random_string(length)
    local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local str = ""
    for i = 1, length do
        local rand = math.random(1, #chars)
        str = str .. string.sub(chars, rand, rand)
    end
    return str
end

-- 生成POW挑战
function _M.generate_challenge(client_ip, uri, difficulty)
    -- 如果没有指定难度，使用默认值
    if not difficulty then
        local config_json = config_dict:get("pow_config")
        local config = {
            base_difficulty = 4,
            max_difficulty = 8
        }
        
        if config_json then
            local success, parsed_config = pcall(cjson.decode, config_json)
            if success then
                config = parsed_config
            end
        end
        
        difficulty = config.base_difficulty
        
        -- 根据客户端请求频率动态调整难度
        local rate_key = "pow_rate:" .. client_ip
        local req_count = cache_dict:incr(rate_key, 1, 0, 300) -- 5分钟窗口
        
        if req_count > 10 then
            -- 随着请求次数增加，逐渐增加难度
            local added_difficulty = math.floor(req_count / 10)
            difficulty = math.min(config.max_difficulty, difficulty + added_difficulty)
        end
    end
    
    -- 生成挑战数据
    local challenge = {
        prefix = random_string(16),
        difficulty = difficulty,
        expires = ngx.time() + 300, -- 5分钟有效期
        uri = uri
    }
    
    -- 保存挑战到缓存
    local challenge_key = "pow_challenge:" .. client_ip
    cache_dict:set(challenge_key, cjson.encode(challenge), 300)
    
    return challenge
end

-- 验证POW解答
function _M.verify_solution(client_ip, prefix, nonce)
    -- 获取挑战
    local challenge_key = "pow_challenge:" .. client_ip
    local challenge_json = cache_dict:get(challenge_key)
    
    if not challenge_json then
        return false, "Challenge not found or expired"
    end
    
    local success, challenge = pcall(cjson.decode, challenge_json)
    if not success then
        return false, "Invalid challenge data"
    end
    
    -- 检查挑战是否过期
    if challenge.expires < ngx.time() then
        return false, "Challenge expired"
    end
    
    -- 检查前缀是否匹配
    if challenge.prefix ~= prefix then
        return false, "Prefix mismatch"
    end
    
    -- 验证工作量证明
    local sha256 = resty_sha256:new()
    local input = prefix .. nonce
    sha256:update(input)
    local hash = str.to_hex(sha256:final())
    
    -- 检查哈希值是否满足难度要求
    -- 难度N表示哈希前N位必须为0
    local difficulty = challenge.difficulty
    local pattern = "^" .. string.rep("0", difficulty)
    
    if not hash:match(pattern) then
        return false, "Invalid solution"
    end
    
    -- 标记该IP已完成POW验证
    local verified_key = "pow_verified:" .. client_ip
    cache_dict:set(verified_key, true, 1800) -- 30分钟内有效
    
    -- 如果是特定URI的验证，也标记该URI
    if challenge.uri then
        local uri_key = "pow_uri:" .. client_ip .. ":" .. challenge.uri
        cache_dict:set(uri_key, true, 1800)
    end
    
    -- 清除挑战
    cache_dict:delete(challenge_key)
    
    return true, "Verification successful"
end

-- 检查客户端是否已通过POW验证
function _M.is_verified(client_ip, uri)
    -- 检查全局验证
    local verified_key = "pow_verified:" .. client_ip
    local verified = cache_dict:get(verified_key)
    
    if verified then
        return true
    end
    
    -- 检查特定URI验证
    if uri then
        local uri_key = "pow_uri:" .. client_ip .. ":" .. uri
        local uri_verified = cache_dict:get(uri_key)
        
        if uri_verified then
            return true
        end
    end
    
    return false
end

-- 生成客户端POW计算脚本
function _M.get_pow_script(challenge)
    -- 返回JavaScript代码，用于在客户端执行POW计算
    local js_code = [[
function sha256(str) {
    // 使用SubtleCrypto API计算SHA-256
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(str))
        .then(buffer => {
            return Array.from(new Uint8Array(buffer))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        });
}

async function findPowSolution(prefix, difficulty) {
    const pattern = new RegExp('^' + '0'.repeat(difficulty));
    let nonce = 0;
    let hash;
    
    // 显示计算进度
    const statusElement = document.getElementById('pow-status');
    if (statusElement) {
        statusElement.innerText = 'Computing proof of work...';
    }
    
    // 每1000次计算更新一次UI
    const updateInterval = 1000;
    let lastUpdate = Date.now();
    
    while (true) {
        hash = await sha256(prefix + nonce);
        if (pattern.test(hash)) {
            return nonce.toString();
        }
        
        nonce++;
        
        // 更新UI
        const now = Date.now();
        if (now - lastUpdate > 100) { // 每100ms更新一次
            if (statusElement) {
                statusElement.innerText = `Computing proof of work... (${nonce} attempts)`;
            }
            // 给UI线程一些时间更新
            await new Promise(resolve => setTimeout(resolve, 0));
            lastUpdate = now;
        }
    }
}
    ]]
    
    return js_code
end

return _M
