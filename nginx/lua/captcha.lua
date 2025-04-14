local _M = {}

-- 引入模块
local cjson = require "cjson"
local utils = require "utils"
local pow = require "pow"

-- 共享内存
local cache_dict = ngx.shared.safeline_cache

-- 生成随机验证码
local function generate_captcha_code()
    local chars = "2345678abcdefhijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
    local code = ""
    for i = 1, 6 do
        local rand = math.random(1, #chars)
        code = code .. string.sub(chars, rand, rand)
    end
    return code
end

-- 处理验证码API请求
local function handle_captcha_api()
    local uri = ngx.var.uri
    local client_ip = ngx.var.remote_addr
    
    -- 处理验证码图片请求
    if uri == "/safeline-api/captcha/image" then
        -- 生成验证码
        local captcha_code = generate_captcha_code()
        
        -- 保存验证码到缓存
        local captcha_key = "captcha:" .. client_ip
        cache_dict:set(captcha_key, captcha_code, 300) -- 5分钟有效期
        
        -- 设置响应头
        ngx.header.content_type = "text/plain"
        
        -- 这里简化处理，实际应生成图片
        -- 返回验证码文本（实际应用中，应返回图片数据）
        ngx.say("CAPTCHA: " .. captcha_code)
        
        return ngx.exit(ngx.OK)
    
    -- 处理验证码验证请求
    elseif uri == "/safeline-api/captcha/verify" then
        -- 读取POST参数
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()
        
        if not args then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({success = false, message = "Invalid request"}))
            return ngx.exit(ngx.OK)
        end
        
        local user_code = args.code
        local token = args.token
        
        -- 验证参数
        if not user_code or not token then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({success = false, message = "Missing parameters"}))
            return ngx.exit(ngx.OK)
        end
        
        -- 验证token
        local token_data = utils.decrypt_token(token)
        if not token_data or not token_data.original_url then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({success = false, message = "Invalid token"}))
            return ngx.exit(ngx.OK)
        end
        
        -- 获取缓存中的验证码
        local captcha_key = "captcha:" .. client_ip
        local stored_code = cache_dict:get(captcha_key)
        
        if not stored_code then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({success = false, message = "Captcha expired"}))
            return ngx.exit(ngx.OK)
        end
        
        -- 验证码不区分大小写
        if string.lower(user_code) == string.lower(stored_code) then
            -- 验证成功，生成验证通过的token
            local verified_token = {
                original_url = token_data.original_url,
                verified = true,
                expires = ngx.time() + 1800 -- 30分钟有效期
            }
            
            local verified_token_str = utils.encrypt_token(verified_token)
            
            -- 清除验证码缓存
            cache_dict:delete(captcha_key)
            
            -- 记录验证成功
            local verified_key = "verified:" .. client_ip
            cache_dict:set(verified_key, true, 1800)
            
            -- 返回成功消息和重定向URL
            ngx.say(cjson.encode({
                success = true, 
                message = "Verification successful", 
                redirect_url = token_data.original_url,
                token = verified_token_str
            }))
        else
            -- 验证失败
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({success = false, message = "Invalid captcha code"}))
        end
        
        return ngx.exit(ngx.OK)
    
    -- 处理滑块验证请求
    elseif uri == "/safeline-api/slider/verify" then
        -- 读取POST参数
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()
        
        if not args then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({success = false, message = "Invalid request"}))
            return ngx.exit(ngx.OK)
        end
        
        local slider_position = tonumber(args.position)
        local token = args.token
        
        -- 验证参数
        if not slider_position or not token then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({success = false, message = "Missing parameters"}))
            return ngx.exit(ngx.OK)
        end
        
        -- 验证token
        local token_data = utils.decrypt_token(token)
        if not token_data or not token_data.original_url then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({success = false, message = "Invalid token"}))
            return ngx.exit(ngx.OK)
        end
        
        -- 获取缓存中的滑块位置
        local slider_key = "slider:" .. client_ip
        local expected_position = cache_dict:get(slider_key)
        
        if not expected_position then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({success = false, message = "Slider verification expired"}))
            return ngx.exit(ngx.OK)
        end
        
        expected_position = tonumber(expected_position)
        
        -- 验证滑块位置（允许一定误差）
        if math.abs(slider_position - expected_position) <= 5 then
            -- 验证成功，生成验证通过的token
            local verified_token = {
                original_url = token_data.original_url,
                verified = true,
                expires = ngx.time() + 1800 -- 30分钟有效期
            }
            
            local verified_token_str = utils.encrypt_token(verified_token)
            
            -- 清除滑块缓存
            cache_dict:delete(slider_key)
            
            -- 记录验证成功
            local verified_key = "verified:" .. client_ip
            cache_dict:set(verified_key, true, 1800)
            
            -- 返回成功消息和重定向URL
            ngx.say(cjson.encode({
                success = true, 
                message = "Verification successful", 
                redirect_url = token_data.original_url,
                token = verified_token_str
            }))
        else
            -- 验证失败
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({success = false, message = "Invalid slider position"}))
        end
        
        return ngx.exit(ngx.OK)
    
    -- 处理POW验证请求
    elseif uri == "/safeline-api/pow/verify" then
        -- 读取POST参数
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()
        
        if not args then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({success = false, message = "Invalid request"}))
            return ngx.exit(ngx.OK)
        end
        
        local prefix = args.prefix
        local nonce = args.nonce
        local token = args.token
        
        -- 验证参数
        if not prefix or not nonce or not token then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({success = false, message = "Missing parameters"}))
            return ngx.exit(ngx.OK)
        end
        
        -- 验证token
        local token_data = utils.decrypt_token(token)
        if not token_data or not token_data.original_url then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({success = false, message = "Invalid token"}))
            return ngx.exit(ngx.OK)
        end
        
        -- 验证POW
        local success, message = pow.verify_solution(client_ip, prefix, nonce)
        
        if success then
            -- 验证成功，生成验证通过的token
            local verified_token = {
                original_url = token_data.original_url,
                verified = true,
                expires = ngx.time() + 1800 -- 30分钟有效期
            }
            
            local verified_token_str = utils.encrypt_token(verified_token)
            
            -- 返回成功消息和重定向URL
            ngx.say(cjson.encode({
                success = true, 
                message = "Verification successful", 
                redirect_url = token_data.original_url,
                token = verified_token_str
            }))
        else
            -- 验证失败
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({success = false, message = message}))
        end
        
        return ngx.exit(ngx.OK)
    
    -- 获取POW挑战
    elseif uri == "/safeline-api/pow/challenge" then
        -- 从GET参数获取token
        local args = ngx.req.get_uri_args()
        local token = args.token
        
        if not token then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({success = false, message = "Missing token"}))
            return ngx.exit(ngx.OK)
        end
        
        -- 验证token
        local token_data = utils.decrypt_token(token)
        if not token_data or not token_data.original_url then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({success = false, message = "Invalid token"}))
            return ngx.exit(ngx.OK)
        end
        
        -- 获取原始URI
        local original_uri = ngx.re.match(token_data.original_url, "https?://[^/]+([^?]+)")
        local uri = original_uri and original_uri[1] or "/"
        
        -- 生成POW挑战
        local challenge = pow.generate_challenge(client_ip, uri)
        
        -- 返回挑战数据
        ngx.say(cjson.encode({
            success = true,
            prefix = challenge.prefix,
            difficulty = challenge.difficulty
        }))
        
        return ngx.exit(ngx.OK)
    
    -- 生成滑块验证数据
    elseif uri == "/safeline-api/slider/generate" then
        -- 生成随机滑块位置
        local position = math.random(20, 280)
        
        -- 保存预期位置到缓存
        local slider_key = "slider:" .. client_ip
        cache_dict:set(slider_key, position, 300) -- 5分钟有效期
        
        -- 返回滑块数据
        ngx.say(cjson.encode({
            success = true,
            position = position
        }))
        
        return ngx.exit(ngx.OK)
    end
    
    -- 未知API路径
    ngx.status = ngx.HTTP_NOT_FOUND
    ngx.say(cjson.encode({success = false, message = "API not found"}))
    return ngx.exit(ngx.OK)
end

-- 初始化验证页面处理
function _M.init()
    -- 初始化随机数种子
    math.randomseed(ngx.time())
end

-- 处理验证API请求的主函数
function _M.handle()
    handle_captcha_api()
end

return _M
