local _M = {}

-- 引入模块
local cjson = require "cjson"
local utils = require "utils"
local pow = require "pow"

-- 共享内存
local cache_dict = ngx.shared.safeline_cache
local limit_dict = ngx.shared.safeline_limit

local function read_request_body_json()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        local body_file = ngx.req.get_body_file()
        if body_file then
            local f = io.open(body_file, "rb")
            if f then
                body = f:read("*a")
                f:close()
            end
        end
    end

    if type(body) ~= "string" or body == "" then
        return nil
    end

    local ok, data = pcall(cjson.decode, body)
    if ok and type(data) == "table" then
        return data
    end

    return nil
end

local function build_cookie_attributes(original_url)
    local attrs = {
        "Path=/",
        "Max-Age=1800",
        "HttpOnly",
        "SameSite=Lax"
    }

    if type(original_url) == "string" and original_url:match("^https://") then
        table.insert(attrs, "Secure")
    elseif ngx.var.scheme == "https" then
        table.insert(attrs, "Secure")
    end

    return table.concat(attrs, "; ")
end

local function extract_url_scope(original_url)
    if type(original_url) ~= "string" or original_url == "" then
        return "", "/"
    end

    local m, err = ngx.re.match(original_url, [[^https?://([^/?#]+)(/[^?#]*)?]], "jo")
    if not m then
        return "", "/"
    end

    local host = (m[1] or ""):lower()
    local path = m[2] or "/"
    if path == "" then
        path = "/"
    end

    return host, path
end

local function get_step_up_verification_type(token_data)
    if type(token_data) ~= "table" then
        return "captcha"
    end

    if token_data.step_up_verification_type == "pow" then
        return "pow"
    end

    return "captcha"
end

local function ensure_token_verification_type(token_data, expected_type)
    if type(token_data) ~= "table" then
        return false, "Invalid token"
    end

    if type(expected_type) ~= "string" or expected_type == "" then
        return true
    end

    if token_data.verification_type ~= expected_type then
        return false, "Verification type mismatch"
    end

    return true
end

local function challenge_matches_token(stored_payload, token_data, client_ip, user_agent)
    if type(stored_payload) ~= "table" or type(token_data) ~= "table" then
        return false, "Invalid challenge context"
    end

    if stored_payload.ip and stored_payload.ip ~= client_ip then
        return false, "Challenge does not match client"
    end

    if stored_payload.ua_hash and stored_payload.ua_hash ~= ngx.md5(user_agent or "") then
        return false, "Challenge does not match client"
    end

    if stored_payload.host and stored_payload.host ~= token_data.host then
        return false, "Challenge context mismatch"
    end

    if stored_payload.path and stored_payload.path ~= token_data.path then
        return false, "Challenge context mismatch"
    end

    if stored_payload.reason and stored_payload.reason ~= token_data.reason then
        return false, "Challenge context mismatch"
    end

    if stored_payload.verification_type and stored_payload.verification_type ~= token_data.verification_type then
        return false, "Challenge context mismatch"
    end

    if stored_payload.method and stored_payload.method ~= token_data.method then
        return false, "Challenge context mismatch"
    end

    return true
end

local function issue_verified_response(token_data, client_ip, user_agent)
    local ttl = tonumber(token_data.grant_ttl or 1800) or 1800
    local verification_type = token_data.verification_type
    local max_ttl = 7200

    if verification_type == "slider" then
        max_ttl = 3600
    end

    if ttl < 60 then
        ttl = 60
    elseif ttl > max_ttl then
        ttl = max_ttl
    end

    local bindings = type(token_data.verification_bindings) == "table" and token_data.verification_bindings or {}
    local bind_ip = bindings.ip_address ~= false
    local bind_user_agent = bindings.user_agent ~= false

    local verified_token = {
        original_url = token_data.original_url,
        verified = true,
        ip = bind_ip and client_ip or nil,
        ua_hash = bind_user_agent and ngx.md5(user_agent or "") or nil,
        issued_at = ngx.time(),
        expires = ngx.time() + ttl,
        verification_type = token_data.verification_type,
        reason = token_data.reason,
        host = token_data.host,
        path = token_data.path,
        path_prefix = token_data.path_prefix,
        method = token_data.method,
        scope_mode = token_data.scope_mode,
        verification_bindings = {
            ip_address = bind_ip,
            user_agent = bind_user_agent
        }
    }
    local verified_token_str = utils.encrypt_token(verified_token)

    local verified_key = "verified:" .. client_ip
    cache_dict:set(verified_key, true, ttl)

    ngx.header["Set-Cookie"] =
        "safeline_verified=" .. verified_token_str .. "; " .. build_cookie_attributes(token_data.original_url)

    ngx.say(cjson.encode({
        success = true,
        message = "Verification successful",
        redirect_url = token_data.original_url,
        step_up_required = false
    }))
end

local function issue_step_up_response(token_data)
    local host = token_data.host or ""
    local path = token_data.path or "/"
    local method = token_data.method or "GET"
    local next_type = get_step_up_verification_type(token_data)
    local grant_ttl = tonumber(token_data.grant_ttl or 1800) or 1800
    local step_up_token = utils.encrypt_token({
        original_url = token_data.original_url,
        verification_type = next_type,
        reason = token_data.reason,
        difficulty = token_data.difficulty,
        host = host,
        path = path,
        method = method,
        scope_mode = "path_exact",
        verification_bindings = token_data.verification_bindings,
        grant_ttl = grant_ttl,
        step_up_required = false,
        expires = ngx.time() + 900
    })

    ngx.say(cjson.encode({
        success = true,
        message = "Step-up verification required",
        step_up_required = true,
        step_up_verification_type = next_type,
        step_up_token = step_up_token,
        redirect_url = "/safeline-static/verify.html?token=" .. ngx.escape_uri(step_up_token)
    }))
end

local function reserve_single_use_key(key, ttl)
    local ok, err = cache_dict:add(key, true, ttl)
    if ok then
        return true
    end

    if err == "exists" then
        return false, "already_used"
    end

    return false, err or "reserve_failed"
end

-- 生成随机验证码 (排除易混淆字符)
local function generate_captcha_code()
    local chars = "2345678abcdefhijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
    local code = ""
    for i = 1, 6 do
        local rand = math.random(1, #chars)
        code = code .. string.sub(chars, rand, rand)
    end
    return code
end

-- 生成验证码SVG图片（不暴露明文）
local function generate_captcha_svg(code)
    local chars = {}
    for i = 1, #code do
        chars[i] = code:sub(i, i)
    end

    local width = 200
    local height = 80
    local parts = {
        string.format('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d">', width, height),
        string.format('<rect width="%d" height="%d" fill="#f0f2f5"/>', width, height),
    }

    -- 干扰线
    for i = 1, 6 do
        local x1 = math.random(0, width)
        local y1 = math.random(0, height)
        local x2 = math.random(0, width)
        local y2 = math.random(0, height)
        parts[#parts + 1] = string.format(
            '<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="rgb(%d,%d,%d)" stroke-width="1.5" opacity="0.6"/>',
            x1, y1, x2, y2,
            math.random(80, 180), math.random(80, 180), math.random(80, 180)
        )
    end

    -- 字符（带旋转和随机色）
    local colors = { "#1a1a2e", "#0f3460", "#533483", "#1b4332", "#7b2d8b" }
    for i, ch in ipairs(chars) do
        local x = 18 + (i - 1) * 28 + math.random(-2, 2)
        local y = 50 + math.random(-6, 6)
        local rotate = math.random(-18, 18)
        local color = colors[math.random(1, #colors)]
        local size = math.random(22, 28)
        parts[#parts + 1] = string.format(
            '<text x="%d" y="%d" transform="rotate(%d,%d,%d)" fill="%s" font-size="%d"'
            .. ' font-family="Courier New,monospace" font-weight="bold">%s</text>',
            x, y, rotate, x, y, color, size, ch
        )
    end

    -- 干扰点
    for i = 1, 25 do
        parts[#parts + 1] = string.format(
            '<circle cx="%d" cy="%d" r="2" fill="rgb(%d,%d,%d)" opacity="0.5"/>',
            math.random(0, width), math.random(0, height),
            math.random(80, 180), math.random(80, 180), math.random(80, 180)
        )
    end

    parts[#parts + 1] = '</svg>'
    return table.concat(parts, '')
end

-- 生成不可预测的挑战ID
local function generate_challenge_id()
    local ok_random, resty_random = pcall(require, "resty.random")
    local ok_string, resty_string = pcall(require, "resty.string")

    if ok_random and ok_string then
        local bytes = resty_random.bytes(16, true)
        if bytes then
            return resty_string.to_hex(bytes)
        end
    end

    local seed = table.concat({
        tostring(ngx.now()),
        tostring(math.random(1000000, 9999999)),
        tostring(ngx.worker.pid()),
        tostring(ngx.var.request_id or "")
    }, ":")
    return ngx.md5(seed)
end

-- 处理验证码API请求
local function handle_captcha_api()
    local uri = ngx.var.uri
    local client_ip = utils.get_client_ip()
    local user_agent = ngx.var.http_user_agent or ""

    -- 速率限制
    local function rate_limit(key, limit, window)
        local count = limit_dict:incr(key, 1, 0, window)
        return count and count > limit
    end

    if rate_limit("verify_api:" .. client_ip, 120, 60) then
        ngx.status = ngx.HTTP_TOO_MANY_REQUESTS
        ngx.say(cjson.encode({ success = false, message = "Too many requests" }))
        return ngx.exit(ngx.OK)
    end

    ngx.header.content_type = "application/json"

    -- 处理验证码图片请求（不返回明文code，返回SVG图片）
    if uri == "/safeline-api/captcha/image" then
        local args = ngx.req.get_uri_args()
        local token = args.token or ngx.var.cookie_safeline_verification
        if not token then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Missing token" }))
            return ngx.exit(ngx.OK)
        end

        local token_data = utils.decrypt_token(token)
        if not token_data or not token_data.original_url or token_data.expires <= ngx.time() then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Invalid token" }))
            return ngx.exit(ngx.OK)
        end
        local type_ok, type_message = ensure_token_verification_type(token_data, "captcha")
        if not type_ok then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = type_message }))
            return ngx.exit(ngx.OK)
        end
        local bindings = type(token_data.verification_bindings) == "table" and token_data.verification_bindings or {}
        local bind_ip = bindings.ip_address ~= false
        local bind_user_agent = bindings.user_agent ~= false

        local captcha_code = generate_captcha_code()
        local challenge_id = generate_challenge_id()

        -- 以challenge_id为key存储code，不以IP为key（支持多tab）
        local captcha_key = "captcha:ch:" .. challenge_id
        cache_dict:set(captcha_key, cjson.encode({
            code = captcha_code,
            ip = bind_ip and client_ip or nil,
            ua_hash = bind_user_agent and ngx.md5(user_agent or "") or nil,
            host = token_data.host,
            path = token_data.path,
            reason = token_data.reason,
            verification_type = token_data.verification_type,
            method = token_data.method,
            issued_at = ngx.time()
        }), 300) -- 5分钟有效期

        -- 返回challenge_id + SVG图片（SVG不包含code）
        local svg = generate_captcha_svg(captcha_code)
        local svg_b64 = ngx.encode_base64(svg)

        ngx.say(cjson.encode({
            success = true,
            challenge_id = challenge_id,
            image = "data:image/svg+xml;base64," .. svg_b64
        }))
        return ngx.exit(ngx.OK)

    -- 处理验证码验证请求
    elseif uri == "/safeline-api/captcha/verify" then
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()

        if not args then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Invalid request" }))
            return ngx.exit(ngx.OK)
        end

        local user_code = args.code
        local token = args.token
        local challenge_id = args.challenge_id

        if not user_code or not token or not challenge_id then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Missing parameters" }))
            return ngx.exit(ngx.OK)
        end

        -- 验证challenge_id格式（防注入）
        if not ngx.re.match(challenge_id, "^[0-9a-f]{32}$") then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Invalid challenge_id" }))
            return ngx.exit(ngx.OK)
        end

        -- 验证token
        local token_data = utils.decrypt_token(token)
        if not token_data or not token_data.original_url or token_data.expires <= ngx.time() then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Invalid token" }))
            return ngx.exit(ngx.OK)
        end
        local type_ok, type_message = ensure_token_verification_type(token_data, "captcha")
        if not type_ok then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = type_message }))
            return ngx.exit(ngx.OK)
        end

        -- 获取服务端存储的验证码（以challenge_id为key）
        local captcha_key = "captcha:ch:" .. challenge_id
        local consume_key = captcha_key .. ":consume"
        local reserved, reserve_err = reserve_single_use_key(consume_key, 300)
        if not reserved then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({
                success = false,
                message = reserve_err == "already_used" and "Captcha challenge already used" or "Captcha validation unavailable"
            }))
            return ngx.exit(ngx.OK)
        end

        local stored_raw = cache_dict:get(captcha_key)

        if not stored_raw then
            cache_dict:delete(consume_key)
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Captcha expired or invalid" }))
            return ngx.exit(ngx.OK)
        end

        -- 验证后立即删除，防止重放
        cache_dict:delete(captcha_key)

        local stored_ok, stored_payload = pcall(cjson.decode, stored_raw)
        local stored_code = stored_raw
        if stored_ok and type(stored_payload) == "table" then
            stored_code = stored_payload.code
        else
            stored_payload = nil
        end

        local matched, match_message = challenge_matches_token(stored_payload, token_data, client_ip, user_agent)
        if not matched then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = match_message }))
            return ngx.exit(ngx.OK)
        end

        if type(stored_code) ~= "string" or stored_code == "" then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Captcha challenge is invalid" }))
            return ngx.exit(ngx.OK)
        end

        -- 不区分大小写比较
        if string.lower(user_code) == string.lower(stored_code) then
            issue_verified_response(token_data, client_ip, user_agent)
        else
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Invalid captcha code" }))
        end

        return ngx.exit(ngx.OK)

    -- 处理滑块验证请求
    elseif uri == "/safeline-api/slider/verify" then
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()

        if not args then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Invalid request" }))
            return ngx.exit(ngx.OK)
        end

        local slider_position = tonumber(args.position)
        local token = args.token
        local challenge_id = args.challenge_id

        if not slider_position or not token or not challenge_id then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Missing parameters" }))
            return ngx.exit(ngx.OK)
        end

        -- 验证challenge_id格式
        if not ngx.re.match(challenge_id, "^[0-9a-f]{32}$") then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Invalid challenge_id" }))
            return ngx.exit(ngx.OK)
        end

        -- 验证token
        local token_data = utils.decrypt_token(token)
        if not token_data or not token_data.original_url or token_data.expires <= ngx.time() then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Invalid token" }))
            return ngx.exit(ngx.OK)
        end
        local type_ok, type_message = ensure_token_verification_type(token_data, "slider")
        if not type_ok then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = type_message }))
            return ngx.exit(ngx.OK)
        end

        -- 以challenge_id为key获取服务端存储的滑块位置（不暴露给客户端）
        local slider_key = "slider:ch:" .. challenge_id
        local consume_key = slider_key .. ":consume"
        local reserved, reserve_err = reserve_single_use_key(consume_key, 300)
        if not reserved then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({
                success = false,
                message = reserve_err == "already_used" and "Slider challenge already used" or "Slider validation unavailable"
            }))
            return ngx.exit(ngx.OK)
        end

        local slider_raw = cache_dict:get(slider_key)

        if not slider_raw then
            cache_dict:delete(consume_key)
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Slider verification expired" }))
            return ngx.exit(ngx.OK)
        end

        -- 验证后立即删除，防止重放
        cache_dict:delete(slider_key)
        local slider_ok, slider_payload = pcall(cjson.decode, slider_raw)
        local expected_position = tonumber(slider_raw)
        if slider_ok and type(slider_payload) == "table" then
            expected_position = tonumber(slider_payload.position)
        else
            slider_payload = nil
        end

        local matched, match_message = challenge_matches_token(slider_payload, token_data, client_ip, user_agent)
        if not matched then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = match_message }))
            return ngx.exit(ngx.OK)
        end

        if not expected_position then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Slider challenge is invalid" }))
            return ngx.exit(ngx.OK)
        end

        -- 允许±5像素误差
        if math.abs(slider_position - expected_position) <= 5 then
            if token_data.step_up_required then
                issue_step_up_response(token_data)
            else
                issue_verified_response(token_data, client_ip, user_agent)
            end
        else
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Invalid slider position" }))
        end

        return ngx.exit(ngx.OK)

    -- 处理POW验证请求
    elseif uri == "/safeline-api/pow/verify" or uri == "/pow/verify" then
        local body_json = read_request_body_json()
        local args = ngx.req.get_post_args() or {}

        local token = (body_json and body_json.token) or args.token or ngx.var.cookie_safeline_verification or ngx.var.arg_token
        if not token then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Missing token" }))
            return ngx.exit(ngx.OK)
        end

        local token_data = utils.decrypt_token(token)
        if not token_data or not token_data.original_url or token_data.expires <= ngx.time() then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Invalid token" }))
            return ngx.exit(ngx.OK)
        end
        local type_ok, type_message = ensure_token_verification_type(token_data, "pow")
        if not type_ok then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = type_message }))
            return ngx.exit(ngx.OK)
        end

        local success, message = pow.verify_solution(client_ip, token_data, user_agent)

        if success then
            issue_verified_response(token_data, client_ip, user_agent)
        else
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = message }))
        end

        return ngx.exit(ngx.OK)

    -- 获取POW挑战
    elseif uri == "/safeline-api/pow/challenge" or uri == "/pow/challenge" then
        local args = ngx.req.get_uri_args()
        local token = args.token or ngx.var.cookie_safeline_verification

        if not token then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Missing token" }))
            return ngx.exit(ngx.OK)
        end

        local token_data = utils.decrypt_token(token)
        if not token_data or not token_data.original_url or token_data.expires <= ngx.time() then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Invalid token" }))
            return ngx.exit(ngx.OK)
        end
        local type_ok, type_message = ensure_token_verification_type(token_data, "pow")
        if not type_ok then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = type_message }))
            return ngx.exit(ngx.OK)
        end

        local original_uri = ngx.re.match(token_data.original_url, "https?://[^/]+([^?]+)")
        local uri_path = original_uri and original_uri[1] or "/"
        local bindings = type(token_data.verification_bindings) == "table" and token_data.verification_bindings or {}
        local bind_ip = bindings.ip_address ~= false
        local bind_user_agent = bindings.user_agent ~= false

        local difficulty = tonumber(token_data.difficulty)
        local challenge = pow.generate_challenge(client_ip, uri_path, difficulty, {
            ip = bind_ip and client_ip or nil,
            ua_hash = bind_user_agent and ngx.md5(user_agent or "") or nil,
            host = token_data.host,
            path = token_data.path,
            reason = token_data.reason,
            verification_type = token_data.verification_type,
            method = token_data.method
        })

        ngx.say(cjson.encode({
            success = true,
            challenge_id = challenge.challenge_id,
            prefix = challenge.prefix,
            difficulty = challenge.difficulty
        }))

        return ngx.exit(ngx.OK)

    -- 生成滑块验证数据（不向客户端暴露正确位置）
    elseif uri == "/safeline-api/slider/generate" then
        local args = ngx.req.get_uri_args()
        local token = args.token or ngx.var.cookie_safeline_verification
        if not token then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Missing token" }))
            return ngx.exit(ngx.OK)
        end

        local token_data = utils.decrypt_token(token)
        if not token_data or not token_data.original_url or token_data.expires <= ngx.time() then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = "Invalid token" }))
            return ngx.exit(ngx.OK)
        end
        local type_ok, type_message = ensure_token_verification_type(token_data, "slider")
        if not type_ok then
            ngx.status = ngx.HTTP_BAD_REQUEST
            ngx.say(cjson.encode({ success = false, message = type_message }))
            return ngx.exit(ngx.OK)
        end
        local bindings = type(token_data.verification_bindings) == "table" and token_data.verification_bindings or {}
        local bind_ip = bindings.ip_address ~= false
        local bind_user_agent = bindings.user_agent ~= false

        local track_width = 300
        local button_width = 40
        local position = track_width - math.floor(button_width / 2)
        local challenge_id = generate_challenge_id()

        -- 以challenge_id为key存储位置，不返回给客户端
        local slider_key = "slider:ch:" .. challenge_id
        cache_dict:set(slider_key, cjson.encode({
            position = position,
            ip = bind_ip and client_ip or nil,
            ua_hash = bind_user_agent and ngx.md5(user_agent or "") or nil,
            host = token_data.host,
            path = token_data.path,
            reason = token_data.reason,
            verification_type = token_data.verification_type,
            method = token_data.method,
            issued_at = ngx.time()
        }), 300)

        -- 前端按固定“拖到最右侧”完成验证，服务端只返回必要的布局参数
        ngx.say(cjson.encode({
            success = true,
            challenge_id = challenge_id,
            track_width = track_width,
            button_width = button_width
        }))

        return ngx.exit(ngx.OK)
    end

    -- 未知API路径
    ngx.status = ngx.HTTP_NOT_FOUND
    ngx.say(cjson.encode({ success = false, message = "API not found" }))
    return ngx.exit(ngx.OK)
end

-- 初始化
function _M.init()
    math.randomseed(ngx.time() + ngx.worker.pid())
end

-- 处理验证API请求的主函数
function _M.handle()
    handle_captcha_api()
end

return _M
