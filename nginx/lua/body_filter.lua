-- 响应体处理脚本
local ok_js_encrypt, js_encrypt = pcall(require, "js_encrypt")
if not ok_js_encrypt then
    ngx.log(ngx.ERR, "[body_filter] Failed to load js_encrypt: ", js_encrypt)
    js_encrypt = nil
end

local MAX_REWRITE_BYTES = 2 * 1024 * 1024

local function inject_script(response_body, js_code)
    if not response_body or response_body == "" or not js_code or js_code == "" then
        return response_body
    end

    local replacement = "<script>" .. js_code .. "</script></head>"
    local injected, _, err = ngx.re.sub(response_body, "</head>", replacement, "ijo")
    if injected and not err and injected ~= response_body then
        return injected
    end

    replacement = "<script>" .. js_code .. "</script></body>"
    injected, _, err = ngx.re.sub(response_body, "</body>", replacement, "ijo")
    if injected and not err and injected ~= response_body then
        return injected
    end

    replacement = "<script>" .. js_code .. "</script></html>"
    injected, _, err = ngx.re.sub(response_body, "</html>", replacement, "ijo")
    if injected and not err and injected ~= response_body then
        return injected
    end

    return response_body .. "<script>" .. js_code .. "</script>"
end

local function cleanup_buffer()
    ngx.ctx.buffer = nil
    ngx.ctx.buffer_size = nil
    ngx.ctx.modify_response = nil
end

local function release_buffered_response(current_chunk)
    local buffered = ""
    if type(ngx.ctx.buffer) == "table" and #ngx.ctx.buffer > 0 then
        buffered = table.concat(ngx.ctx.buffer)
    end

    cleanup_buffer()
    ngx.arg[1] = buffered .. (current_chunk or "")
end

-- 如果需要修改响应体
if ngx.ctx.modify_response then
    local content_type = ngx.header.content_type or ngx.header["Content-Type"]

    -- 只处理HTML内容
    if content_type and content_type:find("text/html", 1, true) and js_encrypt then
        local chunk = ngx.arg[1] or ""
        local is_last_chunk = ngx.arg[2]

        -- 获取或初始化缓冲区
        ngx.ctx.buffer = ngx.ctx.buffer or {}
        ngx.ctx.buffer_size = tonumber(ngx.ctx.buffer_size or 0) or 0

        if chunk ~= "" then
            local next_size = ngx.ctx.buffer_size + #chunk
            if next_size > MAX_REWRITE_BYTES then
                ngx.log(ngx.WARN, "[body_filter] Skip HTML rewrite because response body is too large: ", next_size)
                release_buffered_response(chunk)
                return
            end

            table.insert(ngx.ctx.buffer, chunk)
            ngx.ctx.buffer_size = next_size
            ngx.arg[1] = nil
        end

        -- 如果是最后一块数据，处理完整的响应
        if is_last_chunk then
            local response_body = table.concat(ngx.ctx.buffer)

            if ngx.ctx.js_encryption then
                local ok, js_code = pcall(js_encrypt.get_obfuscated_js)
                if ok then
                    response_body = inject_script(response_body, js_code)
                else
                    ngx.log(ngx.WARN, "[body_filter] Failed to build obfuscated JS: ", js_code)
                end
            end

            if ngx.ctx.prevent_f12 then
                local ok, js_code = pcall(js_encrypt.get_prevent_f12_js)
                if ok then
                    response_body = inject_script(response_body, js_code)
                else
                    ngx.log(ngx.WARN, "[body_filter] Failed to build prevent-f12 JS: ", js_code)
                end
            end

            ngx.arg[1] = response_body
            cleanup_buffer()
        end
    else
        cleanup_buffer()
        if not js_encrypt and (ngx.ctx.js_encryption or ngx.ctx.prevent_f12) then
            ngx.log(ngx.WARN, "[body_filter] Skip HTML rewrite because js_encrypt is unavailable")
        end
    end
end
