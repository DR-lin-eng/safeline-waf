-- 响应体处理脚本
local js_encrypt = require "js_encrypt"

-- 如果需要修改响应体
if ngx.ctx.modify_response then
    local content_type = ngx.header.content_type
    
    -- 只处理HTML内容
    if content_type and content_type:find("text/html", 1, true) then
        local chunk = ngx.arg[1]
        local is_last_chunk = ngx.arg[2]
        
        -- 获取或初始化缓冲区
        ngx.ctx.buffer = ngx.ctx.buffer or {}
        
        if chunk and chunk ~= "" then
            table.insert(ngx.ctx.buffer, chunk)
            ngx.arg[1] = nil
        end
        
        -- 如果是最后一块数据，处理完整的响应
        if is_last_chunk then
            local response_body = table.concat(ngx.ctx.buffer)
            
            -- 注入JS加密脚本
            if ngx.ctx.js_encryption then
                local js_code = js_encrypt.get_obfuscated_js()
                response_body = response_body:gsub("</head>", "<script>" .. js_code .. "</script></head>")
            end
            
            -- 注入防止F12调试的脚本
            if ngx.ctx.prevent_f12 then
                local js_code = js_encrypt.get_prevent_f12_js()
                response_body = response_body:gsub("</head>", "<script>" .. js_code .. "</script></head>")
            end
            
            ngx.arg[1] = response_body
            ngx.ctx.buffer = nil
        end
    end
end
