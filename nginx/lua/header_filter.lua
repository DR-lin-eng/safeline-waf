-- 响应头处理脚本
local utils = require "utils"

-- 添加安全相关响应头
ngx.header["X-Frame-Options"] = "SAMEORIGIN"
ngx.header["X-Content-Type-Options"] = "nosniff"
ngx.header["X-XSS-Protection"] = "1; mode=block"
ngx.header["Referrer-Policy"] = "strict-origin-when-cross-origin"
ngx.header["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"

-- 移除可能泄露服务器信息的响应头
ngx.header["Server"] = nil
ngx.header["X-Powered-By"] = nil

-- 对HTML响应注入JS加密或F12防护
local content_type = ngx.header.content_type
if content_type and content_type:find("text/html", 1, true) then
    -- 设置标记，告知body_filter阶段需要修改响应体
    if ngx.ctx.js_encryption or ngx.ctx.prevent_f12 then
        ngx.ctx.modify_response = true
    end
end
