-- 响应头安全加固脚本
-- 规则：不覆盖上游已设置的响应头，避免破坏应用自身的安全策略

-- 基础安全头（无论上游是否设置都强制注入）
ngx.header["X-Frame-Options"] = "SAMEORIGIN"
ngx.header["X-Content-Type-Options"] = "nosniff"
ngx.header["Referrer-Policy"] = "strict-origin-when-cross-origin"
ngx.header["Permissions-Policy"] =
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()"

-- X-XSS-Protection 已被现代浏览器废弃，CSP 更有效，不再设置

local uri = ngx.var.uri or ""
local is_waf_managed_page = uri == "/pow"
    or uri:sub(1, 5) == "/pow/"
    or uri:sub(1, 18) == "/safeline-static/"
    or uri:sub(1, 14) == "/safeline-api/"

-- 仅对 WAF 自己输出的验证/静态页面兜底注入默认 CSP。
-- 代理后的业务页面即使开启了 JS 加密/F12 防护，也不要强行覆盖 CSP，
-- 否则会拦截业务站点依赖的外链 CSS/JS。
if not ngx.header["Content-Security-Policy"] and is_waf_managed_page then
    local script_src = "script-src 'self'; "
    if ngx.ctx.js_encryption or ngx.ctx.prevent_f12 then
        script_src = "script-src 'self' 'unsafe-inline'; "
    end

    ngx.header["Content-Security-Policy"] =
        "default-src 'self'; " ..
        script_src ..
        "style-src 'self' 'unsafe-inline'; " ..
        "img-src 'self' data: https:; " ..
        "font-src 'self' data:; " ..
        "frame-ancestors 'self'; " ..
        "object-src 'none'; " ..
        "base-uri 'self';"
end

-- 移除可能泄露服务器信息的响应头
ngx.header["Server"] = nil
ngx.header["X-Powered-By"] = nil

-- 对HTML响应注入JS加密或F12防护
local content_type = ngx.header.content_type or ngx.header["Content-Type"]
local content_encoding = ngx.header["Content-Encoding"]
if content_type and content_type:find("text/html", 1, true) then
    if ngx.ctx.js_encryption or ngx.ctx.prevent_f12 then
        local encoding = type(content_encoding) == "string" and content_encoding:lower() or ""
        if encoding ~= "" and encoding ~= "identity" then
            ngx.ctx.modify_response = nil
            ngx.log(ngx.WARN, "[header_filter] Skip HTML rewrite for encoded response: ", encoding)
            return
        end

        ngx.ctx.modify_response = true
        ngx.header["Content-Length"] = nil
        ngx.header["ETag"] = nil
        ngx.header["Last-Modified"] = nil
        ngx.header["Content-Encoding"] = nil
    end
end
