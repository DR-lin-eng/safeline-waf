local _M = {}
local cjson = require "cjson"
local config_dict = ngx.shared.safeline_config

local trusted_bots_cache = nil
local trusted_bots_cache_version = nil

local function contains_any(haystack, needles)
    for _, needle in ipairs(needles) do
        if haystack:find(needle, 1, true) then
            return true
        end
    end
    return false
end

-- 已知合法爬虫 / 搜索引擎机器人（不应拦截）
-- 这些机器人对网站SEO有益，且会遵守 robots.txt
local known_good_bots = {
    "googlebot",
    "bingbot",
    "yandexbot",
    "duckduckbot",
    "baiduspider",
    "applebot",
    "slurp",            -- Yahoo
    "facebookexternalhit",
    "twitterbot",
    "linkedinbot",
    "whatsapp",
    "telegrambot",
    "discordbot",
    "semrushbot",
    "ahrefsbot",
    "mj12bot",
    "dotbot",
    "rogerbot",
}

local function get_trusted_bots()
    if not config_dict then
        return known_good_bots
    end

    local version = tonumber(config_dict:get("config_version") or 0) or 0
    if trusted_bots_cache and trusted_bots_cache_version == version then
        return trusted_bots_cache
    end

    local bots = known_good_bots
    local raw = config_dict:get("trusted_bots")
    if type(raw) == "string" and raw ~= "" then
        local ok, decoded = pcall(cjson.decode, raw)
        if ok and type(decoded) == "table" then
            bots = {}
            for _, item in ipairs(decoded) do
                if type(item) == "string" and item ~= "" then
                    bots[#bots + 1] = item:lower()
                end
            end
        end
    end

    trusted_bots_cache = bots
    trusted_bots_cache_version = version
    return bots
end

-- 已知恶意/自动化工具（区分大小写无关，子串匹配）
local known_bad = {
    "curl/",
    "wget/",
    "python-requests",
    "python-urllib",
    "go-http-client",
    "okhttp/",
    "libwww-perl",
    "scrapy/",
    "nikto",
    "sqlmap",
    "nmap",
    "masscan",
    "apachebench",
    "ab/",
    "phantomjs",
    "headlesschrome",
    "headless",
}

-- 基于User-Agent的基础浏览器识别
-- 注意：WAF更应以"高可疑"触发验证而非直接拒绝；这里返回false会进入验证流程。
function _M.check(user_agent)
    if type(user_agent) ~= "string" or user_agent == "" then
        return false
    end

    local ua = user_agent:lower()

    -- 优先放行已知合法爬虫（避免影响SEO）
    if contains_any(ua, get_trusted_bots()) then
        return true
    end

    -- 检查已知恶意工具（完整子串，避免误判）
    if contains_any(ua, known_bad) then
        return false
    end

    -- 检查通用 bot/spider/crawler 词（合法爬虫已在上面白名单处理）
    if ua:find("bot/", 1, true) or
       ua:find("spider/", 1, true) or
       ua:find("crawler/", 1, true) then
        return false
    end

    -- 必须包含真实浏览器标识
    local known_good = {
        "mozilla/5.0",
        "applewebkit/",
        "chrome/",
        "safari/",
        "firefox/",
        "edg/",
        "edge/",
        "opr/",
    }

    return contains_any(ua, known_good)
end

-- 基于请求头环境的基础校验
function _M.check_environment()
    local headers = ngx.req.get_headers()

    local ua = headers["user-agent"] or headers["User-Agent"]
    local accept = headers["accept"] or headers["Accept"]
    local accept_language = headers["accept-language"] or headers["Accept-Language"]
    local accept_encoding = headers["accept-encoding"] or headers["Accept-Encoding"]

    if not ua or ua == "" then
        return false
    end
    if not accept or accept == "" then
        return false
    end

    -- 对部分合法客户端（如某些App/SDK）兼容：语言/编码缺失时不直接判定失败
    if (not accept_language or accept_language == "") and (not accept_encoding or accept_encoding == "") then
        return false
    end

    return true
end

return _M
