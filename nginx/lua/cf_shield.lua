-- CF 五秒盾联动模块
-- 在 WAF 检测到攻击时，通过 Redis 向后端 Node.js 工作者上报攻击分值；
-- 工作者达到阈值后调用 Cloudflare API 自动开启 Under Attack Mode。
-- 本模块 NEVER 阻塞请求路径 —— 所有 Redis 写操作均使用 fire-and-forget 计时器。

local _M = {}

local utils      = require "utils"
local config_dict = ngx.shared.safeline_config

-- ── 各攻击类型的分值权重 ──────────────────────────────────────────────────
-- 每次攻击事件向 Redis 的滑动窗口计数器 cf:attack:score 累加对应权重。
-- 后端工作者每15秒读取该值与配置的 activate_threshold 比较。
local WEIGHTS = {
    global_hard      = 12,   -- 全局内存满 / 全站高压：最高权重
    global_pressure  =  6,
    global_burst     =  6,
    unique_ip_surge  =  4,
    burst            =  5,   -- CC 短窗口爆发
    uri              =  2,
    ip               =  2,
    fingerprint      =  2,
    url_limit        =  3,
    ip_limit         =  3,
    behavioral       =  3,
    conn_hard        =  8,
    conn_flood       =  3,
}

-- 滑动窗口 TTL（秒）：score 在窗口内累积，窗口过期后自动归零
local SCORE_TTL = 60

-- ── 开关检查 ──────────────────────────────────────────────────────────────

local function cf_enabled()
    local v = config_dict:get("cf:shield:enabled")
    return v == "true" or v == true
end

-- ── 上报攻击信号 ──────────────────────────────────────────────────────────
-- reason : 与 ddos_protection 返回的 reason 字符串对应
-- weight : 可手动覆盖权重；nil 则使用 WEIGHTS 表中的默认值
-- ratio  : count/limit 比值（可选），用于放大权重（超出越多、分值越高）
function _M.report_attack(reason, ratio, weight)
    if not cf_enabled() then return end

    local w = weight or WEIGHTS[reason] or 1

    -- 超出阈值越多，分值放大（上限 3×）
    if ratio and ratio > 1 then
        w = math.min(w * math.min(ratio, 3), w * 3)
    end
    w = math.floor(w)
    if w < 1 then w = 1 end

    ngx.timer.at(0, function(premature)
        if premature then return end
        local red = utils.get_redis(100)
        if not red then return end

        local ok = pcall(function()
            -- INCRBY：向滑动窗口计数器累加权重
            local score_key = "cf:attack:score"
            local new_score = red:incrby(score_key, w)
            -- 每次累加后刷新 TTL（保证60秒内没有新攻击时分值自然清零）
            red:expire(score_key, SCORE_TTL)

            -- 记录峰值（用于 UI 展示历史最高分）
            local peak = tonumber(red:get("cf:attack:peak") or "0") or 0
            if (new_score or 0) > peak then
                red:setex("cf:attack:peak", 7200, tostring(new_score or 0))
            end

            -- 记录最近一次攻击时间戳（用于计算冷却期）
            red:set("cf:attack:last_seen", tostring(ngx.time()))
        end)

        if not ok then
            ngx.log(ngx.WARN, "[CF] Attack score report failed")
        end

        utils.release_redis(red)
    end)
end

-- ── 检查当前是否处于 CF 盾保护中 ─────────────────────────────────────────
-- 供 access.lua 用于决策（可选：被 CF 盾保护时可跳过部分 Lua 防护逻辑节省 CPU）
function _M.is_shielded()
    local v = config_dict:get("cf:shield:active")
    return v == "true" or v == true
end

return _M
