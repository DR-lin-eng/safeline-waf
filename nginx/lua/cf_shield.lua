-- CF 五秒盾联动模块
-- 在 WAF 检测到攻击时，通过 Redis 向后端 Node.js 工作者上报攻击分值；
-- 工作者达到阈值后调用 Cloudflare API 自动开启 Under Attack Mode。
-- 本模块 NEVER 阻塞请求路径 —— 所有 Redis 写操作均使用 fire-and-forget 计时器。

local _M = {}

local cjson      = require "cjson"
local utils      = require "utils"
local config_dict = ngx.shared.safeline_config
local cache_dict = ngx.shared.safeline_cache
local CONFIG_REFRESH_TTL = 5

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

local function refresh_cf_state_async()
    local now = ngx.time()
    local loaded_at = tonumber(cache_dict:get("cf:shield:loaded_at") or 0) or 0
    if (now - loaded_at) < CONFIG_REFRESH_TTL then
        return
    end

    local locked, lock_err = cache_dict:add("cf:shield:refresh_lock", true, 1)
    if not locked and lock_err ~= "exists" then
        return
    end
    if not locked then
        return
    end

    ngx.timer.at(0, function(premature)
        if premature then
            cache_dict:delete("cf:shield:refresh_lock")
            return
        end

        local red = utils.get_redis(100)
        if not red then
            cache_dict:delete("cf:shield:refresh_lock")
            return
        end

        local ok = pcall(function()
            local cfg_raw = red:get("cf:config")
            if cfg_raw ~= ngx.null and type(cfg_raw) == "string" and cfg_raw ~= "" then
                local ok_cfg, cfg = pcall(cjson.decode, cfg_raw)
                if ok_cfg and type(cfg) == "table" then
                    config_dict:set("cf:shield:enabled", cfg.enabled == true and "true" or "false")
                end
            end

            local state_raw = red:get("cf:state")
            if state_raw ~= ngx.null and type(state_raw) == "string" and state_raw ~= "" then
                local ok_state, state = pcall(cjson.decode, state_raw)
                if ok_state and type(state) == "table" then
                    config_dict:set("cf:shield:active", state.active == true and "true" or "false")
                end
            else
                config_dict:set("cf:shield:active", "false")
            end

            cache_dict:set("cf:shield:loaded_at", now, CONFIG_REFRESH_TTL * 2)
        end)

        if not ok then
            ngx.log(ngx.WARN, "[CF] Failed to refresh runtime shield state")
        end

        utils.release_redis(red)
        cache_dict:delete("cf:shield:refresh_lock")
    end)
end

local function cf_enabled()
    refresh_cf_state_async()
    local v = config_dict:get("cf:shield:enabled")
    return v == "true" or v == true
end

local function schedule_score_flush(delay_seconds)
    delay_seconds = tonumber(delay_seconds) or 0
    local scheduled, schedule_err = cache_dict:add("cf:flush_lock", true, 1)
    if not scheduled then
        return schedule_err == "exists"
    end

    local ok, err = ngx.timer.at(delay_seconds, function(premature)
        if premature then
            cache_dict:delete("cf:flush_lock")
            return
        end

        local pending = tonumber(cache_dict:get("cf:pending_score") or 0) or 0
        cache_dict:delete("cf:pending_score")
        local should_retry = false

        if pending > 0 then
            local red = utils.get_redis(100)
            if red then
                local flush_ok = pcall(function()
                    local score_key = "cf:attack:score"
                    local new_score = red:incrby(score_key, pending)
                    red:expire(score_key, SCORE_TTL)

                    local peak = tonumber(red:get("cf:attack:peak") or "0") or 0
                    if (new_score or 0) > peak then
                        red:setex("cf:attack:peak", 7200, tostring(new_score or 0))
                    end

                    red:set("cf:attack:last_seen", tostring(ngx.time()))
                end)

                if not flush_ok then
                    ngx.log(ngx.WARN, "[CF] Attack score report failed")
                    cache_dict:incr("cf:pending_score", pending, 0, SCORE_TTL)
                    should_retry = true
                end

                utils.release_redis(red)
            else
                cache_dict:incr("cf:pending_score", pending, 0, SCORE_TTL)
                should_retry = true
            end
        end

        cache_dict:delete("cf:flush_lock")
        if should_retry or tonumber(cache_dict:get("cf:pending_score") or 0) > 0 then
            schedule_score_flush(1)
        end
    end)

    if not ok then
        cache_dict:delete("cf:flush_lock")
        ngx.log(ngx.WARN, "[CF] Failed to schedule score flush: ", tostring(err))
        return false
    end

    return true
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

    cache_dict:incr("cf:pending_score", w, 0, SCORE_TTL)
    schedule_score_flush(0)
end

-- ── 检查当前是否处于 CF 盾保护中 ─────────────────────────────────────────
-- 供 access.lua 用于决策（可选：被 CF 盾保护时可跳过部分 Lua 防护逻辑节省 CPU）
function _M.is_shielded()
    refresh_cf_state_async()
    local v = config_dict:get("cf:shield:active")
    return v == "true" or v == true
end

return _M
