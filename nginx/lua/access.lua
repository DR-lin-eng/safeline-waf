-- 高级访问控制模块
local cjson = require "cjson"
local utils = require "utils"
local utils_advanced = require "utils_advanced"
local browser_detection = require "browser_detection"
local ip_blacklist = require "ip_blacklist"
local ddos_protection = require "ddos_protection"
local ddos_advanced = require "ddos_advanced"
local pow = require "pow"

-- 共享内存
local config_dict = ngx.shared.safeline_config
local cache_dict = ngx.shared.safeline_cache
local limit_dict = ngx.shared.safeline_limit
local blacklist_dict = ngx.shared.safeline_blacklist
local counters_dict = ngx.shared.safeline_counters

-- 初始化随机数种子
math.randomseed(ngx.now() * 1000)

-- 获取站点配置
local function get_site_config()
    local host = ngx.var.host
    local config_json = config_dict:get("site:" .. host)
    
    if not config_json then
        return nil
    end
    
    local success, config = pcall(cjson.decode, config_json)
    if not success then
        ngx.log(ngx.ERR, "Failed to parse site config for: " .. host)
        return nil
    end
    
    return config
end

-- 检查是否需要跳过WAF
local function should_skip_waf()
    -- 检查是否是静态资源或验证API
    local uri = ngx.var.uri
    if uri:match("^/safeline%-static/") or uri:match("^/safeline%-api/") then
        return true
    end
    
    -- 允许验证后的请求通过
    local cookie_value = ngx.var.cookie_safeline_verified
    if cookie_value then
        local verified_token = utils.decrypt_token(cookie_value)
        if verified_token and verified_token.expires > ngx.time() then
            return true
        end
    end
    
    return false
end

-- 重定向到验证页面
local function redirect_to_verification(verification_type, reason, difficulty)
    -- 生成token包含原始URL和验证原因
    local token_data = {
        original_url = ngx.var.scheme .. "://" .. ngx.var.host .. ngx.var.request_uri,
        verification_type = verification_type,
        reason = reason,
        difficulty = difficulty,
        expires = ngx.time() + 3600 -- 1小时内有效
    }
    
    local token = utils.encrypt_token(token_data)
    local redirect_url = "/safeline-static/verify.html?token=" .. ngx.escape_uri(token)
    
    ngx.header["Set-Cookie"] = "safeline_verification=" .. token .. "; Path=/; Max-Age=3600; HttpOnly"
    
    ngx.redirect(redirect_url)
end

-- 动态选择验证方式
local function select_verification_method(site_config, reason, client_ip, uri)
    -- 获取客户端历史异常分数
    local score_key = "anomaly_score:" .. client_ip
    local score = tonumber(cache_dict:get(score_key) or 0)
    
    -- 根据异常分数和原因选择验证方式
    local verification_type = "captcha"  -- 默认验证码
    local difficulty = 4  -- 默认难度
    
    if score > 8 or reason == "ddos_protection" or reason == "random_attack" then
        -- 高风险请求使用POW
        verification_type = "pow"
        difficulty = 5 + math.floor(score / 5)  -- 根据异常分数增加难度
        difficulty = math.min(difficulty, 8)  -- 最高难度为8
    elseif score > 4 or reason == "anti_cc" then
        -- 中风险请求使用滑块验证
        verification_type = "slider"
    end
    
    -- 确保所选验证方式已启用
    if verification_type == "pow" and not site_config.pow_enabled then
        verification_type = "slider"
    end
    
    if verification_type == "slider" and not site_config.slider_captcha_enabled then
        verification_type = "captcha"
    end
    
    return verification_type, difficulty
end

-- 记录请求日志
local function log_request(site_config, client_ip, uri, status, is_blocked, reason)
    if not site_config.request_logging_enabled then
        return
    end
    
    local log_data = {
        timestamp = ngx.time(),
        client_ip = client_ip,
        uri = uri,
        method = ngx.req.get_method(),
        user_agent = ngx.var.http_user_agent or "",
        status = status,
        is_blocked = is_blocked,
        reason = reason or ""
    }
    
    utils.log_event("request", log_data)
end

-- 更新统计信息
local function update_stats(site_config, client_ip, uri, method, is_blocked, reason)
    -- 更新全局请求计数
    counters_dict:incr("total_requests", 1, 0)
    
    -- 更新站点请求计数
    local site_counter_key = "site_requests:" .. ngx.var.host
    counters_dict:incr(site_counter_key, 1, 0)
    
    -- 更新阻止计数(如果被阻止)
    if is_blocked then
        counters_dict:incr("blocked_requests", 1, 0)
        local block_reason_key = "block_reason:" .. (reason or "unknown")
        counters_dict:incr(block_reason_key, 1, 0)
    end
    
    -- 更新流量分析统计
    if site_config.traffic_analysis_enabled then
        ddos_advanced.update_traffic_stats(client_ip, is_blocked and 403 or 200, uri, method)
    end
}

-- 主WAF处理函数
local function process_waf()
    -- 如果需要跳过WAF检查，直接返回
    if should_skip_waf() then
        return
    end
    
    -- 获取站点配置
    local site_config = get_site_config()
    if not site_config then
        -- 如果没有找到站点配置，允许请求通过
        return
    end
    
    -- 获取客户端信息
    local client_ip = utils.get_client_ip()
    local user_agent = ngx.var.http_user_agent or ""
    local uri = ngx.var.uri
    local method = ngx.req.get_method()
    
    -- 检查蜜罐触发
    if site_config.honeypot_enabled then
        local is_honeypot, trap_type = utils_advanced.check_honeypot_trap(uri, ngx.req.get_uri_args(), ngx.req.get_headers())
        if is_honeypot then
            ngx.log(ngx.WARN, "Honeypot triggered by " .. client_ip .. ": " .. trap_type)
            
            -- 记录异常
            utils_advanced.record_anomaly(client_ip, uri, "honeypot_" .. trap_type, 10)
            
            -- 添加到黑名单（短期）
            if site_config.auto_blacklist_enabled then
                ip_blacklist.add_to_blacklist(client_ip, 3600) -- 1小时
            end
            
            -- 记录请求
            log_request(site_config, client_ip, uri, 403, true, "honeypot_" .. trap_type)
            
            -- 更新统计信息
            update_stats(site_config, client_ip, uri, method, true, "honeypot")
            
            -- 返回403但延迟响应以减缓攻击频率
            ngx.sleep(2)
            ngx.exit(ngx.HTTP_FORBIDDEN)
            return
        end
    end
    
    -- 检查IP黑名单
    if site_config.ip_blacklist_enabled and ip_blacklist.is_blacklisted(client_ip) then
        -- 记录请求
        log_request(site_config, client_ip, uri, 403, true, "ip_blacklist")
        
        -- 更新统计信息
        update_stats(site_config, client_ip, uri, method, true, "ip_blacklist")
        
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end
    
    -- 全局限速检查
    if site_config.global_rate_limit_enabled then
        local rate_key = "global_rate:" .. client_ip
        local is_limited, count, current_limit = utils_advanced.dynamic_rate_limit(
            rate_key, 
            site_config.global_rate_limit_count or 60, 
            site_config.global_rate_limit_window or 60
        )
        
        if is_limited then
            -- 记录异常
            utils_advanced.record_anomaly(client_ip, uri, "global_rate_limit", 3)
            
            -- 判断是否需要进行验证
            if site_config.captcha_enabled or site_config.slider_captcha_enabled or site_config.pow_enabled then
                local verification_type, difficulty = select_verification_method(site_config, "rate_limit", client_ip, uri)
                redirect_to_verification(verification_type, "rate_limit", difficulty)
            else
                -- 记录请求
                log_request(site_config, client_ip, uri, 429, true, "global_rate_limit")
                
                -- 更新统计信息
                update_stats(site_config, client_ip, uri, method, true, "global_rate_limit")
                
                ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
            end
            return
        end
    }
    
    -- 检查URL级DDoS攻击
    if site_config.ddos_protection_enabled then
        local is_ddos, reason, count, limit = ddos_advanced.check_url_ddos(client_ip, uri)
        if is_ddos then
            -- 判断使用什么验证方式
            local verification_type, difficulty = select_verification_method(site_config, "ddos_protection", client_ip, uri)
            
            -- 记录请求
            log_request(site_config, client_ip, uri, 403, true, "ddos_" .. reason)
            
            -- 更新统计信息
            update_stats(site_config, client_ip, uri, method, true, "ddos_" .. reason)
            
            redirect_to_verification(verification_type, "ddos_protection", difficulty)
            return
        end
    }
    
    -- 检查随机请求方法和查询字符串攻击
    if site_config.random_attack_protection_enabled then
        local is_random_attack, attack_type = ddos_advanced.check_random_requests(client_ip)
        if is_random_attack then
            -- 记录异常
            utils_advanced.record_anomaly(client_ip, uri, "random_attack_" .. attack_type, 7)
            
            -- 判断使用什么验证方式
            local verification_type, difficulty = select_verification_method(site_config, "random_attack", client_ip, uri)
            
            -- 记录请求
            log_request(site_config, client_ip, uri, 403, true, "random_attack_" .. attack_type)
            
            -- 更新统计信息
            update_stats(site_config, client_ip, uri, method, true, "random_attack")
            
            redirect_to_verification(verification_type, "random_attack", difficulty)
            return
        end
    }
    
    -- 浏览器检测
    if site_config.browser_detection_enabled then
        local is_real_browser = browser_detection.check(user_agent)
        if not is_real_browser then
            -- 记录异常
            utils_advanced.record_anomaly(client_ip, uri, "fake_browser", 5)
            
            -- 判断验证方式
            local verification_type, difficulty = select_verification_method(site_config, "browser_detection", client_ip, uri)
            
            -- 记录请求
            log_request(site_config, client_ip, uri, 403, true, "browser_detection")
            
            -- 更新统计信息
            update_stats(site_config, client_ip, uri, method, true, "browser_detection")
            
            redirect_to_verification(verification_type, "browser_detection", difficulty)
            return
        end
    }
    
    -- 环境监测
    if site_config.environment_detection_enabled then
        local env_valid = browser_detection.check_environment()
        if not env_valid then
            -- 记录异常
            utils_advanced.record_anomaly(client_ip, uri, "invalid_environment", 4)
            
            -- 判断验证方式
            local verification_type, difficulty = select_verification_method(site_config, "environment_detection", client_ip, uri)
            
            -- 记录请求
            log_request(site_config, client_ip, uri, 403, true, "environment_detection")
            
            -- 更新统计信息
            update_stats(site_config, client_ip, uri, method, true, "environment_detection")
            
            redirect_to_verification(verification_type, "environment_detection", difficulty)
            return
        end
    }
    
    -- 自动化工具检测
    if site_config.automation_detection_enabled then
        local headers = ngx.req.get_headers()
        local is_automation, confidence, signs = utils_advanced.detect_automation_signature(headers, uri, method)
        
        if is_automation then
            -- 记录异常
            utils_advanced.record_anomaly(client_ip, uri, "automation_tool", 6)
            
            -- 判断验证方式
            local verification_type, difficulty = select_verification_method(site_config, "automation_detection", client_ip, uri)
            
            -- 记录请求
            log_request(site_config, client_ip, uri, 403, true, "automation_detection")
            
            -- 更新统计信息
            update_stats(site_config, client_ip, uri, method, true, "automation_detection")
            
            redirect_to_verification(verification_type, "automation_detection", difficulty)
            return
        end
    }
    
    -- Anti-CC防护
    if site_config.anti_cc_enabled then
        local is_cc = ddos_protection.check_cc_attack(client_ip, uri)
        if is_cc then
            -- 记录异常
            utils_advanced.record_anomaly(client_ip, uri, "cc_attack", 6)
            
            -- 判断验证方式
            local verification_type, difficulty = select_verification_method(site_config, "anti_cc", client_ip, uri)
            
            -- 记录请求
            log_request(site_config, client_ip, uri, 403, true, "anti_cc")
            
            -- 更新统计信息
            update_stats(site_config, client_ip, uri, method, true, "anti_cc")
            
            redirect_to_verification(verification_type, "anti_cc", difficulty)
            return
        end
    }
    
    -- 流量动态识别
    if site_config.traffic_analysis_enabled then
        local is_anomalous, score = ddos_advanced.analyze_traffic_pattern(client_ip)
        if is_anomalous then
            -- 记录异常
            utils_advanced.record_anomaly(client_ip, uri, "anomalous_traffic", score)
            
            -- 判断验证方式
            local verification_type, difficulty = select_verification_method(site_config, "traffic_analysis", client_ip, uri)
            
            -- 记录请求
            log_request(site_config, client_ip, uri, 403, true, "anomalous_traffic")
            
            -- 更新统计信息
            update_stats(site_config, client_ip, uri, method, true, "anomalous_traffic")
            
            redirect_to_verification(verification_type, "traffic_analysis", difficulty)
            return
        end
    }
    
    -- 随机抽样检测
    if site_config.request_sampling_enabled and 
       utils_advanced.sample_request(site_config.sampling_rate or 0.01) then
        -- 进行深度行为和特征分析
        local features, feature_data = utils_advanced.extract_request_features(client_ip, uri, method, ngx.req.get_uri_args(), ngx.req.get_headers())
        
        -- 异常检测
        local is_anomalous, distance = utils_advanced.is_anomalous_request(features, site_config.anomaly_threshold or 5.0)
        
        if is_anomalous then
            -- 记录异常
            utils_advanced.record_anomaly(client_ip, uri, "sampled_anomaly", distance)
            
            -- 如果异常分数高，进行验证
            if distance > 8 then
                -- 判断验证方式
                local verification_type, difficulty = select_verification_method(site_config, "anomaly_detection", client_ip, uri)
                
                -- 记录请求
                log_request(site_config, client_ip, uri, 403, true, "anomaly_detection")
                
                -- 更新统计信息
                update_stats(site_config, client_ip, uri, method, true, "anomaly_detection")
                
                redirect_to_verification(verification_type, "anomaly_detection", difficulty)
                return
            end
        end
    }
    
    -- 如果配置了JS加密，注入JS加密脚本
    if site_config.js_encryption_enabled then
        ngx.ctx.js_encryption = true
    end
    
    -- 如果配置了防止浏览器F12，注入相关脚本
    if site_config.prevent_browser_f12 then
        ngx.ctx.prevent_f12 = true
    end
    
    -- 记录正常请求
    log_request(site_config, client_ip, uri, 200, false)
    
    -- 更新统计信息
    update_stats(site_config, client_ip, uri, method, false)
}

-- 执行WAF处理
process_waf()
