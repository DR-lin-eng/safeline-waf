local cjson = require "cjson"
local config_dict = ngx.shared.safeline_config
local blacklist_bloom = require "blacklist_bloom"
local config_reload_subscriber_started = false
local blacklist_subscriber_started = false
local ml_runtime_started = false

-- 启动 Bloom filter 定时刷新
local ok, err = blacklist_bloom.start()
if not ok then
    ngx.log(ngx.ERR, "Failed to start blacklist bloom refresh: ", err)
end

-- 定时清理各 shared dict 的过期条目，防止内存碎片积累
-- 使用 init_worker 是因为每个 worker 独立运行（只有 worker 0 执行，避免多次重复清理）
if ngx.worker.id() == 0 then
    local cache_dict = ngx.shared.safeline_cache
    local limit_dict = ngx.shared.safeline_limit
    local counters_dict = ngx.shared.safeline_counters
    local blacklist_dict = ngx.shared.safeline_blacklist

    local function flush_expired_dicts()
        cache_dict:flush_expired()
        limit_dict:flush_expired()
        counters_dict:flush_expired()
        blacklist_dict:flush_expired()
    end

    -- 每60秒清理一次过期条目
    local function schedule_cleanup()
        local ok_t, t_err = ngx.timer.at(60, function(premature)
            if premature then return end
            pcall(flush_expired_dicts)
            schedule_cleanup()
        end)
        if not ok_t then
            ngx.log(ngx.ERR, "Failed to schedule dict cleanup timer: ", t_err)
        end
    end

    schedule_cleanup()

    local function cluster_runtime_enabled()
        if os.getenv("CLUSTER_ENABLED") == "false" then
            return false
        end

        local raw = config_dict:get("cluster")
        if type(raw) ~= "string" or raw == "" then
            return false
        end

        local ok_cluster, cluster = pcall(cjson.decode, raw)
        return ok_cluster and type(cluster) == "table" and cluster.enabled == true
    end

    local function ensure_config_reload_subscriber_started()
        if config_reload_subscriber_started or not cluster_runtime_enabled() then
            return
        end

        config_reload_subscriber_started = true
        ngx.log(ngx.NOTICE, "[Cluster] Starting config reload subscriber")

        -- Subscribe to config reload events
        local config_loader = require "config_loader"
        ngx.timer.at(0, function(premature)
            if premature then return end
            local ok, err = pcall(config_loader.subscribe_cluster_reload)
            if not ok then
                ngx.log(ngx.ERR, "[Cluster] Config reload subscriber error: ", err)
            end
        end)

    end

    local function ensure_blacklist_subscriber_started()
        if blacklist_subscriber_started then
            return
        end

        blacklist_subscriber_started = true
        ngx.log(ngx.NOTICE, "[Cluster] Starting blacklist sync subscriber")

        local ip_blacklist = require "ip_blacklist"
        ngx.timer.at(0, function(premature)
            if premature then return end
            local ok, err = pcall(ip_blacklist.subscribe_cluster_blacklist)
            if not ok then
                ngx.log(ngx.ERR, "[Cluster] Blacklist sync subscriber error: ", err)
            end
        end)
    end

    ensure_config_reload_subscriber_started()
    ensure_blacklist_subscriber_started()

    local function schedule_cluster_runtime_watch()
        local ok_t, t_err = ngx.timer.at(5, function(premature)
            if premature then return end
            ensure_config_reload_subscriber_started()
            ensure_blacklist_subscriber_started()
            schedule_cluster_runtime_watch()
        end)
        if not ok_t then
            ngx.log(ngx.ERR, "Failed to schedule cluster runtime watcher: ", t_err)
        end
    end

    schedule_cluster_runtime_watch()
end

-- ─── ML Engine Initialisation ────────────────────────────────────────────
local ml_inference = require "ml_inference"

local function ensure_ml_runtime_started()
    if ml_runtime_started then
        return
    end
    ml_runtime_started = true

    -- Attempt to load the active model a couple of seconds after startup
    -- (Redis might not be fully ready at init_worker time)
    ngx.timer.at(2, function(premature)
        if premature then return end
        local ok, info = pcall(ml_inference.load_model)
        if not ok then
            ngx.log(ngx.WARN, "[ML] Initial model load error: ", tostring(info))
        elseif info ~= "no_active_model" then
            ngx.log(ngx.NOTICE, "[ML] Model ready: ", tostring(info))
        end
    end)

    -- Only worker 0 subscribes to reload events
    if ngx.worker.id() == 0 then
        ngx.timer.at(0, function(premature)
            if premature then return end
            local ok, err = pcall(ml_inference.subscribe_model_reload)
            if not ok then
                ngx.log(ngx.ERR, "[ML] Model reload subscriber error: ", err)
            end
        end)
    end
end

ensure_ml_runtime_started()
