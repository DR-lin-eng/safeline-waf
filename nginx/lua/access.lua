-- 引入所需模块
local cjson = require "cjson"
local lfs = require "lfs"

-- 全局配置变量
local config_dict = ngx.shared.safeline_config
local blacklist_dict = ngx.shared.safeline_blacklist

-- 读取配置文件
local function load_config()
    local config_path = ngx.config.prefix() .. "conf/config/default_config.json"
    local file = io.open(config_path, "r")
    
    if not file then
        ngx.log(ngx.ERR, "Failed to open config file: " .. config_path)
        return false
    end
    
    local content = file:read("*a")
    file:close()
    
    local success, config = pcall(cjson.decode, content)
    if not success then
        ngx.log(ngx.ERR, "Failed to parse config JSON: " .. config)
        return false
    end
    
    -- 保存全局配置到共享内存
    for k, v in pairs(config) do
        if type(v) == "table" then
            config_dict:set(k, cjson.encode(v))
        else
            config_dict:set(k, v)
        end
    end
    
    -- 加载IP黑名单
    if config.ip_blacklist then
        for _, ip in ipairs(config.ip_blacklist) do
            blacklist_dict:set(ip, true)
        end
    end
    
    return true
end

-- 加载站点配置
local function load_site_configs()
    local sites_dir = ngx.config.prefix() .. "conf/config/sites"
    
    for file in lfs.dir(sites_dir) do
        if file:match("%.json$") then
            local file_path = sites_dir .. "/" .. file
            local f = io.open(file_path, "r")
            
            if f then
                local content = f:read("*a")
                f:close()
                
                local success, site_config = pcall(cjson.decode, content)
                if success and site_config.domain then
                    config_dict:set("site:" .. site_config.domain, cjson.encode(site_config))
                    ngx.log(ngx.INFO, "Loaded site config for: " .. site_config.domain)
                else
                    ngx.log(ngx.ERR, "Failed to parse site config: " .. file_path)
                end
            end
        end
    end
end

-- 连接Redis
local function setup_redis()
    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeout(1000) -- 1 second timeout
    
    local ok, err = red:connect("redis", 6379)
    if not ok then
        ngx.log(ngx.ERR, "Failed to connect to Redis: ", err)
        return nil
    end
    
    -- 检查连接是否正常
    local res, err = red:ping()
    if not res then
        ngx.log(ngx.ERR, "Failed to ping Redis: ", err)
        return nil
    end
    
    ngx.log(ngx.INFO, "Successfully connected to Redis")
    
    -- 将连接放回连接池
    local ok, err = red:set_keepalive(10000, 100)
    if not ok then
        ngx.log(ngx.ERR, "Failed to set Redis keepalive: ", err)
    end
    
    return true
end

-- 初始化函数
local function init()
    ngx.log(ngx.INFO, "Initializing SafeLine WAF...")
    
    -- 加载主配置
    if not load_config() then
        ngx.log(ngx.ERR, "Failed to load main configuration")
    end
    
    -- 加载站点配置
    load_site_configs()
    
    -- 设置Redis连接
    if not setup_redis() then
        ngx.log(ngx.WARN, "Redis connection failed, some features may not work properly")
    end
    
    ngx.log(ngx.INFO, "SafeLine WAF initialized successfully")
end

-- 执行初始化
init()
