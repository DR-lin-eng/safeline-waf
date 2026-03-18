local config_loader = require "config_loader"
local adaptive_runtime = require "adaptive_runtime"
local cjson = require "cjson"

ngx.log(ngx.INFO, "Initializing SafeLine WAF...")

local config, err = config_loader.load_default_config({ reset_shared_state = true })
if not config then
    ngx.log(ngx.ERR, "Failed to load configuration: ", err)
else
    local ok, adaptive = adaptive_runtime.apply_on_init()
    if ok then
        ngx.log(ngx.INFO, "Adaptive runtime applied: ", cjson.encode(adaptive))
    else
        ngx.log(ngx.WARN, "Adaptive runtime skipped: ", tostring(adaptive))
    end
    ngx.log(ngx.INFO, "SafeLine WAF initialized successfully")
end
