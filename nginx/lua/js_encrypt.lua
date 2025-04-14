local _M = {}

-- 引入模块
local cjson = require "cjson"

-- 共享内存
local config_dict = ngx.shared.safeline_config
local cache_dict = ngx.shared.safeline_cache

-- 生成随机字符串
local function random_string(length)
    local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local str = ""
    for i = 1, length do
        local rand = math.random(1, #chars)
        str = str .. string.sub(chars, rand, rand)
    end
    return str
end

-- 获取混淆后的JavaScript代码
function _M.get_obfuscated_js()
    -- 获取配置
    local config_json = config_dict:get("js_encryption")
    local config = {
        renew_interval = 3600, -- 每小时更新一次
        variable_name_length = 8
    }
    
    if config_json then
        local success, parsed_config = pcall(cjson.decode, config_json)
        if success then
            config = parsed_config
        end
    end
    
    -- 检查缓存中是否有混淆过的代码
    local cache_key = "obfuscated_js"
    local cached_js = cache_dict:get(cache_key)
    local timestamp = cache_dict:get(cache_key .. "_timestamp")
    
    -- 如果缓存存在且未过期
    if cached_js and timestamp and (ngx.time() - timestamp < config.renew_interval) then
        return cached_js
    end
    
    -- 生成新的混淆代码
    local var_names = {}
    for i = 1, 10 do
        var_names[i] = random_string(config.variable_name_length)
    end
    
    -- 构建混淆的JavaScript代码
    local js_code = string.format([[
(function() {
    var %s = function(e) { 
        return e.split('').map(function(c) { 
            return String.fromCharCode(c.charCodeAt(0) ^ 7); 
        }).join(''); 
    };
    
    var %s = function(t) { 
        return window.btoa(t).replace(/=/g, ''); 
    };
    
    var %s = function() {
        var %s = %s(%s(navigator.userAgent));
        var %s = %s(%s(document.referrer || ''));
        var %s = %s(%s(window.location.href));
        
        var %s = document.createElement('script');
        %s.type = 'text/javascript';
        %s.src = '/safeline-api/js_verify?ua=' + %s + '&ref=' + %s + '&loc=' + %s;
        document.head.appendChild(%s);
    };
    
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
        setTimeout(%s, 100);
    } else {
        document.addEventListener('DOMContentLoaded', %s);
    }
})();
]], 
        var_names[1], -- encode function
        var_names[2], -- base64 function
        var_names[3], -- init function
        var_names[4], -- ua var
        var_names[2], var_names[1], 
        var_names[5], -- ref var
        var_names[2], var_names[1],
        var_names[6], -- loc var
        var_names[2], var_names[1],
        var_names[7], -- script element
        var_names[7], var_names[7],
        var_names[4], var_names[5], var_names[6],
        var_names[7],
        var_names[3], var_names[3]
    )
    
    -- 保存到缓存
    cache_dict:set(cache_key, js_code, config.renew_interval)
    cache_dict:set(cache_key .. "_timestamp", ngx.time(), config.renew_interval)
    
    return js_code
end

-- 获取防止F12调试的JavaScript代码
function _M.get_prevent_f12_js()
    local js_code = [[
(function() {
    // 检测F12、右键菜单和开发者工具
    function preventDevTools() {
        // 禁用右键菜单
        document.addEventListener('contextmenu', function(e) {
            e.preventDefault();
            return false;
        });
        
        // 禁用F12、Ctrl+Shift+I等快捷键
        document.addEventListener('keydown', function(e) {
            if (
                e.keyCode === 123 || // F12
                (e.ctrlKey && e.shiftKey && e.keyCode === 73) || // Ctrl+Shift+I
                (e.ctrlKey && e.shiftKey && e.keyCode === 74) || // Ctrl+Shift+J
                (e.ctrlKey && e.keyCode === 85) // Ctrl+U
            ) {
                e.preventDefault();
                return false;
            }
        });
        
        // 检测开发者工具是否打开
        function detectDevTools() {
            const widthThreshold = window.outerWidth - window.innerWidth > 160;
            const heightThreshold = window.outerHeight - window.innerHeight > 160;
            
            if (
                widthThreshold || 
                heightThreshold || 
                window.Firebug && window.Firebug.chrome && window.Firebug.chrome.isInitialized
            ) {
                document.body.innerHTML = '<div style="text-align:center;margin-top:100px;font-size:24px;">Developer Tools Detected</div>';
                return true;
            }
            return false;
        }
        
        // 定期检测
        setInterval(detectDevTools, 1000);
    }
    
    // 执行保护措施
    preventDevTools();
})();
]]

    return js_code
end

-- 在响应中注入JavaScript代码
function _M.inject_js(js_code)
    if not js_code then
        js_code = _M.get_obfuscated_js()
    end
    
    -- 在</body>标签前注入脚本
    local response_body = ngx.arg[1]
    
    if response_body then
        local new_response = response_body:gsub("</body>", "<script>" .. js_code .. "</script></body>")
        
        -- 如果找不到</body>标签，尝试在</html>标签前注入
        if new_response == response_body then
            new_response = response_body:gsub("</html>", "<script>" .. js_code .. "</script></html>")
        end
        
        ngx.arg[1] = new_response
    end
end

return _M
