local _M = {}

-- 引入模块
local resty_sha256 = require "resty.sha256"
local resty_random = require "resty.random"
local str = require "resty.string"
local cjson = require "cjson"

-- 共享内存
local cache_dict = ngx.shared.safeline_cache
local config_dict = ngx.shared.safeline_config

local function safe_incr(dict, key, value, init, ttl, fallback)
    local newval = dict:incr(key, value, init, ttl)
    if newval == nil then
        if fallback ~= nil then
            return fallback
        end
        return init or 0
    end
    return newval
end

local function acquire_single_verification_lock(key, ttl)
    local ok, err = cache_dict:add(key, true, ttl)
    if ok then
        return true
    end

    if err == "exists" then
        return false, "Challenge is already being verified"
    end

    return false, "Failed to acquire verification lock"
end

local function random_hex(bytes_len, fallback_len)
    local bytes = resty_random and resty_random.bytes(bytes_len, true) or nil
    if bytes then
        return str.to_hex(bytes)
    end

    local seed = table.concat({
        tostring(ngx.now()),
        tostring(math.random(1000000, 9999999)),
        tostring(ngx.worker.pid()),
        tostring(ngx.var.request_id or "")
    }, ":")
    local hex = ngx.md5(seed)
    if type(fallback_len) == "number" and fallback_len > 0 and fallback_len < #hex then
        return hex:sub(1, fallback_len)
    end
    return hex
end

local function read_request_body_json()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        local body_file = ngx.req.get_body_file()
        if body_file then
            local f = io.open(body_file, "rb")
            if f then
                body = f:read("*a")
                f:close()
            end
        end
    end

    if type(body) ~= "string" or body == "" then
        return nil
    end

    local ok, data = pcall(cjson.decode, body)
    if ok and type(data) == "table" then
        return data
    end

    return nil
end

-- 生成POW挑战
function _M.generate_challenge(client_ip, uri, difficulty, context)
    -- 如果没有指定难度，使用默认值
    if not difficulty then
        local config_json = config_dict:get("pow_config")
        local config = {
            base_difficulty = 4,
            max_difficulty = 8
        }
        
        if config_json then
            local success, parsed_config = pcall(cjson.decode, config_json)
            if success then
                config = parsed_config
            end
        end
        
        difficulty = config.base_difficulty
        
        -- 根据客户端请求频率动态调整难度
        local rate_key = "pow_rate:" .. client_ip
        local req_count = safe_incr(cache_dict, rate_key, 1, 0, 300, 0) -- 5分钟窗口
        
        if req_count > 10 then
            -- 随着请求次数增加，逐渐增加难度
            local added_difficulty = math.floor(req_count / 10)
            difficulty = math.min(config.max_difficulty, difficulty + added_difficulty)
        end
    end
    
    -- 生成挑战数据
    local challenge_id = random_hex(16, 32)
    local challenge = {
        challenge_id = challenge_id,
        prefix = random_hex(8, 16),
        difficulty = difficulty,
        expires = ngx.time() + 300, -- 5分钟有效期
        uri = uri,
        ip = context and context.ip or client_ip,
        ua_hash = context and context.ua_hash or nil,
        host = context and context.host or nil,
        path = context and context.path or uri,
        reason = context and context.reason or nil,
        verification_type = context and context.verification_type or "pow",
        method = context and context.method or nil
    }
    
    -- 保存挑战到缓存
    local challenge_key = "pow_challenge:" .. challenge_id
    cache_dict:set(challenge_key, cjson.encode(challenge), 300)
    
    return challenge
end

-- 验证POW解答
function _M.verify_solution(client_ip, token_data, user_agent)
    local content_type = ngx.var.http_content_type or ""
    local body_json = nil
    local args = nil

    if content_type:find("application/json", 1, true) then
        body_json = read_request_body_json()
    else
        ngx.req.read_body()
        local post_args = ngx.req.get_post_args()
        if type(post_args) == "table" then
            args = post_args
        end
    end

    local challenge_id = body_json and body_json.challenge_id or (args and args.challenge_id) or nil
    local nonce = body_json and body_json.nonce or (args and args.nonce) or nil

    if type(challenge_id) ~= "string" or challenge_id == "" then
        return false, "Missing challenge_id"
    end

    if type(nonce) ~= "string" and type(nonce) ~= "number" then
        return false, "Missing nonce"
    end

    if not ngx.re.match(challenge_id, "^[0-9a-f]{32}$") then
        return false, "Invalid challenge_id"
    end

    local nonce_str = tostring(nonce)
    if #nonce_str > 32 or not nonce_str:match("^%d+$") then
        return false, "Invalid nonce"
    end

    local challenge_key = "pow_challenge:" .. challenge_id
    local verify_lock_key = challenge_key .. ":verify_lock"
    local locked, lock_err = acquire_single_verification_lock(verify_lock_key, 5)
    if not locked then
        return false, lock_err
    end

    local function release_lock()
        cache_dict:delete(verify_lock_key)
    end

    -- 获取挑战
    local challenge_json = cache_dict:get(challenge_key)
    
    if not challenge_json then
        release_lock()
        return false, "Challenge not found or expired"
    end
    
    local success, challenge = pcall(cjson.decode, challenge_json)
    if not success then
        release_lock()
        return false, "Invalid challenge data"
    end
    
    -- 检查挑战是否过期
    if challenge.expires < ngx.time() then
        cache_dict:delete(challenge_key)
        release_lock()
        return false, "Challenge expired"
    end

    if challenge.ip and challenge.ip ~= client_ip then
        release_lock()
        return false, "Challenge does not match client"
    end

    if challenge.ua_hash and challenge.ua_hash ~= ngx.md5(user_agent or "") then
        release_lock()
        return false, "Challenge does not match client"
    end

    if type(token_data) == "table" then
        if challenge.host and challenge.host ~= token_data.host then
            release_lock()
            return false, "Challenge context mismatch"
        end

        if challenge.path and challenge.path ~= token_data.path then
            release_lock()
            return false, "Challenge context mismatch"
        end

        if challenge.reason and challenge.reason ~= token_data.reason then
            release_lock()
            return false, "Challenge context mismatch"
        end

        if challenge.verification_type and challenge.verification_type ~= token_data.verification_type then
            release_lock()
            return false, "Challenge context mismatch"
        end

        if challenge.method and challenge.method ~= token_data.method then
            release_lock()
            return false, "Challenge context mismatch"
        end
    end

    local prefix = challenge.prefix
    local difficulty = challenge.difficulty

    -- 防止nonce重放：使用add原子写入，避免多worker下的TOCTOU竞争
    local nonce_key = "pow_used_nonce:" .. challenge_id .. ":" .. ngx.md5(prefix .. nonce_str)
    local added, add_err = cache_dict:add(nonce_key, true, 300)
    if not added then
        release_lock()
        if add_err == "exists" then
            return false, "Nonce already used"
        end
        return false, "Failed to reserve nonce"
    end
    
    -- 验证工作量证明
    local sha256 = resty_sha256:new()
    local input = prefix .. nonce_str
    sha256:update(input)
    local hash = str.to_hex(sha256:final())
    
    -- 检查哈希值是否满足难度要求
    -- 难度N表示哈希前N位必须为0
    local pattern = "^" .. string.rep("0", difficulty)
    
    if not hash:match(pattern) then
        cache_dict:delete(nonce_key)
        release_lock()
        return false, "Invalid solution"
    end
    
    -- 标记该IP已完成POW验证
    local verified_key = "pow_verified:" .. client_ip
    cache_dict:set(verified_key, true, 1800) -- 30分钟内有效
    
    -- 如果是特定URI的验证，也标记该URI
    if challenge.uri then
        local uri_key = "pow_uri:" .. client_ip .. ":" .. challenge.uri
        cache_dict:set(uri_key, true, 1800)
    end
    
    -- 清除挑战
    cache_dict:delete(challenge_key)
    release_lock()
    
    return true, "Verification successful"
end

-- 检查客户端是否已通过POW验证
function _M.is_verified(client_ip, uri)
    -- 检查全局验证
    local verified_key = "pow_verified:" .. client_ip
    local verified = cache_dict:get(verified_key)
    
    if verified then
        return true
    end
    
    -- 检查特定URI验证
    if uri then
        local uri_key = "pow_uri:" .. client_ip .. ":" .. uri
        local uri_verified = cache_dict:get(uri_key)
        
        if uri_verified then
            return true
        end
    end
    
    return false
end

-- 生成客户端POW计算脚本
function _M.get_pow_script()
    local html = {
        '<!doctype html>',
        '<html lang="zh-CN">',
        '<head>',
        '  <meta charset="utf-8" />',
        '  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />',
        '  <meta http-equiv="Content-Security-Policy" content="default-src \'self\' \'unsafe-inline\' blob:" />',
        '  <meta name="color-scheme" content="light dark" />',
        '  <title>安全验证 - Proof of Work</title>',
        '  <style>',
        '    :root {',
        '      --bg: #f5f7fb;',
        '      --card: #ffffff;',
        '      --text: #111827;',
        '      --muted: #6b7280;',
        '      --border: rgba(17, 24, 39, 0.12);',
        '      --accent: #2563eb;',
        '      --accent-2: #60a5fa;',
        '      --danger: #dc2626;',
        '      --shadow: 0 10px 30px rgba(0,0,0,0.08);',
        '    }',
        '    @media (prefers-color-scheme: dark) {',
        '      :root {',
        '        --bg: #0b1220;',
        '        --card: #0f172a;',
        '        --text: #e5e7eb;',
        '        --muted: #94a3b8;',
        '        --border: rgba(148, 163, 184, 0.20);',
        '        --accent: #60a5fa;',
        '        --accent-2: #93c5fd;',
        '        --danger: #f87171;',
        '        --shadow: 0 10px 30px rgba(0,0,0,0.35);',
        '      }',
        '    }',
        '    * { box-sizing: border-box; }',
        '    html, body { height: 100%; }',
        '    body {',
        '      margin: 0;',
        '      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji";',
        '      background: radial-gradient(1200px 600px at 20% 10%, rgba(37,99,235,0.10), transparent 60%),',
        '                  radial-gradient(900px 500px at 90% 30%, rgba(96,165,250,0.12), transparent 55%),',
        '                  var(--bg);',
        '      color: var(--text);',
        '      display: flex;',
        '      align-items: center;',
        '      justify-content: center;',
        '      padding: 20px;',
        '    }',
        '    .card {',
        '      width: 100%;',
        '      max-width: 560px;',
        '      background: var(--card);',
        '      border: 1px solid var(--border);',
        '      border-radius: 16px;',
        '      box-shadow: var(--shadow);',
        '      padding: 22px 22px 18px;',
        '    }',
        '    h1 {',
        '      margin: 0 0 8px;',
        '      font-size: 20px;',
        '      line-height: 1.25;',
        '    }',
        '    .desc {',
        '      margin: 0 0 18px;',
        '      color: var(--muted);',
        '      font-size: 14px;',
        '      line-height: 1.6;',
        '    }',
        '    .status {',
        '      display: flex;',
        '      gap: 10px;',
        '      align-items: center;',
        '      justify-content: space-between;',
        '      margin: 12px 0 10px;',
        '      font-size: 14px;',
        '      color: var(--muted);',
        '    }',
        '    .status strong { color: var(--text); font-weight: 600; }',
        '    .progress {',
        '      position: relative;',
        '      height: 18px;',
        '      border-radius: 999px;',
        '      overflow: hidden;',
        '      border: 1px solid var(--border);',
        '      background: rgba(148, 163, 184, 0.10);',
        '    }',
        '    .bar {',
        '      height: 100%;',
        '      width: 100%;',
        '      background: linear-gradient(90deg, rgba(37,99,235,0.25), rgba(96,165,250,0.55), rgba(37,99,235,0.25));',
        '      background-size: 200% 100%;',
        '      animation: shimmer 1.1s linear infinite;',
        '      filter: saturate(1.1);',
        '    }',
        '    .progressLabel {',
        '      position: absolute;',
        '      inset: 0;',
        '      display: flex;',
        '      align-items: center;',
        '      justify-content: center;',
        '      font-size: 12px;',
        '      font-weight: 600;',
        '      color: var(--text);',
        '      pointer-events: none;',
        '      text-shadow: 0 1px 1px rgba(0,0,0,0.18);',
        '    }',
        '    @keyframes shimmer {',
        '      0% { background-position: 0% 0; }',
        '      100% { background-position: 200% 0; }',
        '    }',
        '    .attempts {',
        '      margin-top: 10px;',
        '      display: flex;',
        '      align-items: center;',
        '      justify-content: space-between;',
        '      gap: 8px;',
        '      color: var(--muted);',
        '      font-size: 13px;',
        '    }',
        '    code {',
        '      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;',
        '      font-size: 12px;',
        '      padding: 2px 6px;',
        '      border-radius: 8px;',
        '      border: 1px solid var(--border);',
        '      background: rgba(148, 163, 184, 0.10);',
        '      color: var(--text);',
        '    }',
        '    .error {',
        '      margin-top: 14px;',
        '      padding: 10px 12px;',
        '      border-radius: 12px;',
        '      border: 1px solid rgba(220, 38, 38, 0.35);',
        '      background: rgba(220, 38, 38, 0.10);',
        '      color: var(--danger);',
        '      font-size: 13px;',
        '      line-height: 1.5;',
        '      display: none;',
        '      white-space: pre-wrap;',
        '      word-break: break-word;',
        '    }',
        '    .actions {',
        '      margin-top: 14px;',
        '      display: flex;',
        '      justify-content: flex-end;',
        '      gap: 10px;',
        '    }',
        '    button {',
        '      appearance: none;',
        '      border: 1px solid var(--border);',
        '      background: transparent;',
        '      color: var(--text);',
        '      border-radius: 12px;',
        '      padding: 10px 12px;',
        '      font-size: 14px;',
        '      cursor: pointer;',
        '    }',
        '    button.primary {',
        '      border-color: rgba(37, 99, 235, 0.35);',
        '      background: rgba(37, 99, 235, 0.10);',
        '    }',
        '    button:disabled { opacity: 0.6; cursor: not-allowed; }',
        '  </style>',
        '</head>',
        '<body>',
        '  <div class="card">',
        '    <h1>系统正在进行安全验证</h1>',
        '    <p class="desc">为继续访问，浏览器需要完成一次工作量证明（PoW）计算。该计算会在后台线程中运行，不会阻塞页面。</p>',
        '    <div class="status">',
        '      <div id="statusText"><strong id="statusStrong">正在获取挑战…</strong></div>',
        '      <div><span>难度：</span><code id="difficulty">-</code></div>',
        '    </div>',
        '    <div class="progress" aria-label="PoW progress">',
        '      <div class="bar" id="progressBar"></div>',
        '      <div class="progressLabel" id="progressLabel">0 次尝试</div>',
        '    </div>',
        '    <div class="attempts">',
        '      <div>已尝试：<strong id="tried">0</strong> 次</div>',
        '      <div>前缀：<code id="prefix">-</code></div>',
        '    </div>',
        '    <div class="error" id="errorBox"></div>',
        '    <div class="actions">',
        '      <button id="retryBtn" class="primary" style="display:none;">重试</button>',
        '    </div>',
        '  </div>',
        '  <script>',
        '    (function(){',
        '      "use strict";',
        '',
        '      var statusStrong = document.getElementById("statusStrong");',
        '      var progressLabel = document.getElementById("progressLabel");',
        '      var triedEl = document.getElementById("tried");',
        '      var prefixEl = document.getElementById("prefix");',
        '      var difficultyEl = document.getElementById("difficulty");',
        '      var errorBox = document.getElementById("errorBox");',
        '      var retryBtn = document.getElementById("retryBtn");',
        '',
        '      var worker = null;',
        '      var workerUrl = null;',
        '      var currentChallengeId = null;',
        '',
        '      function setStatus(text) {',
        '        statusStrong.textContent = String(text);',
        '      }',
        '',
        '      function setError(text) {',
        '        errorBox.style.display = "block";',
        '        errorBox.textContent = String(text || "验证失败");',
        '        retryBtn.style.display = "inline-block";',
        '      }',
        '',
        '      function clearError() {',
        '        errorBox.style.display = "none";',
        '        errorBox.textContent = "";',
        '        retryBtn.style.display = "none";',
        '      }',
        '',
        '      function setTried(n) {',
        '        var v = (Number(n) || 0);',
        '        var formatted = v.toLocaleString();',
        '        triedEl.textContent = formatted;',
        '        progressLabel.textContent = formatted + " 次尝试";',
        '      }',
        '',
        '      function cleanupWorker() {',
        '        try {',
        '          if (worker) worker.terminate();',
        '        } catch (_) {}',
        '        worker = null;',
        '',
        '        try {',
        '          if (workerUrl) URL.revokeObjectURL(workerUrl);',
        '        } catch (_) {}',
        '        workerUrl = null;',
        '      }',
        '',
        '      window.addEventListener("unload", function(){',
        '        cleanupWorker();',
        '      });',
        '',
        '      function createPowWorker() {',
        '        var code = [',
        '          "\'use strict\';",',
        '          "var encoder = new TextEncoder();",',
        '          "function bufToHex(buf){",',
        '          "  var b = new Uint8Array(buf);",',
        '          "  var out = \'\';",',
        '          "  for (var i=0;i<b.length;i++){",',
        '          "    var v = b[i];",',
        '          "    out += (v >>> 4).toString(16);",',
        '          "    out += (v & 15).toString(16);",',
        '          "  }",',
        '          "  return out;",',
        '          "}",',
        '          "function rotr(x,n){ return (x>>>n) | (x<<(32-n)); }",',
        '          "var K = [",',
        '          "  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,",',
        '          "  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,",',
        '          "  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,",',
        '          "  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,",',
        '          "  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,",',
        '          "  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,",',
        '          "  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,",',
        '          "  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2",',
        '          "];",',
        '          "function sha256js(bytes){",',
        '          "  var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];",',
        '          "  var l = bytes.length;",',
        '          "  var bitHi = Math.floor((l * 8) / 4294967296);",',
        '          "  var bitLo = (l * 8) >>> 0;",',
        '          "  var withOne = l + 1;",',
        '          "  var padLen = ((withOne + 8 + 63) & ~63) - withOne - 8;",',
        '          "  var total = l + 1 + padLen + 8;",',
        '          "  var buf = new Uint8Array(total);",',
        '          "  buf.set(bytes);",',
        '          "  buf[l] = 0x80;",',
        '          "  var view = new DataView(buf.buffer);",',
        '          "  view.setUint32(total - 8, bitHi);",',
        '          "  view.setUint32(total - 4, bitLo);",',
        '          "  var W = new Uint32Array(64);",',
        '          "  for (var off=0; off<total; off+=64){",',
        '          "    for (var i=0;i<16;i++){ W[i] = view.getUint32(off + i*4); }",',
        '          "    for (var i2=16;i2<64;i2++){",',
        '          "      var v15 = W[i2-15];",',
        '          "      var v2 = W[i2-2];",',
        '          "      var s0 = rotr(v15,7) ^ rotr(v15,18) ^ (v15>>>3);",',
        '          "      var s1 = rotr(v2,17) ^ rotr(v2,19) ^ (v2>>>10);",',
        '          "      W[i2] = (W[i2-16] + s0 + W[i2-7] + s1) >>> 0;",',
        '          "    }",',
        '          "    var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];",',
        '          "    for (var j=0;j<64;j++){",',
        '          "      var S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);",',
        '          "      var ch = (e & f) ^ (~e & g);",',
        '          "      var t1 = (h + S1 + ch + K[j] + W[j]) >>> 0;",',
        '          "      var S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);",',
        '          "      var maj = (a & b) ^ (a & c) ^ (b & c);",',
        '          "      var t2 = (S0 + maj) >>> 0;",',
        '          "      h=g; g=f; f=e; e=(d + t1) >>> 0; d=c; c=b; b=a; a=(t1 + t2) >>> 0;",',
        '          "    }",',
        '          "    H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;",',
        '          "    H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;",',
        '          "  }",',
        '          "  var hex = \'\';",',
        '          "  for (var k=0;k<8;k++){ hex += (\'00000000\' + H[k].toString(16)).slice(-8); }",',
        '          "  return hex;",',
        '          "}",',
        '          "async function sha256Hex(input){",',
        '          "  var data = encoder.encode(input);",',
        '          "  if (self.crypto && self.crypto.subtle && self.crypto.subtle.digest){",',
        '          "    try {",',
        '          "      var digest = await self.crypto.subtle.digest(\'SHA-256\', data);",',
        '          "      return bufToHex(digest);",',
        '          "    } catch (_) {}",',
        '          "  }",',
        '          "  return sha256js(data);",',
        '          "}",',
        '          "self.onmessage = async function(ev){",',
        '          "  var payload = ev.data || {}; ",',
        '          "  var prefix = String(payload.prefix || \'\');",',
        '          "  var difficulty = Number(payload.difficulty || 0);",',
        '          "  var startNonce = Number(payload.start_nonce || 0);",',
        '          "  if (!prefix || !difficulty) { self.postMessage({type:\'error\', message:\'invalid_params\'}); return; }",',
        '          "  var target = Array(difficulty + 1).join(\'0\');",',
        '          "  var nonce = startNonce;",',
        '          "  var tried = 0;",',
        '          "  while (true){",',
        '          "    var h = await sha256Hex(prefix + String(nonce));",',
        '          "    tried++;",',
        '          "    if (h.indexOf(target) === 0){",',
        '          "      self.postMessage({type:\'found\', nonce: nonce, hash: h});",',
        '          "      return;",',
        '          "    }",',
        '          "    if (tried % 1000 === 0){",',
        '          "      self.postMessage({type:\'progress\', tried: tried});",',
        '          "    }",',
        '          "    nonce++;",',
        '          "  }",',
        '          "};"',
        '        ].join(\"\\n\");',
        '',
        '        workerUrl = URL.createObjectURL(new Blob([code], {type: "text/javascript"}));',
        '        worker = new Worker(workerUrl);',
        '        return worker;',
        '      }',
        '',
        '      function safeJson(res) {',
        '        return res.json().catch(function(){ return {}; });',
        '      }',
        '',
        '      function fetchChallenge() {',
        '        setStatus("正在获取挑战…");',
        '        return fetch("/pow/challenge", {',
        '          method: "GET",',
        '          credentials: "same-origin",',
        '          headers: { "Accept": "application/json" }',
        '        }).then(function(res){',
        '          return safeJson(res).then(function(data){',
        '            if (!res.ok) {',
        '              throw new Error(data.message || ("challenge_http_" + res.status));',
        '            }',
        '            if (data && data.success === false) {',
        '              throw new Error(data.message || "获取挑战失败");',
        '            }',
        '            if (!data || !data.challenge_id || !data.prefix || !data.difficulty) {',
        '              throw new Error("挑战数据不完整");',
        '            }',
        '            return data;',
        '          });',
        '        });',
        '      }',
        '',
        '      function verifySolution(challengeId, nonce) {',
        '        setStatus("验证中…");',
        '        return fetch("/pow/verify", {',
        '          method: "POST",',
        '          credentials: "same-origin",',
        '          headers: { "Content-Type": "application/json", "Accept": "application/json" },',
        '          body: JSON.stringify({ challenge_id: challengeId, nonce: nonce })',
        '        }).then(function(res){',
        '          return safeJson(res).then(function(data){',
        '            if (!res.ok || (data && data.success === false)) {',
        '              throw new Error((data && data.message) || ("verify_http_" + res.status));',
        '            }',
        '            return data;',
        '          });',
        '        });',
        '      }',
        '',
        '      function startPow(prefix, difficulty, challengeId) {',
        '        cleanupWorker();',
        '        clearError();',
        '        currentChallengeId = challengeId;',
        '        prefixEl.textContent = String(prefix);',
        '        difficultyEl.textContent = String(difficulty);',
        '        setTried(0);',
        '        setStatus("计算中…");',
        '',
        '        var w = createPowWorker();',
        '        w.onmessage = function(ev){',
        '          var msg = ev.data || {};',
        '          if (msg.type === "progress") {',
        '            setTried(msg.tried);',
        '            return;',
        '          }',
        '          if (msg.type === "found") {',
        '            setTried(msg.nonce + 1);',
        '            cleanupWorker();',
        '            verifySolution(currentChallengeId, msg.nonce)',
        '              .then(function(data){',
        '                setStatus("验证成功，即将跳转…");',
        '                var redirectUrl = data && data.redirect_url;',
        '                if (redirectUrl) {',
        '                  window.location.replace(redirectUrl);',
        '                  return;',
        '                }',
        '                window.location.replace("/");',
        '              })',
        '              .catch(function(err){',
        '                setStatus("验证失败");',
        '                setError(err && err.message ? err.message : String(err));',
        '              });',
        '            return;',
        '          }',
        '          if (msg.type === "error") {',
        '            setStatus("计算失败");',
        '            setError(msg.message || "worker_error");',
        '            return;',
        '          }',
        '        };',
        '',
        '        w.onerror = function(){',
        '          setStatus("计算失败");',
        '          setError("worker_crashed");',
        '        };',
        '',
        '        w.postMessage({ prefix: prefix, difficulty: Number(difficulty) });',
        '      }',
        '',
        '      function start() {',
        '        cleanupWorker();',
        '        clearError();',
        '        prefixEl.textContent = "-";',
        '        difficultyEl.textContent = "-";',
        '        setTried(0);',
        '        fetchChallenge()',
        '          .then(function(ch){',
        '            startPow(ch.prefix, Number(ch.difficulty), ch.challenge_id);',
        '          })',
        '          .catch(function(err){',
        '            setStatus("无法获取挑战");',
        '            setError(err && err.message ? err.message : String(err));',
        '          });',
        '      }',
        '',
        '      retryBtn.addEventListener("click", function(){',
        '        start();',
        '      });',
        '',
        '      start();',
        '    })();',
        '  </script>',
        '</body>',
        '</html>',
    }

    return table.concat(html, "\n")
end

return _M
