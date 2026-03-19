-- 高级访问控制模块
local cjson = require "cjson"
local utils = require "utils"
local config_loader = require "config_loader"
local browser_detection = require "browser_detection"
local ip_blacklist = require "ip_blacklist"
local ddos_protection = require "ddos_protection"
local llm_auditor = require "llm_auditor"
local feature_extractor = require "semantic.feature_extractor"

-- 共享内存
local config_dict = ngx.shared.safeline_config
local cache_dict = ngx.shared.safeline_cache
local limit_dict = ngx.shared.safeline_limit
local blacklist_dict = ngx.shared.safeline_blacklist
local counters_dict = ngx.shared.safeline_counters

local dangerous_methods = {
    TRACE = true,
    TRACK = true,
    DEBUG = true,
    CONNECT = true
}

local normalize_inspection_text

local function build_inspection_preview(value, max_len)
    if value == nil then
        return ""
    end

    if type(value) ~= "string" then
        value = tostring(value)
    end

    value = value:gsub("[%z\1-\8\11\12\14-\31\127]", " ")
    value = value:gsub("%s+", " ")

    local limit = tonumber(max_len or 240) or 240
    if limit < 64 then
        limit = 64
    end

    if #value > limit then
        return value:sub(1, limit) .. "…"
    end

    return value
end

local function persist_inspection_summary(summary)
    if type(summary) ~= "table" or type(summary.request_id) ~= "string" or summary.request_id == "" then
        return false
    end

    local ok = utils.log_event("inspection", summary)
    if not ok then
        return false
    end

    local encoded_ok, encoded = pcall(cjson.encode, summary)
    if not encoded_ok or type(encoded) ~= "string" then
        return false
    end

    ngx.timer.at(0, function(premature)
        if premature then
            return
        end

        local red = utils.get_redis(200)
        if not red then
            return
        end

        local ok_push = pcall(function()
            red:lpush("inspection:events", encoded)
            red:ltrim("inspection:events", 0, 499)
            red:set("inspection:event:" .. summary.request_id, encoded)
            red:expire("inspection:event:" .. summary.request_id, 86400)
        end)

        if not ok_push then
            ngx.log(ngx.WARN, "[Inspection] Failed to persist inspection summary")
        end

        utils.release_redis(red)
    end)

    return true
end

local function build_payload_inspection_summary(candidate, signature_id, score, source, label)
    if type(candidate) ~= "table" then
        return nil
    end

    local analysis = feature_extractor.analyze(candidate.raw or candidate.normalized or "")
    local meta = (analysis and analysis.meta) or {}
    local normalized = type(meta.normalized) == "string" and meta.normalized or candidate.normalized or ""
    local encoding_layers = type(meta.encoding_layers) == "table" and meta.encoding_layers or {}

    return {
        trigger_reason = "payload_" .. tostring(signature_id or "malicious_input"),
        source = source or candidate.source or "unknown",
        label = label or candidate.label or "payload",
        matched_signature = signature_id or "malicious_input",
        score = tonumber(score or 0) or 0,
        body_preview = build_inspection_preview(candidate.raw or candidate.normalized or "", 240),
        normalized_preview = build_inspection_preview(normalized, 240),
        encoding_layers = encoding_layers,
        encoding_layer_count = #encoding_layers,
        obfusc_score = tonumber(meta.obfusc_score or 0) or 0,
        attack_class = (analysis and analysis.class) or "unknown",
        confidence = tonumber((analysis and analysis.confidence) or 0) or 0,
        sql_hits = tonumber(meta.sql_hits or 0) or 0,
        xss_hits = tonumber(meta.xss_hits or 0) or 0,
    }
end

local function normalize_inspection_summary(summary, client_ip, uri, method, status, is_blocked)
    if type(summary) ~= "table" then
        return nil
    end

    return {
        request_id = ensure_request_id(),
        ip = client_ip,
        host = ngx.var.host or "",
        method = method or ngx.req.get_method(),
        uri = uri,
        status = tonumber(status) or 0,
        is_blocked = is_blocked == true,
        trigger_reason = summary.trigger_reason or "inspection",
        source = summary.source or "unknown",
        label = summary.label or "payload",
        matched_signature = summary.matched_signature or "unknown",
        score = tonumber(summary.score or 0) or 0,
        body_preview = build_inspection_preview(summary.body_preview or "", 240),
        normalized_preview = build_inspection_preview(summary.normalized_preview or "", 240),
        encoding_layers = type(summary.encoding_layers) == "table" and summary.encoding_layers or {},
        encoding_layer_count = tonumber(summary.encoding_layer_count or 0) or 0,
        obfusc_score = tonumber(summary.obfusc_score or 0) or 0,
        attack_class = summary.attack_class or "unknown",
        confidence = tonumber(summary.confidence or 0) or 0,
        sql_hits = tonumber(summary.sql_hits or 0) or 0,
        xss_hits = tonumber(summary.xss_hits or 0) or 0,
        timestamp = ngx.time(),
    }
end

local function safe_decode_table(json, fallback)
    if type(json) ~= "string" or json == "" then
        return fallback
    end

    local ok, data = pcall(cjson.decode, json)
    if ok and type(data) == "table" then
        return data
    end

    return fallback
end

local _cached_global_config_version = nil
local _cached_global_configs = {}

local function get_global_config(key, fallback)
    local version = tonumber(config_dict:get("config_version") or 0) or 0
    if _cached_global_config_version ~= version then
        _cached_global_config_version = version
        _cached_global_configs = {}
    end

    local cached = _cached_global_configs[key]
    if cached ~= nil then
        return cached
    end

    local decoded = safe_decode_table(config_dict:get(key) or "{}", fallback or {})
    _cached_global_configs[key] = decoded
    return decoded
end

local function normalize_site_config(raw)
    if type(raw) ~= "table" then
        return nil
    end
    if raw.enabled == false then
        return nil
    end

    local normalized = {}

    for k, v in pairs(raw) do
        if k ~= "protection" and k ~= "verification_methods" then
            normalized[k] = v
        end
    end

    if type(raw.protection) == "table" then
        for k, v in pairs(raw.protection) do
            if normalized[k] == nil then
                normalized[k] = v
            end
        end
    end

    if type(raw.verification_methods) == "table" then
        for k, v in pairs(raw.verification_methods) do
            if normalized[k] == nil then
                normalized[k] = v
            end
        end
    end

    return normalized
end

local function maybe_auto_blacklist(site_config, client_ip, total_score, duration_override)
    if not site_config.auto_blacklist_enabled then
        return false
    end

    local threshold = tonumber(site_config.auto_blacklist_score_threshold or 20) or 20
    if total_score < threshold then
        return false
    end

    local duration = tonumber(duration_override or site_config.auto_blacklist_duration or 900) or 900
    if duration < 60 then
        duration = 60
    end

    ip_blacklist.add_to_blacklist(client_ip, duration)
    return true
end

-- 获取站点配置
local function get_site_config()
    local host = (ngx.var.host or ""):lower()
    local raw = config_loader.get_site_config(host)

    if not raw then
        return nil
    end

    -- 禁用站点：直接跳过WAF（由Nginx配置决定是否继续代理）
    if raw.enabled == false then
        return nil
    end

    return normalize_site_config(raw)
end

local function get_request_scope_context()
    local method = ngx.req.get_method() or "GET"
    local host = (ngx.var.host or ""):lower()
    local path = ngx.var.uri or "/"

    return {
        host = host,
        path = path,
        method = method
    }
end

local function matches_request_scope(verified_token, request_ctx)
    if type(verified_token) ~= "table" or type(request_ctx) ~= "table" then
        return false
    end

    if verified_token.host and verified_token.host ~= request_ctx.host then
        return false
    end

    if verified_token.method and verified_token.method ~= request_ctx.method then
        return false
    end

    local scope_mode = verified_token.scope_mode
    if scope_mode == "path_exact" then
        return verified_token.path == request_ctx.path
    end

    if scope_mode == "path_prefix" then
        local prefix = verified_token.path_prefix or verified_token.path
        if type(prefix) ~= "string" or prefix == "" then
            return false
        end
        return request_ctx.path:sub(1, #prefix) == prefix
    end

    return true
end

local function get_verified_token(client_ip, user_agent)
    local cookie_value = ngx.var.cookie_safeline_verified
    if not cookie_value then
        return nil
    end

    if cookie_value then
        local verified_token = utils.decrypt_token(cookie_value)
        local request_ctx = get_request_scope_context()

        if verified_token and verified_token.verified and verified_token.expires > ngx.time() and
           verified_token.ip == client_ip and verified_token.ua_hash == ngx.md5(user_agent or "") and
           matches_request_scope(verified_token, request_ctx) then
            return verified_token
        end
    end

    return nil
end

local function ensure_request_id()
    if type(ngx.ctx.request_id) == "string" and ngx.ctx.request_id ~= "" then
        return ngx.ctx.request_id
    end

    local request_id = ngx.var.request_id
    if type(request_id) ~= "string" or request_id == "" then
        local seed = table.concat({
            ngx.var.connection or "",
            ngx.var.remote_addr or "",
            tostring(ngx.now()),
            ngx.var.request_uri or ""
        }, ":")
        request_id = ngx.md5(seed)
    end

    ngx.ctx.request_id = request_id
    ngx.header["X-Request-ID"] = request_id
    return request_id
end

local function get_pow_bounds(site_config)
    local base_difficulty = tonumber(site_config.pow_base_difficulty or 4) or 4
    local max_difficulty = tonumber(site_config.pow_max_difficulty or 8) or 8

    if base_difficulty < 1 then
        base_difficulty = 1
    elseif base_difficulty > 15 then
        base_difficulty = 15
    end

    if max_difficulty < base_difficulty then
        max_difficulty = base_difficulty
    elseif max_difficulty > 15 then
        max_difficulty = 15
    end

    return base_difficulty, max_difficulty
end

local function get_verification_grant_ttl(site_config, verification_type)
    if type(site_config) ~= "table" then
        return 1800
    end

    local ttl_key = tostring(verification_type or "") .. "_verification_ttl"
    local ttl = tonumber(site_config[ttl_key] or 1800) or 1800

    if verification_type == "slider" then
        if ttl < 60 then
            ttl = 60
        elseif ttl > 3600 then
            ttl = 3600
        end
    else
        if ttl < 60 then
            ttl = 60
        elseif ttl > 7200 then
            ttl = 7200
        end
    end

    return ttl
end

local html_entity_map = {
    ["&lt;"] = "<",
    ["&gt;"] = ">",
    ["&quot;"] = "\"",
    ["&#39;"] = "'",
    ["&apos;"] = "'",
    ["&amp;"] = "&",
    ["&colon;"] = ":"
}

local payload_signatures = {
    { id = "xss_script_tag", pattern = [[<\s*script\b]], score = 10 },
    { id = "xss_event_handler", pattern = [[on(?:error|load|click|mouseover|focus|submit|animationstart)\s*=]], score = 9 },
    { id = "xss_javascript_uri", pattern = [[javascript\s*:]], score = 9 },
    { id = "xss_data_html", pattern = [[data\s*:\s*text/html]], score = 9 },
    { id = "xss_vbscript_uri", pattern = [[vbscript\s*:]], score = 9 },
    { id = "xss_css_expression", pattern = [[expression\s*\(]], score = 8 },
    { id = "xss_svg_onload", pattern = [[<\s*svg\b[^>]*onload\s*=]], score = 9 },
    { id = "xss_srcdoc", pattern = [[srcdoc\s*=]], score = 8 },
    { id = "sqli_union_select", pattern = [[union\s+all?\s*select\b]], score = 9 },
    { id = "sqli_boolean_or", pattern = [[['"`]?\s*or\s+['"`]?\w+['"`]?\s*=\s*['"`]?\w+]], score = 8 },
    { id = "sqli_time_delay", pattern = [[(?:sleep|benchmark|pg_sleep)\s*\(]], score = 10 },
    { id = "sqli_waitfor_delay", pattern = [[waitfor\s+delay]], score = 10 },
    { id = "sqli_stacked_query", pattern = [[;\s*(?:select|insert|update|delete|drop)\b]], score = 8 },
    { id = "sqli_schema_probe", pattern = [[(?:information_schema|pg_catalog|sqlite_master)\b]], score = 8 },
    { id = "path_traversal", pattern = [[(?:\.\.[/\\]+|\.{2,}\s*/+)|/etc/passwd|/proc/self/environ|/windows/win\.ini|boot\.ini|web\.config]], score = 8 },
    { id = "ssrf_dangerous_scheme", pattern = [[\b(?:dict|gopher|file|jar|ldap|ldaps|tftp)\s*://]], score = 10 },
    { id = "ssrf_metadata", pattern = [[(?:169\.254\.169\.254|metadata\.google(?:\.internal)?|metadata\.azure|100\.100\.100\.200)\b]], score = 10 },
    { id = "ssrf_internal_http", pattern = [[https?\s*://\s*(?:127\.0\.0\.1|0\.0\.0\.0|localhost|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|\[::1\]|::1|fc[0-9a-f]{2}:|fd[0-9a-f]{2}:)]], score = 9 },
    { id = "jndi_lookup", pattern = [[\$\s*\{\s*jndi\s*:]], score = 10 },
    { id = "jndi_nested_lookup", pattern = [[\$\s*\{\s*\$\s*\{]], score = 8 },
    { id = "graphql_introspection", pattern = [[__(?:schema|type)\b]], score = 6 }
}

local function decode_html_entities(value)
    local decoded = value
    for entity, replacement in pairs(html_entity_map) do
        decoded = decoded:gsub(entity, replacement)
    end

    decoded = decoded:gsub("&#x([0-9a-fA-F]+);?", function(hex)
        local num = tonumber(hex, 16)
        if num and num > 0 and num < 256 then
            return string.char(num)
        end
        return ""
    end)

    decoded = decoded:gsub("&#(%d+);?", function(dec)
        local num = tonumber(dec, 10)
        if num and num > 0 and num < 256 then
            return string.char(num)
        end
        return ""
    end)

    return decoded
end

local function decode_ascii_escape(hex, base)
    local num = tonumber(hex, base)
    if num and num >= 0 and num <= 255 then
        return string.char(num)
    end
    return ""
end

local function normalize_lookup_obfuscation(value)
    local normalized = value

    for _ = 1, 4 do
        local previous = normalized
        normalized = normalized:gsub("%${lower:([^{}]+)}", function(inner)
            return string.lower(inner)
        end)
        normalized = normalized:gsub("%${upper:([^{}]+)}", function(inner)
            return string.upper(inner)
        end)
        normalized = normalized:gsub("%${::%-([^{}]+)}", "%1")
        normalized = normalized:gsub("%${%s*env:[^:}]+:-(.-)}", "%1")
        if normalized == previous then
            break
        end
    end

    return normalized
end

local function normalize_unsafe_utf8_sequences(value)
    return value
        :gsub("\192\175", "/")
        :gsub("\224\128\175", "/")
        :gsub("\240\128\128\175", "/")
        :gsub("\192\174", ".")
        :gsub("\224\128\174", ".")
end

local function flatten_header_values(value)
    if value == nil then
        return {}
    end

    if type(value) == "table" then
        local flattened = {}
        for _, item in ipairs(value) do
            if type(item) == "string" and item ~= "" then
                flattened[#flattened + 1] = item
            end
        end
        return flattened
    end

    if type(value) == "string" and value ~= "" then
        return { value }
    end

    return {}
end

local function count_unique_normalized_values(values, max_len)
    local seen = {}
    local count = 0
    for _, value in ipairs(values) do
        local normalized = normalize_inspection_text(value, max_len or 256)
        if normalized ~= "" and not seen[normalized] then
            seen[normalized] = true
            count = count + 1
        end
    end
    return count
end

local function measure_structure_depth(value, max_scan_len)
    if type(value) ~= "string" or value == "" then
        return 0, false
    end

    local depth = 0
    local max_depth = 0
    local unbalanced = false
    local limit = math.min(#value, tonumber(max_scan_len or 32768) or 32768)

    for index = 1, limit do
        local char = value:sub(index, index)
        if char == "{" or char == "[" then
            depth = depth + 1
            if depth > max_depth then
                max_depth = depth
            end
        elseif char == "}" or char == "]" then
            depth = depth - 1
            if depth < 0 then
                unbalanced = true
                depth = 0
            end
        end
    end

    if depth ~= 0 then
        unbalanced = true
    end

    return max_depth, unbalanced
end

local function inspect_list_header_shape(values, max_items, max_token_len)
    local total = 0
    local item_limit = tonumber(max_items or 16) or 16
    local token_limit = tonumber(max_token_len or 256) or 256

    for _, raw in ipairs(values) do
        if type(raw) == "string" then
            for token in raw:gmatch("[^,]+") do
                local trimmed = token:gsub("^%s+", ""):gsub("%s+$", "")
                if trimmed ~= "" then
                    if #trimmed > token_limit or trimmed:find("[%z\r\n]") then
                        return total, "malformed"
                    end

                    total = total + 1
                    if total > item_limit then
                        return total, "too_many_items"
                    end
                end
            end
        end
    end

    return total, nil
end

normalize_inspection_text = function(value, max_len)
    if value == nil then
        return ""
    end

    if type(value) ~= "string" then
        value = tostring(value)
    end

    if value == "" then
        return ""
    end

    local normalized = value
    local limit = tonumber(max_len or 4096) or 4096
    if limit < 128 then
        limit = 128
    end

    if #normalized > limit then
        normalized = normalized:sub(1, limit)
    end

    for _ = 1, 3 do
        local decoded = ngx.unescape_uri(normalized:gsub("%+", "%%20"))
        if decoded == normalized then
            break
        end
        normalized = decoded
    end

    normalized = decode_html_entities(normalized)
    normalized = normalized:gsub("%%u00([0-9a-fA-F][0-9a-fA-F])", function(hex)
        return decode_ascii_escape(hex, 16)
    end)
    normalized = normalized:gsub("\\u00([0-9a-fA-F][0-9a-fA-F])", function(hex)
        return decode_ascii_escape(hex, 16)
    end)
    normalized = normalized:gsub("\\x([0-9a-fA-F][0-9a-fA-F])", function(hex)
        return decode_ascii_escape(hex, 16)
    end)
    normalized = normalize_unsafe_utf8_sequences(normalized)
    normalized = normalize_lookup_obfuscation(normalized)
    normalized = normalized:gsub("/%*.-%*/", " ")
    normalized = normalized:gsub("\\", "/")
    normalized = normalized:gsub("/+", "/")
    normalized = normalized:gsub("[%z\1-\8\11\12\14-\31\127]", " ")
    normalized = normalized:lower()
    normalized = normalized:gsub("%s+", " ")

    return normalized
end

local function add_payload_candidate(candidates, source, label, value, opts)
    opts = opts or {}

    if value == nil or #candidates >= (opts.max_candidates or 64) then
        return
    end

    local value_type = type(value)
    if value_type == "table" then
        local depth = tonumber(opts.depth or 0) or 0
        if depth >= (opts.max_depth or 4) then
            return
        end

        local count = 0
        for key, nested in pairs(value) do
            count = count + 1
            if count > (opts.max_fields_per_table or 20) then
                break
            end

            local child_label = label .. "." .. tostring(key)
            add_payload_candidate(candidates, source, child_label, nested, {
                depth = depth + 1,
                max_depth = opts.max_depth,
                max_candidates = opts.max_candidates,
                max_fields_per_table = opts.max_fields_per_table,
                max_len = opts.max_len
            })
        end
        return
    end

    if value_type ~= "string" then
        if value_type == "number" or value_type == "boolean" then
            value = tostring(value)
        else
            return
        end
    end

    if value == "" then
        return
    end

    candidates[#candidates + 1] = {
        source = source,
        label = label,
        raw = build_inspection_preview(value, opts.preview_len or 240),
        normalized = normalize_inspection_text(value, opts.max_len)
    }
end

local function read_request_body_for_inspection(site_config)
    local method = ngx.req.get_method()
    if method ~= "POST" and method ~= "PUT" and method ~= "PATCH" and method ~= "DELETE" then
        return nil, nil, nil
    end

    local content_type = string.lower(ngx.var.content_type or "")
    if content_type == "" then
        return nil, nil, nil
    end

    local body_kind = nil
    if content_type:find("multipart/form-data", 1, true) then
        body_kind = "multipart"
    elseif content_type:find("application/octet-stream", 1, true) then
        return nil, content_type, "binary"
    end

    local inspectable = body_kind == "multipart" or
        content_type:find("application/json", 1, true) or
        content_type:find("+json", 1, true) or
        content_type:find("application/x-www-form-urlencoded", 1, true) or
        content_type:find("application/xml", 1, true) or
        content_type:find("application/graphql", 1, true) or
        content_type:find("text/", 1, true)

    if not inspectable then
        return nil, content_type, nil
    end

    ngx.req.read_body()

    local max_bytes = tonumber(site_config.request_body_max_bytes or 32768) or 32768
    if max_bytes < 1024 then
        max_bytes = 1024
    elseif max_bytes > 262144 then
        max_bytes = 262144
    end

    local body = ngx.req.get_body_data()
    if body and #body > max_bytes then
        body = body:sub(1, max_bytes)
    end

    if not body then
        local body_file = ngx.req.get_body_file()
        if body_file then
            local file = io.open(body_file, "rb")
            if file then
                body = file:read(max_bytes)
                file:close()
            end
        end
    end

    if not body_kind then
        body_kind = "text"
    end

    return body, content_type, body_kind
end

local function inspect_multipart_body(body, max_len)
    if type(body) ~= "string" or body == "" then
        return false
    end

    local normalized = normalize_inspection_text(body, max_len or 8192)
    local signatures = {
        { id = "multipart_filename_traversal", pattern = [[filename\s*=\s*["'][^"'\r\n]*(?:\.\./|\.\.\\|%2e%2e|/etc/passwd)]], score = 10 },
        { id = "multipart_dangerous_extension", pattern = [[filename\s*=\s*["'][^"'\r\n]*\.(?:php[0-9]*|phtml|phar|jspx?|aspx?|ashx|cgi|pl|py|rb|exe|dll|sh|bat|cmd)\b]], score = 9 }
    }

    for _, signature in ipairs(signatures) do
        local from = ngx.re.find(normalized, signature.pattern, "jo")
        if from then
            return true, signature.id, signature.score, "body", "multipart"
        end
    end

    return false
end

local function inspect_body_shape(site_config, body, content_type)
    if type(body) ~= "string" or body == "" or type(content_type) ~= "string" then
        return false
    end

    local max_depth = tonumber(site_config.request_body_max_depth or 32) or 32
    if max_depth < 8 then
        max_depth = 8
    elseif max_depth > 96 then
        max_depth = 96
    end

    local graphql_depth_limit = tonumber(site_config.graphql_max_depth or 12) or 12
    if graphql_depth_limit < 4 then
        graphql_depth_limit = 4
    elseif graphql_depth_limit > 48 then
        graphql_depth_limit = 48
    end

    if content_type:find("application/json", 1, true) or content_type:find("+json", 1, true) then
        local depth, unbalanced = measure_structure_depth(body, site_config.request_body_max_bytes)
        if depth > max_depth then
            return true, "json_nested_depth", 8, "body", "json_depth"
        end
        if unbalanced and depth >= max_depth then
            return true, "json_unbalanced_structure", 7, "body", "json_structure"
        end
    end

    if content_type:find("application/graphql", 1, true) then
        local depth = 0
        local max_seen = 0
        for i = 1, math.min(#body, tonumber(site_config.request_body_max_bytes or 32768) or 32768) do
            local ch = body:sub(i, i)
            if ch == "{" then
                depth = depth + 1
                if depth > max_seen then
                    max_seen = depth
                end
            elseif ch == "}" then
                depth = math.max(0, depth - 1)
            end
        end

        if max_seen > graphql_depth_limit then
            return true, "graphql_nested_query", 8, "body", "graphql_depth"
        end
    end

    return false
end

local function inspect_protocol_compliance(site_config, uri)
    local method = ngx.req.get_method()
    if dangerous_methods[method] then
        return true, "dangerous_method", 405, 8
    end

    local request_uri = ngx.var.request_uri or uri or "/"
    local max_uri_len = tonumber(site_config.max_uri_length or 8192) or 8192
    if max_uri_len < 1024 then
        max_uri_len = 1024
    elseif max_uri_len > 65535 then
        max_uri_len = 65535
    end

    if #request_uri > max_uri_len then
        return true, "uri_too_long", 414, 7
    end

    local headers = ngx.req.get_headers(128, true)
    local header_count = 0
    for _ in pairs(headers) do
        header_count = header_count + 1
    end

    local max_header_count = tonumber(site_config.max_header_count or 96) or 96
    if max_header_count < 32 then
        max_header_count = 32
    elseif max_header_count > 256 then
        max_header_count = 256
    end

    if header_count > max_header_count then
        return true, "too_many_headers", 431, 6
    end

    local host_values = flatten_header_values(headers["host"] or headers["Host"])
    if #host_values > 1 and count_unique_normalized_values(host_values, 255) > 1 then
        return true, "conflicting_host_header", 400, 10
    end

    local host = host_values[1] or ngx.var.host or ""
    if type(host) == "table" then
        host = host[1] or ""
    end
    if type(host) == "string" and host ~= "" then
        host = host:gsub("^%s+", ""):gsub("%s+$", "")
        if host == "" or host:find("[/%z\r\n\t\\]") or not host:match("^[%w%.:%-%[%]]+$") then
            return true, "invalid_host_header", 400, 8
        end
    end

    local transfer_encoding_values = flatten_header_values(headers["transfer-encoding"] or headers["Transfer-Encoding"])
    local content_length_values = flatten_header_values(headers["content-length"] or headers["Content-Length"])
    local forwarded_values = flatten_header_values(headers["forwarded"] or headers["Forwarded"])
    local xff_values = flatten_header_values(headers["x-forwarded-for"] or headers["X-Forwarded-For"])

    for _, header_value in ipairs(content_length_values) do
        local normalized = normalize_inspection_text(header_value, 64)
        if normalized == "" or not normalized:match("^%d+$") then
            return true, "invalid_content_length", 400, 8
        end
    end

    if #content_length_values > 1 and count_unique_normalized_values(content_length_values, 64) > 1 then
        return true, "http_smuggling_conflicting_content_length", 400, 10
    end

    if #transfer_encoding_values > 1 and count_unique_normalized_values(transfer_encoding_values, 128) > 1 then
        return true, "http_smuggling_multiple_transfer_encoding", 400, 9
    end

    if #transfer_encoding_values > 0 and #content_length_values > 0 then
        return true, "http_smuggling_te_cl", 400, 10
    end

    for _, header_value in ipairs(transfer_encoding_values) do
        local normalized = normalize_inspection_text(header_value, 128)
        if normalized:find("chunked", 1, true) and normalized:find("identity", 1, true) then
            return true, "http_smuggling_ambiguous_transfer_encoding", 400, 10
        end
    end

    local max_forwarded_hops = tonumber(site_config.max_forwarded_hops or 16) or 16
    if max_forwarded_hops < 4 then
        max_forwarded_hops = 4
    elseif max_forwarded_hops > 64 then
        max_forwarded_hops = 64
    end

    local xff_hops, xff_error = inspect_list_header_shape(xff_values, max_forwarded_hops, 128)
    if xff_error == "malformed" then
        return true, "invalid_x_forwarded_for", 400, 7
    elseif xff_error == "too_many_items" then
        return true, "forwarded_chain_too_long", 400, 6
    end

    local forwarded_hops, forwarded_error = inspect_list_header_shape(forwarded_values, max_forwarded_hops, 256)
    if forwarded_error == "malformed" then
        return true, "invalid_forwarded_header", 400, 7
    elseif forwarded_error == "too_many_items" then
        return true, "forwarded_chain_too_long", 400, 6
    end

    if xff_hops and xff_hops > 0 and #xff_values > 1 and count_unique_normalized_values(xff_values, 512) > 1 then
        return true, "conflicting_x_forwarded_for", 400, 7
    end

    for _, header_value in ipairs(forwarded_values) do
        local normalized = normalize_inspection_text(header_value, 512)
        if normalized ~= "" and not normalized:find("for=", 1, true) then
            return true, "invalid_forwarded_header", 400, 7
        end
    end

    return false
end

local function inspect_request_payload(site_config, uri)
    if site_config.request_content_inspection_enabled == false then
        return false
    end

    local candidates = {}
    local candidate_opts = {
        max_candidates = 64,
        max_fields_per_table = 20,
        max_depth = 4,
        max_len = tonumber(site_config.request_field_max_len or 4096) or 4096,
        preview_len = 240
    }

    add_payload_candidate(candidates, "uri", "path", uri or ngx.var.request_uri or "/", candidate_opts)

    local args = ngx.req.get_uri_args(50)
    if type(args) == "table" then
        for key, value in pairs(args) do
            if #candidates >= candidate_opts.max_candidates then
                break
            end
            add_payload_candidate(candidates, "query", "name", key, candidate_opts)
            add_payload_candidate(candidates, "query", tostring(key), value, candidate_opts)
        end
    end

    local body, content_type, body_kind = read_request_body_for_inspection(site_config)
    if body_kind == "multipart" then
        local multipart_detected, multipart_signature, multipart_score, multipart_source, multipart_label =
            inspect_multipart_body(body, candidate_opts.max_len)
        if multipart_detected then
            return true, multipart_signature, multipart_score, multipart_source, multipart_label, nil
        end
    end

    if body_kind == "text" then
        local shape_detected, shape_signature, shape_score, shape_source, shape_label =
            inspect_body_shape(site_config, body, content_type)
        if shape_detected then
            return true, shape_signature, shape_score, shape_source, shape_label, nil
        end
    end

    if type(body) == "string" and body ~= "" and #candidates < candidate_opts.max_candidates then
        if body_kind == "text" and content_type and (content_type:find("application/json", 1, true) or content_type:find("+json", 1, true)) then
            local ok, decoded = pcall(cjson.decode, body)
            if ok and type(decoded) == "table" then
                add_payload_candidate(candidates, "body", "json", decoded, candidate_opts)
            else
                add_payload_candidate(candidates, "body", "raw", body, candidate_opts)
            end
        elseif body_kind == "text" then
            add_payload_candidate(candidates, "body", "raw", body, candidate_opts)
        end
    end

    local findings = {}
    for _, candidate in ipairs(candidates) do
        local text = candidate.normalized
        if text and text ~= "" then
            for _, signature in ipairs(payload_signatures) do
                local from = ngx.re.find(text, signature.pattern, "jo")
                if from then
                    findings[#findings + 1] = {
                        id = signature.id,
                        score = signature.score,
                        source = candidate.source,
                        label = candidate.label,
                        candidate = candidate
                    }
                    break
                end
            end
        end
    end

    if #findings == 0 then
        return false
    end

    table.sort(findings, function(a, b)
        if a.score == b.score then
            return a.id < b.id
        end
        return a.score > b.score
    end)

    local total_score = 0
    for i = 1, math.min(3, #findings) do
        total_score = total_score + findings[i].score
    end

    local primary = findings[1]
    local inspection_summary = build_payload_inspection_summary(primary.candidate, primary.id, total_score, primary.source, primary.label)
    return true, primary.id, total_score, primary.source, primary.label, inspection_summary
end

local function is_high_risk_reason(reason)
    if type(reason) ~= "string" then
        return false
    end

    return reason == "ddos_protection" or reason == "random_attack" or reason == "llm_verdict" or
        reason:sub(1, 16) == "ddos_protection" or reason:sub(1, 10) == "slow_ddos_"
end

-- 重定向到验证页面
local function redirect_to_verification(site_config, verification_type, reason, difficulty)
    -- WebSocket握手无法跟随302跳转；遇到需要验证时应直接拒绝，让前端页面先完成验证再建立WS连接
    local headers = ngx.req.get_headers()
    local upgrade = headers["upgrade"] or headers["Upgrade"]
    if type(upgrade) == "string" and upgrade:lower() == "websocket" then
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.header.content_type = "text/plain"
        ngx.say("WebSocket connection requires verification")
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    local request_ctx = get_request_scope_context()
    local scope_mode = is_high_risk_reason(reason) and "path_exact" or "host"

    -- 生成token包含原始URL和验证原因
    local grant_ttl = get_verification_grant_ttl(site_config, verification_type)

    local token_data = {
        original_url = ngx.var.scheme .. "://" .. ngx.var.host .. ngx.var.request_uri,
        verification_type = verification_type,
        reason = reason,
        difficulty = difficulty,
        host = request_ctx.host,
        path = request_ctx.path,
        method = request_ctx.method,
        scope_mode = scope_mode,
        grant_ttl = grant_ttl,
        expires = ngx.time() + 3600 -- 1小时内有效
    }

    if verification_type == "slider" and is_high_risk_reason(reason) then
        token_data.step_up_verification_type = "pow"
        token_data.step_up_required = true
    end

    if verification_type == "slider" and token_data.step_up_required then
        token_data.grant_ttl = get_verification_grant_ttl(site_config, token_data.step_up_verification_type)
    end

    local token = utils.encrypt_token(token_data)
    local redirect_url = nil
    if verification_type == "pow" then
        redirect_url = "/pow"
    else
        redirect_url = "/safeline-static/verify.html?token=" .. ngx.escape_uri(token)
    end

    ngx.header["Set-Cookie"] = "safeline_verification=" .. token .. "; Path=/; Max-Age=3600; HttpOnly"

    ngx.redirect(redirect_url)
end

-- 动态选择验证方式
local function select_verification_method(site_config, reason, client_ip, uri)
    -- 获取客户端历史异常分数
    local score_key = "anomaly_score:" .. client_ip
    local score = tonumber(cache_dict:get(score_key) or 0)
    local base_difficulty, max_difficulty = get_pow_bounds(site_config)

    -- 根据异常分数和原因选择验证方式
    local verification_type = "captcha"  -- 默认验证��
    local difficulty = base_difficulty

    if is_high_risk_reason(reason) or score > 8 then
        -- 高风险请求使用POW
        verification_type = "pow"
        difficulty = base_difficulty + math.floor(score / 5)
        if is_high_risk_reason(reason) then
            difficulty = math.max(difficulty, base_difficulty + 1)
        end
        difficulty = math.min(difficulty, max_difficulty)
    elseif score > 4 or reason == "anti_cc" then
        -- 中风险请求使用滑块验证
        verification_type = "slider"
    end

        -- 确保所选验证方式已启用
    if verification_type == "pow" and not site_config.pow_enabled then
        verification_type = site_config.captcha_enabled and "captcha" or "slider"
    end

    if verification_type == "slider" and not site_config.slider_captcha_enabled then
        verification_type = "captcha"
    end

    if verification_type == "captcha" and not site_config.captcha_enabled and site_config.slider_captcha_enabled then
        verification_type = "slider"
    end

    return verification_type, difficulty
end

-- 记录请求日志
local function log_request(site_config, client_ip, uri, status, is_blocked, reason)
    if not site_config.request_logging_enabled then
        return
    end

    -- 默认仅记录被拦截请求；放行请求可通过 log_sample_rate 抽样记录
    if not is_blocked then
        local sample_rate = tonumber(site_config.log_sample_rate)
            or tonumber(site_config.sampling_rate)
            or 0
        if sample_rate <= 0 or math.random() >= sample_rate then
            return
        end
    end
    
    local log_data = {
        timestamp = ngx.time(),
        request_id = ensure_request_id(),
        client_ip = client_ip,
        host = ngx.var.host or "",
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

    -- 更新趋势统计（10秒桶，保留2小时）
    local now = ngx.time()
    local bucket = now - (now % 10)
    counters_dict:incr("trend_total:" .. bucket, 1, 0, 7200)
    if is_blocked then
        counters_dict:incr("trend_blocked:" .. bucket, 1, 0, 7200)
    end
    
    -- 更新流量分析统计
    if site_config.traffic_analysis_enabled then
        ddos_protection.update_traffic_stats(client_ip, is_blocked and 403 or 200, uri, method)
    end

    -- 同步统计到Redis（供管理后台查询）
    local host = (ngx.var.host or "unknown"):lower()
    local meta = {
        client_ip = client_ip,
        uri = uri,
        method = method
    }

    if is_blocked then
        utils.update_redis_stats(host, true, reason, meta, 1)
    else
        local sample_rate = tonumber(site_config.stats_sample_rate or 0.01) or 0.01
        if sample_rate > 0 and math.random() < sample_rate then
            -- 抽样后按权重回填，避免统计长期偏低
            local weight = math.max(1, math.floor(1 / sample_rate + 0.5))
            utils.update_redis_stats(host, false, nil, meta, weight)
        end
    end
end

-- 主WAF处理函数
local function process_waf()
    local uri = ngx.var.uri

    -- 检查是否是静态资源/验证API/POW验证页面
    if uri:match("^/safeline%-static/") or uri:match("^/safeline%-api/") or uri == "/pow" or uri:match("^/pow/") then
        return
    end

    -- 获取客户端信息（尽可能早，避免重复解析）
    local client_ip = utils.get_client_ip()
    local user_agent = ngx.var.http_user_agent or ""
    ensure_request_id()

    local verified_token = get_verified_token(client_ip, user_agent)
    local request_is_verified = verified_token ~= nil
    
    -- 获取站点配置
    local site_config = get_site_config()
    if not site_config then
        -- 如果没有找到站点配置，允许请求通过
        return
    end
    
    -- 请求信息
    local method = ngx.req.get_method()
    local adaptive_cfg = get_global_config("adaptive_protection", {})
    local skip_deep_checks = false

    local protocol_violation, protocol_reason, protocol_status, protocol_score = inspect_protocol_compliance(site_config, uri)
    if protocol_violation then
        local total_score = utils.record_anomaly(client_ip, uri, protocol_reason, protocol_score or 6)
        if protocol_score and protocol_score >= 9 then
            maybe_auto_blacklist(site_config, client_ip, total_score, 1800)
        end

        local should_block = true
        local inspection_summary = normalize_inspection_summary({
            trigger_reason = protocol_reason,
            source = "protocol",
            label = "protocol",
            matched_signature = protocol_reason,
            score = tonumber(protocol_score or 0) or 0,
            body_preview = "",
            normalized_preview = "",
            encoding_layers = {},
            encoding_layer_count = 0,
            obfusc_score = 0,
            attack_class = "protocol",
            confidence = 1,
            sql_hits = 0,
            xss_hits = 0
        }, client_ip, uri, method, protocol_status or 400, should_block)
        if inspection_summary then
            persist_inspection_summary(inspection_summary)
        end

        log_request(site_config, client_ip, uri, protocol_status or 400, true, protocol_reason)
        update_stats(site_config, client_ip, uri, method, true, protocol_reason)
        ngx.exit(protocol_status or 400)
        return
    end

    -- 源站回源保护（防 CF/CDN bypass）：仅允许来自可信代理网段的请求
    -- 使用全局 trusted_proxies 作为“允许回源 IP 段”来源（同时也是 get_client_ip 的信任来源）
    if site_config.origin_proxy_only_enabled then
        local remote_ip = ngx.var.remote_addr or ""
        if remote_ip == "" or not utils.is_trusted_proxy_ip(remote_ip) then
            local total_score = utils.record_anomaly(client_ip, uri, "origin_proxy_bypass", 10)
            maybe_auto_blacklist(site_config, client_ip, total_score, 3600)

            local inspection_summary = normalize_inspection_summary({
                trigger_reason = "origin_proxy_bypass",
                source = "origin_proxy",
                label = "origin_proxy",
                matched_signature = "origin_proxy_bypass",
                score = 10,
                body_preview = "",
                normalized_preview = "",
                encoding_layers = {},
                encoding_layer_count = 0,
                obfusc_score = 0,
                attack_class = "origin_proxy",
                confidence = 1,
                sql_hits = 0,
                xss_hits = 0
            }, client_ip, uri, method, 444, true)
            if inspection_summary then
                persist_inspection_summary(inspection_summary)
            end

            log_request(site_config, client_ip, uri, 444, true, "origin_proxy_bypass")
            update_stats(site_config, client_ip, uri, method, true, "origin_proxy_bypass")
            ngx.exit(444)
            return
        end
    end
    
    -- 检查蜜罐触发
    if site_config.honeypot_enabled then
        local is_honeypot, trap_type = utils.check_honeypot_trap(uri, ngx.req.get_uri_args(), ngx.req.get_headers())
        if is_honeypot then
            ngx.log(ngx.WARN, "Honeypot triggered by " .. client_ip .. ": " .. trap_type)

            -- 记录异常
            utils.record_anomaly(client_ip, uri, "honeypot_" .. trap_type, 10)

            -- 添加到黑名单（短期）
            if site_config.auto_blacklist_enabled then
                ip_blacklist.add_to_blacklist(client_ip, 21600) -- 6小时
            end

            local trigger_reason = "honeypot_" .. trap_type
            local inspection_summary = normalize_inspection_summary({
                trigger_reason = trigger_reason,
                source = "honeypot",
                label = tostring(trap_type or "honeypot"),
                matched_signature = tostring(trap_type or "honeypot"),
                score = 10,
                body_preview = "",
                normalized_preview = "",
                encoding_layers = {},
                encoding_layer_count = 0,
                obfusc_score = 0,
                attack_class = "honeypot",
                confidence = 1,
                sql_hits = 0,
                xss_hits = 0
            }, client_ip, uri, method, 444, true)
            if inspection_summary then
                persist_inspection_summary(inspection_summary)
            end

            -- 记录请求
            log_request(site_config, client_ip, uri, 444, true, trigger_reason)

            -- 更新统计信息
            update_stats(site_config, client_ip, uri, method, true, trigger_reason)

            -- 直接丢弃连接，节省带宽/连接资源（Nginx 444）
            ngx.exit(444)
            return
        end
    end
    
    -- 检查IP黑名单
    if site_config.ip_blacklist_enabled and ip_blacklist.is_blacklisted(client_ip) then
        local reason = "ip_blacklist"
        local inspection_summary = normalize_inspection_summary({
            trigger_reason = reason,
            source = "blacklist",
            label = "ip",
            matched_signature = reason,
            score = 10,
            body_preview = "",
            normalized_preview = "",
            encoding_layers = {},
            encoding_layer_count = 0,
            obfusc_score = 0,
            attack_class = "blacklist",
            confidence = 1,
            sql_hits = 0,
            xss_hits = 0
        }, client_ip, uri, method, 403, true)
        if inspection_summary then
            persist_inspection_summary(inspection_summary)
        end

        -- 记录请求
        log_request(site_config, client_ip, uri, 403, true, reason)

        -- 更新统计信息
        update_stats(site_config, client_ip, uri, method, true, reason)

        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end

    -- 检查LLM审计缓存裁决（快速路径，非阻塞）
    if site_config.llm_audit_enabled ~= false then
        local llm_action = llm_auditor.apply_verdict(client_ip)
        if llm_action == "ban" then
            local reason = "llm_verdict_ban"
            local inspection_summary = normalize_inspection_summary({
                trigger_reason = reason,
                source = "llm",
                label = "verdict",
                matched_signature = reason,
                score = 10,
                body_preview = "",
                normalized_preview = "",
                encoding_layers = {},
                encoding_layer_count = 0,
                obfusc_score = 0,
                attack_class = "llm",
                confidence = 1,
                sql_hits = 0,
                xss_hits = 0
            }, client_ip, uri, method, 403, true)
            if inspection_summary then
                persist_inspection_summary(inspection_summary)
            end

            log_request(site_config, client_ip, uri, 403, true, reason)
            update_stats(site_config, client_ip, uri, method, true, reason)
            ngx.exit(ngx.HTTP_FORBIDDEN)
            return
        elseif llm_action == "challenge" then
            local verification_type, difficulty = select_verification_method(site_config, "llm_verdict", client_ip, uri)
            local reason = "llm_verdict_challenge"

            local inspection_summary = normalize_inspection_summary({
                trigger_reason = reason,
                source = "llm",
                label = "challenge",
                matched_signature = reason,
                score = 7,
                body_preview = "",
                normalized_preview = "",
                encoding_layers = {},
                encoding_layer_count = 0,
                obfusc_score = 0,
                attack_class = "llm",
                confidence = 1,
                sql_hits = 0,
                xss_hits = 0
            }, client_ip, uri, method, 403, true)
            if inspection_summary then
                persist_inspection_summary(inspection_summary)
            end

            log_request(site_config, client_ip, uri, 403, true, reason)
            update_stats(site_config, client_ip, uri, method, true, reason)
            redirect_to_verification(site_config, verification_type, "llm_verdict", difficulty)
            return
        end
    end
    if site_config.ddos_protection_enabled and site_config.slow_ddos_protection_enabled ~= false then
        local is_slow, slow_reason, count, limit = ddos_protection.check_slow_ddos(client_ip)
        if is_slow then
            local reason = "slow_ddos_" .. tostring(slow_reason or "unknown")

            local score = (slow_reason == "conn_hard") and 10 or 7
            local total_score = utils.record_anomaly(client_ip, uri, reason, score)
            local blacklisted = maybe_auto_blacklist(site_config, client_ip, total_score, (slow_reason == "conn_hard") and 3600 or nil)

            -- 连接风暴/系统高压：优先直接丢弃连接，避免验证页把资源拖垮
            if blacklisted or (count and limit and count > (limit * 3)) or slow_reason == "conn_hard" then
                local inspection_summary = normalize_inspection_summary({
                    trigger_reason = reason,
                    source = "ddos",
                    label = "slow_ddos",
                    matched_signature = reason,
                    score = tonumber(score or 0) or 0,
                    body_preview = "",
                    normalized_preview = "",
                    encoding_layers = {},
                    encoding_layer_count = 0,
                    obfusc_score = 0,
                    attack_class = "ddos",
                    confidence = 1,
                    sql_hits = 0,
                    xss_hits = 0
                }, client_ip, uri, method, 444, true)
                if inspection_summary then
                    persist_inspection_summary(inspection_summary)
                end

                log_request(site_config, client_ip, uri, 444, true, reason)
                update_stats(site_config, client_ip, uri, method, true, reason)
                ngx.exit(444)
                return
            end

            -- 已通过验证：不要再走验证页，直接限速返回
            if request_is_verified then
                local inspection_summary = normalize_inspection_summary({
                    trigger_reason = reason,
                    source = "ddos",
                    label = "slow_ddos_verified",
                    matched_signature = reason,
                    score = tonumber(score or 0) or 0,
                    body_preview = "",
                    normalized_preview = "",
                    encoding_layers = {},
                    encoding_layer_count = 0,
                    obfusc_score = 0,
                    attack_class = "ddos",
                    confidence = 1,
                    sql_hits = 0,
                    xss_hits = 0
                }, client_ip, uri, method, 429, true)
                if inspection_summary then
                    persist_inspection_summary(inspection_summary)
                end

                log_request(site_config, client_ip, uri, 429, true, reason)
                update_stats(site_config, client_ip, uri, method, true, reason)
                ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
                return
            end

            -- 默认用POW抬高连接成本（更适合防御慢速/连接风暴类攻击）
            if site_config.pow_enabled then
                local difficulty = 6
                if count and limit and limit > 0 then
                    local ratio = count / limit
                    if ratio > 1 then
                        difficulty = 6 + math.floor(ratio)
                    end
                end
                difficulty = clamp_pow_difficulty(site_config, difficulty)

                log_request(site_config, client_ip, uri, 403, true, reason)
                update_stats(site_config, client_ip, uri, method, true, reason)
                redirect_to_verification(site_config, "pow", reason, difficulty)
                return
            end

            -- 没启用验证手段：直接429
            log_request(site_config, client_ip, uri, 429, true, reason)
            update_stats(site_config, client_ip, uri, method, true, reason)
            ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
            return
        end
    end

    -- 全局限速检查
    if site_config.global_rate_limit_enabled then
        local rate_key = "global_rate:" .. client_ip
        local is_limited, count, current_limit = utils.dynamic_rate_limit(
            rate_key, 
            site_config.global_rate_limit_count or 60, 
            site_config.global_rate_limit_window or 60
        )
        
        if is_limited then
            -- 记录异常
            local total_score = utils.record_anomaly(client_ip, uri, "global_rate_limit", 3)
            maybe_auto_blacklist(site_config, client_ip, total_score)

            local base_limit = tonumber(site_config.global_rate_limit_count or 60) or 60
            if count > base_limit * 5 then
                -- 极端高频：直接丢弃连接，避免被“验证页/重定向”拖垮
                local reason = "global_rate_limit_burst"
                local inspection_summary = normalize_inspection_summary({
                    trigger_reason = reason,
                    source = "rate_limit",
                    label = "global",
                    matched_signature = reason,
                    score = 8,
                    body_preview = "",
                    normalized_preview = "",
                    encoding_layers = {},
                    encoding_layer_count = 0,
                    obfusc_score = 0,
                    attack_class = "rate_limit",
                    confidence = 1,
                    sql_hits = 0,
                    xss_hits = 0
                }, client_ip, uri, method, 444, true)
                if inspection_summary then
                    persist_inspection_summary(inspection_summary)
                end

                log_request(site_config, client_ip, uri, 444, true, reason)
                update_stats(site_config, client_ip, uri, method, true, reason)
                ngx.exit(444)
                return
            end

            -- 已通过验证：不要再重定向到验证页，直接限速返回
            if request_is_verified then
                local reason = "global_rate_limit"
                local inspection_summary = normalize_inspection_summary({
                    trigger_reason = reason,
                    source = "rate_limit",
                    label = "verified",
                    matched_signature = reason,
                    score = 3,
                    body_preview = "",
                    normalized_preview = "",
                    encoding_layers = {},
                    encoding_layer_count = 0,
                    obfusc_score = 0,
                    attack_class = "rate_limit",
                    confidence = 1,
                    sql_hits = 0,
                    xss_hits = 0
                }, client_ip, uri, method, 429, true)
                if inspection_summary then
                    persist_inspection_summary(inspection_summary)
                end

                log_request(site_config, client_ip, uri, 429, true, reason)
                update_stats(site_config, client_ip, uri, method, true, reason)
                ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
                return
            end

            -- 判断是否需要进行验证
            if site_config.captcha_enabled or site_config.slider_captcha_enabled or site_config.pow_enabled then
                local verification_type, difficulty = select_verification_method(site_config, "rate_limit", client_ip, uri)
                local reason = "rate_limit"
                local inspection_summary = normalize_inspection_summary({
                    trigger_reason = reason,
                    source = "rate_limit",
                    label = verification_type or "challenge",
                    matched_signature = reason,
                    score = 3,
                    body_preview = "",
                    normalized_preview = "",
                    encoding_layers = {},
                    encoding_layer_count = 0,
                    obfusc_score = 0,
                    attack_class = "rate_limit",
                    confidence = 1,
                    sql_hits = 0,
                    xss_hits = 0
                }, client_ip, uri, method, 403, true)
                if inspection_summary then
                    persist_inspection_summary(inspection_summary)
                end

                redirect_to_verification(site_config, verification_type, "rate_limit", difficulty)
            else
                local reason = "global_rate_limit"
                local inspection_summary = normalize_inspection_summary({
                    trigger_reason = reason,
                    source = "rate_limit",
                    label = "no_challenge",
                    matched_signature = reason,
                    score = 3,
                    body_preview = "",
                    normalized_preview = "",
                    encoding_layers = {},
                    encoding_layer_count = 0,
                    obfusc_score = 0,
                    attack_class = "rate_limit",
                    confidence = 1,
                    sql_hits = 0,
                    xss_hits = 0
                }, client_ip, uri, method, 429, true)
                if inspection_summary then
                    persist_inspection_summary(inspection_summary)
                end

                -- 记录请求
                log_request(site_config, client_ip, uri, 429, true, reason)

                -- 更新统计信息
                update_stats(site_config, client_ip, uri, method, true, reason)

                ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
            end
            return
        end
    end
    
    -- 检查URL级DDoS攻击
    if site_config.ddos_protection_enabled then
        local is_ddos, reason, count, limit = ddos_protection.check_url_ddos(client_ip, uri)
        if is_ddos then
            local ddos_reason = "ddos_" .. tostring(reason or "unknown")

            local is_global_pressure = reason == "global_pressure" or reason == "global_burst" or
                reason == "unique_ip_surge" or reason == "global_hard"

            local hard_drop_on_overload = site_config.global_hard_drop_enabled
            if hard_drop_on_overload == nil then
                hard_drop_on_overload = adaptive_cfg.hard_drop_on_overload == true
            end

            -- 超出阈值过多：直接丢弃连接并可选自动封禁
            if (not is_global_pressure) and count and limit and count > (limit * 3) then
                if site_config.auto_blacklist_enabled then
                    ip_blacklist.add_to_blacklist(client_ip, 1800) -- 30分钟
                end

                local inspection_summary = normalize_inspection_summary({
                    trigger_reason = ddos_reason,
                    source = "ddos",
                    label = "url_ddos_drop",
                    matched_signature = ddos_reason,
                    score = 9,
                    body_preview = "",
                    normalized_preview = "",
                    encoding_layers = {},
                    encoding_layer_count = 0,
                    obfusc_score = 0,
                    attack_class = "ddos",
                    confidence = 1,
                    sql_hits = 0,
                    xss_hits = 0
                }, client_ip, uri, method, 444, true)
                if inspection_summary then
                    persist_inspection_summary(inspection_summary)
                end

                log_request(site_config, client_ip, uri, 444, true, ddos_reason)
                update_stats(site_config, client_ip, uri, method, true, ddos_reason)
                ngx.exit(444)
                return
            end

            -- 浏览器集群型DDoS（跨IP）：触发POW并可要求短周期复验，抬高每个浏览器的请求成本
            if is_global_pressure then
                if reason == "global_hard" and not request_is_verified then
                    -- global_hard：无论 hard_drop_on_overload 是否配置，未验证请求一律丢弃
                    -- 减少验证页本身被攻击者利用为反射放大目标
                    local inspection_summary = normalize_inspection_summary({
                        trigger_reason = ddos_reason,
                        source = "ddos",
                        label = "global_hard_drop",
                        matched_signature = ddos_reason,
                        score = 10,
                        body_preview = "",
                        normalized_preview = "",
                        encoding_layers = {},
                        encoding_layer_count = 0,
                        obfusc_score = 0,
                        attack_class = "ddos",
                        confidence = 1,
                        sql_hits = 0,
                        xss_hits = 0
                    }, client_ip, uri, method, 444, true)
                    if inspection_summary then
                        persist_inspection_summary(inspection_summary)
                    end

                    log_request(site_config, client_ip, uri, 444, true, ddos_reason)
                    update_stats(site_config, client_ip, uri, method, true, ddos_reason)
                    ngx.exit(444)
                    return
                end

                local now = ngx.time()
                local issued_at = verified_token and tonumber(verified_token.issued_at) or 0
                -- 缩短复验窗口：全局高压时默认45秒（而非120秒），降低已验证token的有效期
                local reverify_window = tonumber(site_config.ddos_reverify_window or 45) or 45
                if reason == "global_hard" then
                    -- global_hard 下进一步压缩到20秒，让已验证botnet更快重新验证
                    local hard_window = tonumber(adaptive_cfg.global_hard_reverify_window or 20) or 20
                    if hard_window > 0 then
                        reverify_window = math.min(reverify_window, hard_window)
                    end
                end
                if reverify_window < 10 then
                    reverify_window = 10
                end

                local recently_verified = issued_at > 0 and (now - issued_at) < reverify_window

                if not recently_verified then
                    local difficulty = 6
                    if count and limit and limit > 0 then
                        local ratio = count / limit
                        if ratio > 1 then
                            difficulty = 6 + math.floor(ratio)
                        end
                    end
                    difficulty = clamp_pow_difficulty(site_config, difficulty)

                    log_request(site_config, client_ip, uri, 403, true, ddos_reason)
                    update_stats(site_config, client_ip, uri, method, true, ddos_reason)

                    redirect_to_verification(site_config, "pow", "ddos_protection_" .. tostring(reason), difficulty)
                    return
                end

                -- 已在短窗口内完成复验：限速放行（单IP每秒最多 verified_scrubbing_rps 条）
                local verified_scrubbing_rps = tonumber(site_config.verified_scrubbing_rps or adaptive_cfg.verified_scrubbing_rps or 10) or 10
                if verified_scrubbing_rps < 1 then
                    verified_scrubbing_rps = 1
                end

                local scrub_key = "scrub:verified:" .. client_ip
                local verified_count = limit_dict:incr(scrub_key, 1, 0, 1)
                -- incr 返回 nil 代表 shared dict 内存已耗尽（系统处于极高压状态），直接限速
                if not verified_count then
                    local reason = "scrubbing_verified_limit"
                    local inspection_summary = normalize_inspection_summary({
                        trigger_reason = reason,
                        source = "ddos",
                        label = "scrubbing_verified",
                        matched_signature = reason,
                        score = 6,
                        body_preview = "",
                        normalized_preview = "",
                        encoding_layers = {},
                        encoding_layer_count = 0,
                        obfusc_score = 0,
                        attack_class = "ddos",
                        confidence = 1,
                        sql_hits = 0,
                        xss_hits = 0
                    }, client_ip, uri, method, 429, true)
                    if inspection_summary then
                        persist_inspection_summary(inspection_summary)
                    end

                    log_request(site_config, client_ip, uri, 429, true, reason)
                    update_stats(site_config, client_ip, uri, method, true, reason)
                    ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
                    return
                end

                if verified_count > verified_scrubbing_rps then
                    local reason = "scrubbing_verified_limit"
                    local inspection_summary = normalize_inspection_summary({
                        trigger_reason = reason,
                        source = "ddos",
                        label = "scrubbing_verified",
                        matched_signature = reason,
                        score = 6,
                        body_preview = "",
                        normalized_preview = "",
                        encoding_layers = {},
                        encoding_layer_count = 0,
                        obfusc_score = 0,
                        attack_class = "ddos",
                        confidence = 1,
                        sql_hits = 0,
                        xss_hits = 0
                    }, client_ip, uri, method, 429, true)
                    if inspection_summary then
                        persist_inspection_summary(inspection_summary)
                    end

                    log_request(site_config, client_ip, uri, 429, true, reason)
                    update_stats(site_config, client_ip, uri, method, true, reason)
                    ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
                    return
                end

                is_ddos = false
                skip_deep_checks = true
            end

            if not is_ddos then
                -- 允许通过（继续执行后续检查）
            else
                -- 已通过验证的请求：不要再走验证页（避免攻击者利用重定向放大资源消耗）
                if request_is_verified then
                    local inspection_summary = normalize_inspection_summary({
                        trigger_reason = ddos_reason,
                        source = "ddos",
                        label = "verified_limit",
                        matched_signature = ddos_reason,
                        score = 5,
                        body_preview = "",
                        normalized_preview = "",
                        encoding_layers = {},
                        encoding_layer_count = 0,
                        obfusc_score = 0,
                        attack_class = "ddos",
                        confidence = 1,
                        sql_hits = 0,
                        xss_hits = 0
                    }, client_ip, uri, method, 429, true)
                    if inspection_summary then
                        persist_inspection_summary(inspection_summary)
                    end

                    log_request(site_config, client_ip, uri, 429, true, ddos_reason)
                    update_stats(site_config, client_ip, uri, method, true, ddos_reason)
                    ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
                    return
                end

            -- 判断使用什么验证方式
            local verification_type, difficulty = select_verification_method(site_config, "ddos_protection", client_ip, uri)

            -- 记录请求
            local inspection_summary = normalize_inspection_summary({
                trigger_reason = ddos_reason,
                source = "ddos",
                label = verification_type or "challenge",
                matched_signature = ddos_reason,
                score = 7,
                body_preview = "",
                normalized_preview = "",
                encoding_layers = {},
                encoding_layer_count = 0,
                obfusc_score = 0,
                attack_class = "ddos",
                confidence = 1,
                sql_hits = 0,
                xss_hits = 0
            }, client_ip, uri, method, 403, true)
            if inspection_summary then
                persist_inspection_summary(inspection_summary)
            end

            log_request(site_config, client_ip, uri, 403, true, ddos_reason)

            -- 更新统计信息
            update_stats(site_config, client_ip, uri, method, true, ddos_reason)

            redirect_to_verification(site_config, verification_type, "ddos_protection", difficulty)
            return
            end
        end
    end

    -- 请求内容检测：对查询参数/JSON/表单正文做多阶段解码后匹配高危签名
    local payload_detected, payload_signature, payload_score, payload_source, payload_label, payload_summary = inspect_request_payload(site_config, uri)
    if payload_detected then
        local reason = "payload_" .. tostring(payload_signature or "malicious_input")
        local total_score = utils.record_anomaly(client_ip, uri, reason, payload_score or 8)
        local blacklisted = maybe_auto_blacklist(site_config, client_ip, total_score, (payload_score or 0) >= 10 and 3600 or nil)
        local should_drop = blacklisted or total_score >= 30

        local inspection_summary = normalize_inspection_summary(payload_summary, client_ip, uri, method, should_drop and 444 or 403, true)
        if inspection_summary then
            inspection_summary.source = payload_source or inspection_summary.source
            inspection_summary.label = payload_label or inspection_summary.label
            inspection_summary.score = tonumber(payload_score or inspection_summary.score or 0) or 0
            inspection_summary.trigger_reason = reason
            persist_inspection_summary(inspection_summary)
        end

        log_request(site_config, client_ip, uri, should_drop and 444 or 403, true, reason)
        update_stats(site_config, client_ip, uri, method, true, reason)

        -- 异步队列LLM深度分析（fire-and-forget，不阻塞当前请求）
        if site_config.llm_audit_enabled ~= false then
            local headers = ngx.req.get_headers()
            local body_preview = (inspection_summary and inspection_summary.body_preview) or (ngx.var.request_body or "")
            llm_auditor.queue_for_review(client_ip, uri, method, headers,
                body_preview:sub(1, 500), reason, (payload_score or 8) / 10)
        end

        if should_drop then
            ngx.exit(444)
            return
        end

        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end
    
    -- 检查随机请求方法和查询字符串攻击
    if (not skip_deep_checks) and site_config.random_attack_protection_enabled then
        local is_random_attack, attack_type = ddos_protection.check_random_requests(client_ip)
        if is_random_attack then
            -- 记录异常
            local total_score = utils.record_anomaly(client_ip, uri, "random_attack_" .. attack_type, 7)
            maybe_auto_blacklist(site_config, client_ip, total_score)

            if total_score >= 40 then
                local inspection_summary = normalize_inspection_summary({
                    trigger_reason = "random_attack_" .. tostring(attack_type),
                    source = "random_attack",
                    label = "drop",
                    matched_signature = tostring(attack_type),
                    score = 7,
                    body_preview = "",
                    normalized_preview = "",
                    encoding_layers = {},
                    encoding_layer_count = 0,
                    obfusc_score = 0,
                    attack_class = "random_attack",
                    confidence = 1,
                    sql_hits = 0,
                    xss_hits = 0
                }, client_ip, uri, method, 444, true)
                if inspection_summary then
                    persist_inspection_summary(inspection_summary)
                end

                log_request(site_config, client_ip, uri, 444, true, "random_attack_" .. attack_type)
                update_stats(site_config, client_ip, uri, method, true, "random_attack_" .. attack_type)
                ngx.exit(444)
                return
            end
            local verification_type, difficulty = select_verification_method(site_config, "random_attack", client_ip, uri)

            local inspection_summary = normalize_inspection_summary({
                trigger_reason = "random_attack_" .. tostring(attack_type),
                source = "random_attack",
                label = verification_type or "challenge",
                matched_signature = tostring(attack_type),
                score = 7,
                body_preview = "",
                normalized_preview = "",
                encoding_layers = {},
                encoding_layer_count = 0,
                obfusc_score = 0,
                attack_class = "random_attack",
                confidence = 1,
                sql_hits = 0,
                xss_hits = 0
            }, client_ip, uri, method, 403, true)
            if inspection_summary then
                persist_inspection_summary(inspection_summary)
            end

            -- 记录请求
            log_request(site_config, client_ip, uri, 403, true, "random_attack_" .. attack_type)

            -- 更新统计信息
            update_stats(site_config, client_ip, uri, method, true, "random_attack_" .. attack_type)

            redirect_to_verification(site_config, verification_type, "random_attack", difficulty)
            return
        end
    end
    
    -- 浏览器检测（已通过验证的请求不再重复做弱特征校验）
    if (not skip_deep_checks) and (not request_is_verified) and site_config.browser_detection_enabled then
        local is_real_browser = browser_detection.check(user_agent)
        if not is_real_browser then
            -- 记录异常
            utils.record_anomaly(client_ip, uri, "fake_browser", 5)
            
            -- 判断验证方式
            local verification_type, difficulty = select_verification_method(site_config, "browser_detection", client_ip, uri)
            
            -- 记录请求
            local inspection_summary = normalize_inspection_summary({
                trigger_reason = "browser_detection",
                source = "browser_detection",
                label = verification_type or "challenge",
                matched_signature = "browser_detection",
                score = 5,
                body_preview = "",
                normalized_preview = "",
                encoding_layers = {},
                encoding_layer_count = 0,
                obfusc_score = 0,
                attack_class = "bot",
                confidence = 1,
                sql_hits = 0,
                xss_hits = 0
            }, client_ip, uri, method, 403, true)
            if inspection_summary then
                persist_inspection_summary(inspection_summary)
            end

            log_request(site_config, client_ip, uri, 403, true, "browser_detection")
            
            -- 更新统计信息
            update_stats(site_config, client_ip, uri, method, true, "browser_detection")
            
            redirect_to_verification(site_config, verification_type, "browser_detection", difficulty)
            return
        end
    end
    
    -- 环境监测（已通过验证的请求不再重复做弱特征校验）
    if (not skip_deep_checks) and (not request_is_verified) and site_config.environment_detection_enabled then
        local env_valid = browser_detection.check_environment()
        if not env_valid then
            -- 记录异常
            utils.record_anomaly(client_ip, uri, "invalid_environment", 4)
            
            -- 判断验证方式
            local verification_type, difficulty = select_verification_method(site_config, "environment_detection", client_ip, uri)
            
            -- 记录请求
            local inspection_summary = normalize_inspection_summary({
                trigger_reason = "environment_detection",
                source = "environment_detection",
                label = verification_type or "challenge",
                matched_signature = "environment_detection",
                score = 4,
                body_preview = "",
                normalized_preview = "",
                encoding_layers = {},
                encoding_layer_count = 0,
                obfusc_score = 0,
                attack_class = "bot",
                confidence = 1,
                sql_hits = 0,
                xss_hits = 0
            }, client_ip, uri, method, 403, true)
            if inspection_summary then
                persist_inspection_summary(inspection_summary)
            end

            log_request(site_config, client_ip, uri, 403, true, "environment_detection")
            
            -- 更新统计信息
            update_stats(site_config, client_ip, uri, method, true, "environment_detection")
            
            redirect_to_verification(site_config, verification_type, "environment_detection", difficulty)
            return
        end
    end
    
    -- 自动化工具检测
    if (not skip_deep_checks) and site_config.automation_detection_enabled then
        local headers = ngx.req.get_headers()
        local is_automation, confidence, signs = utils.detect_automation_signature(headers, uri, method, client_ip)
        
        if is_automation then
            -- 记录异常
            local total_score = utils.record_anomaly(client_ip, uri, "automation_tool", 6)
            maybe_auto_blacklist(site_config, client_ip, total_score)

            if total_score >= 35 then
                local inspection_summary = normalize_inspection_summary({
                    trigger_reason = "automation_detection",
                    source = "automation_detection",
                    label = "drop",
                    matched_signature = "automation_tool",
                    score = 6,
                    body_preview = "",
                    normalized_preview = "",
                    encoding_layers = {},
                    encoding_layer_count = 0,
                    obfusc_score = 0,
                    attack_class = "bot",
                    confidence = 1,
                    sql_hits = 0,
                    xss_hits = 0
                }, client_ip, uri, method, 444, true)
                if inspection_summary then
                    persist_inspection_summary(inspection_summary)
                end

                log_request(site_config, client_ip, uri, 444, true, "automation_detection")
                update_stats(site_config, client_ip, uri, method, true, "automation_detection")
                ngx.exit(444)
                return
            end

            -- 判断验证方式
            local verification_type, difficulty = select_verification_method(site_config, "automation_detection", client_ip, uri)

            local inspection_summary = normalize_inspection_summary({
                trigger_reason = "automation_detection",
                source = "automation_detection",
                label = verification_type or "challenge",
                matched_signature = "automation_tool",
                score = 6,
                body_preview = "",
                normalized_preview = "",
                encoding_layers = {},
                encoding_layer_count = 0,
                obfusc_score = 0,
                attack_class = "bot",
                confidence = 1,
                sql_hits = 0,
                xss_hits = 0
            }, client_ip, uri, method, 403, true)
            if inspection_summary then
                persist_inspection_summary(inspection_summary)
            end

            -- 记录请求
            log_request(site_config, client_ip, uri, 403, true, "automation_detection")

            -- 更新统计信息
            update_stats(site_config, client_ip, uri, method, true, "automation_detection")

            redirect_to_verification(site_config, verification_type, "automation_detection", difficulty)
            return
        end
    end
    
    -- Anti-CC防护
    if (not skip_deep_checks) and site_config.anti_cc_enabled then
        local is_cc, cc_reason, count, limit = ddos_protection.check_cc_attack(client_ip, uri)
        if is_cc then
            -- 记录异常
            local score = (cc_reason == "burst") and 8 or 6
            local total_score = utils.record_anomaly(client_ip, uri, "cc_attack_" .. (cc_reason or "unknown"), score)
            local blacklisted = maybe_auto_blacklist(site_config, client_ip, total_score, (cc_reason == "burst") and 1800 or nil)

            -- 爆发/重复违规：直接丢弃连接
            if cc_reason == "burst" or blacklisted or (count and limit and count > (limit * 2)) then
                local inspection_summary = normalize_inspection_summary({
                    trigger_reason = "anti_cc_" .. tostring(cc_reason or "unknown"),
                    source = "anti_cc",
                    label = "drop",
                    matched_signature = tostring(cc_reason or "unknown"),
                    score = score,
                    body_preview = "",
                    normalized_preview = "",
                    encoding_layers = {},
                    encoding_layer_count = 0,
                    obfusc_score = 0,
                    attack_class = "anti_cc",
                    confidence = 1,
                    sql_hits = 0,
                    xss_hits = 0
                }, client_ip, uri, method, 444, true)
                if inspection_summary then
                    persist_inspection_summary(inspection_summary)
                end

                log_request(site_config, client_ip, uri, 444, true, "anti_cc_" .. (cc_reason or "unknown"))
                update_stats(site_config, client_ip, uri, method, true, "anti_cc_" .. (cc_reason or "unknown"))
                ngx.exit(444)
                return
            end

            -- 判断验证方式
            local verification_type, difficulty = select_verification_method(site_config, "anti_cc", client_ip, uri)

            local inspection_summary = normalize_inspection_summary({
                trigger_reason = "anti_cc_" .. tostring(cc_reason or "unknown"),
                source = "anti_cc",
                label = verification_type or "challenge",
                matched_signature = tostring(cc_reason or "unknown"),
                score = score,
                body_preview = "",
                normalized_preview = "",
                encoding_layers = {},
                encoding_layer_count = 0,
                obfusc_score = 0,
                attack_class = "anti_cc",
                confidence = 1,
                sql_hits = 0,
                xss_hits = 0
            }, client_ip, uri, method, 403, true)
            if inspection_summary then
                persist_inspection_summary(inspection_summary)
            end

            -- 记录请求
            log_request(site_config, client_ip, uri, 403, true, "anti_cc_" .. (cc_reason or "unknown"))

            -- 更新统计信息
            update_stats(site_config, client_ip, uri, method, true, "anti_cc_" .. (cc_reason or "unknown"))

            redirect_to_verification(site_config, verification_type, "anti_cc", difficulty)
            return
        end
    end
    
    -- 流量动态识别
    if (not skip_deep_checks) and site_config.traffic_analysis_enabled then
        local is_anomalous, score = ddos_protection.analyze_traffic_pattern(client_ip)
        if is_anomalous then
            -- 记录异常
            local total_score = utils.record_anomaly(client_ip, uri, "anomalous_traffic", score)
            maybe_auto_blacklist(site_config, client_ip, total_score)

            if total_score >= 45 then
                local inspection_summary = normalize_inspection_summary({
                    trigger_reason = "anomalous_traffic",
                    source = "traffic_analysis",
                    label = "drop",
                    matched_signature = "anomalous_traffic",
                    score = tonumber(score or 0) or 0,
                    body_preview = "",
                    normalized_preview = "",
                    encoding_layers = {},
                    encoding_layer_count = 0,
                    obfusc_score = 0,
                    attack_class = "traffic_anomaly",
                    confidence = 1,
                    sql_hits = 0,
                    xss_hits = 0
                }, client_ip, uri, method, 444, true)
                if inspection_summary then
                    persist_inspection_summary(inspection_summary)
                end

                log_request(site_config, client_ip, uri, 444, true, "anomalous_traffic")
                update_stats(site_config, client_ip, uri, method, true, "anomalous_traffic")
                ngx.exit(444)
                return
            end

            -- 判断验证方式
            local verification_type, difficulty = select_verification_method(site_config, "traffic_analysis", client_ip, uri)

            local inspection_summary = normalize_inspection_summary({
                trigger_reason = "anomalous_traffic",
                source = "traffic_analysis",
                label = verification_type or "challenge",
                matched_signature = "anomalous_traffic",
                score = tonumber(score or 0) or 0,
                body_preview = "",
                normalized_preview = "",
                encoding_layers = {},
                encoding_layer_count = 0,
                obfusc_score = 0,
                attack_class = "traffic_anomaly",
                confidence = 1,
                sql_hits = 0,
                xss_hits = 0
            }, client_ip, uri, method, 403, true)
            if inspection_summary then
                persist_inspection_summary(inspection_summary)
            end

            -- 记录请求
            log_request(site_config, client_ip, uri, 403, true, "anomalous_traffic")

            -- 更新统计信息
            update_stats(site_config, client_ip, uri, method, true, "anomalous_traffic")

            redirect_to_verification(site_config, verification_type, "traffic_analysis", difficulty)
            return
        end
    end
    
    -- 随机抽样检测
    if (not skip_deep_checks) and site_config.request_sampling_enabled and
       utils.sample_request(site_config.sampling_rate or 0.01) then
        -- 进行深度行为和特征分析
        local features, feature_data = utils.extract_request_features(client_ip, uri, method, ngx.req.get_uri_args(), ngx.req.get_headers())

        -- 异常检测
        local is_anomalous, distance = utils.is_anomalous_request(features, site_config.anomaly_threshold or 5.0)

        if is_anomalous then
            -- 记录异常
            local total_score = utils.record_anomaly(client_ip, uri, "sampled_anomaly", distance)
            maybe_auto_blacklist(site_config, client_ip, total_score)

            if distance > 15 then
                local inspection_summary = normalize_inspection_summary({
                    trigger_reason = "sampled_anomaly",
                    source = "sampling",
                    label = "drop",
                    matched_signature = "sampled_anomaly",
                    score = tonumber(distance or 0) or 0,
                    body_preview = "",
                    normalized_preview = "",
                    encoding_layers = {},
                    encoding_layer_count = 0,
                    obfusc_score = 0,
                    attack_class = "anomaly",
                    confidence = 1,
                    sql_hits = 0,
                    xss_hits = 0
                }, client_ip, uri, method, 444, true)
                if inspection_summary then
                    persist_inspection_summary(inspection_summary)
                end

                log_request(site_config, client_ip, uri, 444, true, "sampled_anomaly")
                update_stats(site_config, client_ip, uri, method, true, "sampled_anomaly")
                ngx.exit(444)
                return
            end

            -- 如果异常分数高，进行验证
            if distance > 8 then
                -- 判断验证方式
                local verification_type, difficulty = select_verification_method(site_config, "anomaly_detection", client_ip, uri)

                local inspection_summary = normalize_inspection_summary({
                    trigger_reason = "anomaly_detection",
                    source = "sampling",
                    label = verification_type or "challenge",
                    matched_signature = "sampled_anomaly",
                    score = tonumber(distance or 0) or 0,
                    body_preview = "",
                    normalized_preview = "",
                    encoding_layers = {},
                    encoding_layer_count = 0,
                    obfusc_score = 0,
                    attack_class = "anomaly",
                    confidence = 1,
                    sql_hits = 0,
                    xss_hits = 0
                }, client_ip, uri, method, 403, true)
                if inspection_summary then
                    persist_inspection_summary(inspection_summary)
                end

                -- 记录请求
                log_request(site_config, client_ip, uri, 403, true, "anomaly_detection")

                -- 更新统计信息
                update_stats(site_config, client_ip, uri, method, true, "anomaly_detection")

                redirect_to_verification(site_config, verification_type, "anomaly_detection", difficulty)
                return
            end
        end
    end
    
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
end

-- 执行WAF处理
process_waf()
