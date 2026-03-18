-- Semantic Feature Extractor for Payload Inspection
-- Extracts 20 features and classifies via lightweight decision tree
local _M = {}

local normalizer = require "semantic.payload_normalizer"

-- ─── Keyword Sets ─────────────────────────────────────────────────────────
local SQL_KEYWORDS = {
    "select", "union", "insert", "update", "delete", "drop", "create",
    "alter", "exec", "execute", "xp_", "sp_", "information_schema",
    "sysobjects", "syscolumns", "sleep(", "benchmark(", "waitfor",
    "char(", "ascii(", "substr(", "concat(", "group_by", "order_by",
    "having", "from", "where", "into", "outfile", "load_file",
}

local XSS_PATTERNS = {
    "<script", "</script>", "javascript:", "vbscript:", "data:",
    "onerror=", "onload=", "onclick=", "onmouseover=", "onfocus=",
    "alert(", "prompt(", "confirm(", "document.cookie", "document.write",
    "eval(", "settimeout(", "setinterval(", "fromcharcode(",
    "expression(", "url(", "innerHTML", "outerHTML",
}

local PATH_TRAVERSAL = {
    "../", "..\\", "/..", "\\..", "/etc/passwd", "/etc/shadow",
    "c:\\windows", "c:/windows", "/proc/self", "boot.ini",
    "web.config", ".htaccess", "win.ini",
}

local SSRF_PATTERNS = {
    "localhost", "127.0.0.1", "0.0.0.0", "169.254.", "192.168.",
    "10.0.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "file://", "dict://", "gopher://", "ftp://", "ldap://",
    "metadata.google.internal", "169.254.169.254",
}

local JNDI_PATTERNS = {
    "jndi:", "jndi:ldap", "jndi:rmi", "jndi:dns", "jndi:iiop",
    "${", "#{", "{{",  -- common injection templates
}

local BOOLEAN_TAUTOLOGY = {
    "1=1", "1 = 1", "'1'='1'", "\"1\"=\"1\"",
    "or 1=1", "or true", "and 1=1",
    "' or ''='", "\" or \"\"=\"",
}

-- ─── Utility: count keyword hits ──────────────────────────────────────────
local function count_keywords(text_lower, kw_list)
    local count = 0
    for _, kw in ipairs(kw_list) do
        if text_lower:find(kw, 1, true) then
            count = count + 1
        end
    end
    return count
end

-- ─── Entropy ──────────────────────────────────────────────────────────────
local function char_entropy(s)
    if #s == 0 then return 0 end
    local freq = {}
    for i = 1, #s do
        local ch = s:sub(i, i)
        freq[ch] = (freq[ch] or 0) + 1
    end
    local h = 0
    for _, c in pairs(freq) do
        local p = c / #s
        if p > 0 then h = h - p * math.log(p) end
    end
    return h
end

-- Character bigram entropy
local function bigram_entropy(s)
    if #s < 2 then return 0 end
    local bigrams = {}
    local total = 0
    for i = 1, #s - 1 do
        local bg = s:sub(i, i+1)
        bigrams[bg] = (bigrams[bg] or 0) + 1
        total = total + 1
    end
    local h = 0
    for _, c in pairs(bigrams) do
        local p = c / total
        if p > 0 then h = h - p * math.log(p) end
    end
    return h
end

-- ─── Structural Analysis ──────────────────────────────────────────────────
local function count_nesting_depth(s)
    local depth = 0
    local max_depth = 0
    for i = 1, #s do
        local ch = s:sub(i, i)
        if ch == "(" or ch == "[" or ch == "{" then
            depth = depth + 1
            if depth > max_depth then max_depth = depth end
        elseif ch == ")" or ch == "]" or ch == "}" then
            depth = depth - 1
        end
    end
    return max_depth
end

local function bracket_imbalance(s)
    local open  = 0
    local close = 0
    for i = 1, #s do
        local ch = s:sub(i, i)
        if ch == "(" or ch == "[" or ch == "{" then
            open = open + 1
        elseif ch == ")" or ch == "]" or ch == "}" then
            close = close + 1
        end
    end
    return math.abs(open - close)
end

-- ─── Token Count ──────────────────────────────────────────────────────────
local function count_tokens(s)
    local n = 0
    for _ in s:gmatch("%S+") do n = n + 1 end
    return n
end

-- ─── Context Detection ────────────────────────────────────────────────────
local function detect_context(payload)
    local pl = payload:lower()
    local is_json = (payload:sub(1,1) == "{" or payload:sub(1,1) == "[") and 1 or 0
    local is_xml  = (payload:sub(1,1) == "<") and 1 or 0
    -- Quick SQL context: starts with SELECT / has FROM clause
    local is_sql  = (pl:find("^%s*select") or pl:find("%sfrom%s")) and 1 or 0
    return is_json, is_xml, (is_sql or 0)
end

-- ─── Approximate Compression Ratio ────────────────────────────────────────
-- Use run-length encoding as a proxy for compressibility
local function rle_ratio(s)
    if #s == 0 then return 1 end
    local runs = 0
    local i = 1
    while i <= #s do
        runs = runs + 1
        local ch = s:sub(i, i)
        while i <= #s and s:sub(i, i) == ch do i = i + 1 end
    end
    return runs / #s  -- low ratio = highly compressible (repetitive)
end

-- ─── Feature Extraction ───────────────────────────────────────────────────
-- Returns 20-element numeric array + metadata table
function _M.extract_features(payload, context_hint)
    if type(payload) ~= "string" then
        return {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, {}
    end

    -- Normalize first
    local norm, enc_layers, obfusc_score = normalizer.normalize(payload, 4)
    local pl = norm:lower()

    local f = {}

    -- 1  sql_keyword_density  (hits / payload_length)
    local sql_hits = count_keywords(pl, SQL_KEYWORDS)
    f[1] = (#pl > 0) and (sql_hits / #pl * 100) or 0

    -- 2  xss_keyword_density
    local xss_hits = count_keywords(pl, XSS_PATTERNS)
    f[2] = (#pl > 0) and (xss_hits / #pl * 100) or 0

    -- 3  path_traversal_hits
    f[3] = count_keywords(pl, PATH_TRAVERSAL)

    -- 4  ssrf_keyword_hits
    f[4] = count_keywords(pl, SSRF_PATTERNS)

    -- 5  operator_count  (SQL/logic operators)
    local op_count = 0
    for _ in pl:gmatch("[=<>!]+") do op_count = op_count + 1 end
    for _ in pl:gmatch("%sor%s") do op_count = op_count + 1 end
    for _ in pl:gmatch("%sand%s") do op_count = op_count + 1 end
    f[5] = op_count

    -- 6  identifier_entropy  (of the normalized payload)
    f[6] = char_entropy(norm)

    -- 7  nesting_depth
    f[7] = count_nesting_depth(norm)

    -- 8  bracket_imbalance
    f[8] = bracket_imbalance(norm)

    -- 9  char_bigram_entropy
    f[9] = bigram_entropy(norm)

    -- 10  gzip_ratio_approx  (via RLE proxy)
    f[10] = rle_ratio(norm)

    -- 11  has_sql_union_select
    f[11] = (pl:find("union%s+select") or pl:find("union%s+all%s+select")) and 1 or 0

    -- 12  has_boolean_tautology
    f[12] = count_keywords(pl, BOOLEAN_TAUTOLOGY) > 0 and 1 or 0

    -- 13  has_xss_event_handler
    f[13] = (pl:find("on%a+%s*=") ~= nil) and 1 or 0

    -- 14  has_path_traversal
    f[14] = (pl:find("%.%./") or pl:find("%.%.\\")) and 1 or 0

    -- 15  has_ssrf_internal_ip
    f[15] = (pl:find("127%.0%.0%.1") or pl:find("169%.254%.") or pl:find("192%.168%.")) and 1 or 0

    -- 16  has_jndi_lookup
    f[16] = count_keywords(pl, JNDI_PATTERNS) > 0 and 1 or 0

    -- 17  payload_length_log
    f[17] = math.log10(#norm + 1)

    -- 18  special_char_ratio
    local spec_count = 0
    for _ in norm:gmatch("[^%w%s]") do spec_count = spec_count + 1 end
    f[18] = (#norm > 0) and (spec_count / #norm) or 0

    -- 19  is_json / is_xml (packed as: 2=json, 1=xml, 0=neither)
    local is_json, is_xml, _ = detect_context(norm)
    f[19] = is_json == 1 and 2 or (is_xml == 1 and 1 or 0)

    -- 20  encoding_obfuscation_score
    f[20] = obfusc_score

    local meta = {
        normalized      = norm,
        encoding_layers = enc_layers,
        obfusc_score    = obfusc_score,
        sql_hits        = sql_hits,
        xss_hits        = xss_hits,
    }

    return f, meta
end

-- ─── Lightweight Decision Tree Classifier ─────────────────────────────────
-- Hard-coded thresholds based on typical attack signatures.
-- Returns: {class, confidence}  class ∈ {sqli, xss, path_traversal, ssrf, jndi, benign}
function _M.classify(feature_vec)
    local f = feature_vec
    if not f or #f < 20 then
        return { class = "unknown", confidence = 0 }
    end

    -- JNDI / Template Injection (check first – high specificity)
    if f[16] == 1 then
        local conf = 0.85 + math.min(f[20] * 0.01, 0.14)
        return { class = "jndi", confidence = math.min(conf, 0.99) }
    end

    -- SQL Injection signals
    local sqli_score = 0
    if f[11] == 1 then sqli_score = sqli_score + 0.50 end  -- UNION SELECT
    if f[12] == 1 then sqli_score = sqli_score + 0.25 end  -- tautology
    if f[1]  > 0.5 then sqli_score = sqli_score + 0.15 end -- keyword density
    if f[5]  > 3   then sqli_score = sqli_score + 0.10 end -- operators

    if sqli_score >= 0.50 then
        return { class = "sqli", confidence = math.min(sqli_score + f[20] * 0.01, 0.99) }
    end

    -- XSS signals
    local xss_score = 0
    if f[13] == 1 then xss_score = xss_score + 0.50 end   -- event handler
    if f[2]  > 0.3 then xss_score = xss_score + 0.25 end  -- keyword density
    if f[7]  > 4   then xss_score = xss_score + 0.10 end  -- nesting

    if xss_score >= 0.50 then
        return { class = "xss", confidence = math.min(xss_score + f[20] * 0.01, 0.99) }
    end

    -- Path Traversal
    if f[14] == 1 then
        local conf = 0.75 + math.min(f[3] * 0.05, 0.20)
        return { class = "path_traversal", confidence = math.min(conf, 0.99) }
    end

    -- SSRF
    if f[15] == 1 or f[4] >= 2 then
        return { class = "ssrf", confidence = 0.80 }
    end

    -- High obfuscation with no clear class
    if f[20] >= 6 then
        return { class = "obfuscation", confidence = 0.60 + math.min(f[20] * 0.01, 0.30) }
    end

    return { class = "benign", confidence = 1 - (f[1] + f[2]) * 0.1 }
end

-- ─── High-level API ───────────────────────────────────────────────────────
-- Returns {class, confidence, features, meta}
function _M.analyze(payload, context_hint)
    local features, meta = _M.extract_features(payload, context_hint)
    local result = _M.classify(features)
    result.features = features
    result.meta     = meta
    return result
end

-- ─── Attack Context Summary ───────────────────────────────────────────────
function _M.get_attack_context(payload)
    local result = _M.analyze(payload)
    if result.class == "benign" then
        return nil
    end
    return {
        attack_type   = result.class,
        confidence    = result.confidence,
        obfusc_score  = result.meta and result.meta.obfusc_score or 0,
        enc_layers    = result.meta and result.meta.encoding_layers or {},
        normalized    = result.meta and result.meta.normalized or payload,
    }
end

return _M
