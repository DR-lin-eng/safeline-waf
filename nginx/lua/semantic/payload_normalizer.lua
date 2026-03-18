-- Semantic Payload Normalizer
-- Multi-layer encoding detection and unwrapping
local _M = {}

local ENCODING_URL      = "url"
local ENCODING_HTML     = "html"
local ENCODING_BASE64   = "base64"
local ENCODING_HEX      = "hex"
local ENCODING_UNICODE  = "unicode"

-- ─── URL Decode ───────────────────────────────────────────────────────────
local function url_decode(s)
    return (s:gsub("%%(%x%x)", function(hex)
        return string.char(tonumber(hex, 16))
    end):gsub("+", " "))
end

local function looks_url_encoded(s)
    -- Has at least one %XX that is not already decoded
    return s:match("%%[0-9a-fA-F][0-9a-fA-F]") ~= nil
end

-- ─── HTML Entity Decode ───────────────────────────────────────────────────
local HTML_ENTITIES = {
    ["&amp;"]   = "&",
    ["&lt;"]    = "<",
    ["&gt;"]    = ">",
    ["&quot;"]  = '"',
    ["&#39;"]   = "'",
    ["&apos;"]  = "'",
    ["&nbsp;"]  = " ",
    ["&semi;"]  = ";",
    ["&equals;"]= "=",
    ["&lpar;"]  = "(",
    ["&rpar;"]  = ")",
}

local function html_decode(s)
    -- Named entities
    s = s:gsub("&[a-zA-Z]+;", function(e)
        return HTML_ENTITIES[e] or e
    end)
    -- Decimal &#NNN;
    s = s:gsub("&#(%d+);", function(n)
        local cp = tonumber(n)
        if cp and cp >= 0 and cp <= 127 then
            return string.char(cp)
        end
        return ""
    end)
    -- Hex &#xNN;
    s = s:gsub("&#x(%x+);", function(h)
        local cp = tonumber(h, 16)
        if cp and cp >= 0 and cp <= 127 then
            return string.char(cp)
        end
        return ""
    end)
    return s
end

local function looks_html_encoded(s)
    return s:match("&[a-zA-Z]+;") ~= nil
        or s:match("&#%d+;") ~= nil
        or s:match("&#x%x+;") ~= nil
end

-- ─── Base64 Detection & Decode ────────────────────────────────────────────
local function is_valid_base64(s)
    -- Must be >8 chars, only base64 alphabet, correctly padded
    if #s < 8 then return false end
    if s:match("[^A-Za-z0-9+/=]") then return false end
    -- Length must be multiple of 4 (with padding)
    local stripped = s:gsub("=", "")
    return (#stripped % 4) <= 2
end

local function base64_decode_safe(s)
    local pad = #s % 4
    if pad == 2 then s = s .. "=="
    elseif pad == 3 then s = s .. "="
    end
    local ok, result = pcall(ngx.decode_base64, s)
    if ok and result then return result end
    return nil
end

local function looks_base64(s)
    -- Heuristic: long alphanum string that is a valid b64
    if #s < 12 then return false end
    -- Must have high ratio of valid chars
    local valid = s:match("^[A-Za-z0-9+/]+=*$")
    return valid ~= nil and is_valid_base64(s)
end

-- ─── Hex Decode ───────────────────────────────────────────────────────────
-- Handles 0x414141 or \x41\x41 style
local function hex_decode(s)
    -- Remove 0x prefix and decode
    local stripped = s:gsub("0x", ""):gsub("\\x", "")
    if #stripped % 2 ~= 0 then return nil end
    local result = stripped:gsub("%x%x", function(h)
        return string.char(tonumber(h, 16))
    end)
    return result
end

local function looks_hex_encoded(s)
    -- Matches \xNN\xNN... or 0xNNNN...
    return s:match("\\x%x%x") ~= nil or s:match("0x%x%x%x%x") ~= nil
end

-- ─── Unicode Unescape ─────────────────────────────────────────────────────
local function unicode_unescape(s)
    -- \uXXXX and \UXXXXXXXX (ASCII range only for safety)
    s = s:gsub("\\u(%x%x%x%x)", function(h)
        local cp = tonumber(h, 16)
        if cp and cp >= 0 and cp <= 127 then
            return string.char(cp)
        end
        return ""
    end)
    s = s:gsub("\\U%x%x%x%x%x%x%x%x", "")  -- strip non-ASCII \U escapes
    return s
end

local function looks_unicode_escaped(s)
    return s:match("\\u%x%x%x%x") ~= nil
end

-- ─── Core Normalisation Loop ──────────────────────────────────────────────
local MAX_DEPTH = 6

function _M.normalize(payload, max_depth)
    if type(payload) ~= "string" or payload == "" then
        return payload, {}, 0
    end

    max_depth = max_depth or MAX_DEPTH
    local layers   = {}
    local current  = payload
    local prev     = nil
    local depth    = 0

    while current ~= prev and depth < max_depth do
        prev = current
        depth = depth + 1

        if looks_url_encoded(current) then
            local decoded = url_decode(current)
            if decoded ~= current then
                table.insert(layers, ENCODING_URL)
                current = decoded
                goto next_layer
            end
        end

        if looks_html_encoded(current) then
            local decoded = html_decode(current)
            if decoded ~= current then
                table.insert(layers, ENCODING_HTML)
                current = decoded
                goto next_layer
            end
        end

        if looks_hex_encoded(current) then
            local decoded = hex_decode(current)
            if decoded and decoded ~= current then
                table.insert(layers, ENCODING_HEX)
                current = decoded
                goto next_layer
            end
        end

        if looks_unicode_escaped(current) then
            local decoded = unicode_unescape(current)
            if decoded ~= current then
                table.insert(layers, ENCODING_UNICODE)
                current = decoded
                goto next_layer
            end
        end

        -- Base64: only attempt on standalone tokens that look like b64
        -- (avoid decoding random alphanumeric strings)
        local token = current:match("^([A-Za-z0-9+/]+=*)$")
        if token and looks_base64(token) then
            local decoded = base64_decode_safe(token)
            if decoded and decoded ~= current and #decoded > 0 then
                -- Only accept if decoded text is ASCII printable
                if decoded:match("^[\x20-\x7e]+$") then
                    table.insert(layers, ENCODING_BASE64)
                    current = decoded
                    goto next_layer
                end
            end
        end

        -- No transformation this round – stop
        break
        ::next_layer::
    end

    -- Obfuscation score: more encoding layers = higher score
    local obfuscation_score = #layers * 2
    -- Bonus for mixing different encoding types
    local seen = {}
    for _, l in ipairs(layers) do seen[l] = true end
    local distinct = 0
    for _ in pairs(seen) do distinct = distinct + 1 end
    if distinct > 1 then obfuscation_score = obfuscation_score + distinct * 3 end

    return current, layers, obfuscation_score
end

-- ─── Detect Encoding Layers (without normalising) ─────────────────────────
function _M.detect_encoding_layers(text)
    local layers = {}
    if looks_url_encoded(text)     then table.insert(layers, ENCODING_URL)     end
    if looks_html_encoded(text)    then table.insert(layers, ENCODING_HTML)    end
    if looks_hex_encoded(text)     then table.insert(layers, ENCODING_HEX)     end
    if looks_unicode_escaped(text) then table.insert(layers, ENCODING_UNICODE) end
    if looks_base64(text)          then table.insert(layers, ENCODING_BASE64)  end
    return layers
end

-- ─── Quick Obfuscation Score ──────────────────────────────────────────────
function _M.detect_obfuscation_score(text)
    local _, _, score = _M.normalize(text, 4)
    return score
end

return _M
