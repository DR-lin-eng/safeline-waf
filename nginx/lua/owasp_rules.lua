local _M = {}

local function clamp_integer(value, default_value, min_value, max_value)
    local normalized = tonumber(value)
    if normalized == nil then
        normalized = default_value
    end

    normalized = math.floor(normalized)
    if normalized < min_value then
        normalized = min_value
    elseif normalized > max_value then
        normalized = max_value
    end

    return normalized
end

_M.PAYLOAD_RULES = {
    { id = "941100", tag = "application-attack-xss", name = "xss_script_tag", paranoia = 1, score = 5, pattern = [[<\s*script\b]] },
    { id = "941110", tag = "application-attack-xss", name = "xss_event_handler", paranoia = 1, score = 5, pattern = [[on(?:error|load|click|mouseover|focus|submit|animationstart)\s*=]] },
    { id = "941120", tag = "application-attack-xss", name = "xss_protocol_handler", paranoia = 1, score = 5, pattern = [[(?:javascript|vbscript)\s*:|data\s*:\s*text/html]] },
    { id = "941130", tag = "application-attack-xss", name = "xss_svg_onload", paranoia = 2, score = 4, pattern = [[<\s*svg\b[^>]*onload\s*=]] },
    { id = "941140", tag = "application-attack-xss", name = "xss_srcdoc", paranoia = 2, score = 4, pattern = [[srcdoc\s*=]] },

    { id = "942100", tag = "application-attack-sqli", name = "sqli_union_select", paranoia = 1, score = 5, pattern = [[union\s+all?\s*select\b]] },
    { id = "942110", tag = "application-attack-sqli", name = "sqli_boolean_or", paranoia = 1, score = 5, pattern = [[['"`]?\s*or\s+['"`]?\w+['"`]?\s*=\s*['"`]?\w+]] },
    { id = "942120", tag = "application-attack-sqli", name = "sqli_time_delay", paranoia = 1, score = 5, pattern = [[(?:sleep|benchmark|pg_sleep)\s*\(|waitfor\s+delay]] },
    { id = "942130", tag = "application-attack-sqli", name = "sqli_stacked_query", paranoia = 2, score = 4, pattern = [[;\s*(?:select|insert|update|delete|drop)\b]] },
    { id = "942140", tag = "application-attack-sqli", name = "sqli_schema_probe", paranoia = 2, score = 4, pattern = [[(?:information_schema|pg_catalog|sqlite_master)\b]] },

    { id = "930100", tag = "application-attack-lfi", name = "path_traversal", paranoia = 1, score = 5, pattern = [[(?:\.\.[/\\]+|\.{2,}\s*/+)|/etc/passwd|/proc/self/environ|/windows/win\.ini|boot\.ini|web\.config]] },
    { id = "930110", tag = "application-attack-lfi", name = "encoded_path_traversal", paranoia = 2, score = 4, pattern = [[(?:%2e%2e|%252e%252e|%c0%ae%c0%ae|%c0%af|%5c%2e%2e)]] },

    { id = "932100", tag = "application-attack-rce", name = "command_injection_chain", paranoia = 1, score = 5, pattern = [[(?:;|&&|\|\|)\s*(?:cat|ls|id|whoami|uname|bash|sh|nc|curl|wget)\b]] },
    { id = "932110", tag = "application-attack-rce", name = "command_substitution", paranoia = 2, score = 4, pattern = [[(?:\$\([^)]+\)|`[^`]+`|<\([^)]+\))]] },
    { id = "932120", tag = "application-attack-ssti", name = "template_injection", paranoia = 2, score = 4, pattern = [[(?:\{\{[^}]+\}\}|<%=?|%\{|#\{[^}]+\}|__import__\s*\()]] },
    { id = "932130", tag = "application-attack-ognl", name = "ognl_expression", paranoia = 1, score = 5, pattern = [[(?:%\{[^}]+}|#(?:context|_memberAccess|attr|parameters)|@java\.lang\.runtime@getruntime\(\)|new\s+java\.lang\.processbuilder)]] },
    { id = "932140", tag = "application-attack-spel", name = "spel_expression", paranoia = 1, score = 5, pattern = [[(?:t\s*\(\s*java\.lang\.(?:runtime|system)|#this|#root|#request|new\s+java\.lang\.)]] },
    { id = "932150", tag = "application-attack-ssti", name = "freemarker_expression", paranoia = 2, score = 4, pattern = [[(?:<#(?:assign|if|list|include)|\$\{[^}]+}|freemarker\.template\.utility\.execute)]] },
    { id = "932160", tag = "application-attack-ssti", name = "twig_expression", paranoia = 2, score = 4, pattern = [[(?:\{\{[^}]+\}\}|\{%[^%]+%\}|_self|attribute\(|dump\())]] },
    { id = "932170", tag = "application-attack-ssti", name = "velocity_expression", paranoia = 2, score = 4, pattern = [[(?:#set\s*\(|#foreach\s*\(|#if\s*\(|\$class\.inspect|\$velocitycount|#evaluate\s*\())]] },

    { id = "920120", tag = "protocol-attack", name = "header_injection", paranoia = 1, score = 5, pattern = [[(?:%0d%0a|\\r\\n|%0a%0d)]] },

    { id = "934100", tag = "application-attack-ssrf", name = "ssrf_dangerous_scheme", paranoia = 1, score = 5, pattern = [[\b(?:dict|gopher|file|jar|ldap|ldaps|tftp)\s*://]] },
    { id = "934110", tag = "application-attack-ssrf", name = "ssrf_metadata", paranoia = 1, score = 5, pattern = [[(?:169\.254\.169\.254|metadata\.google(?:\.internal)?|metadata\.azure|100\.100\.100\.200)\b]] },
    { id = "934120", tag = "application-attack-ssrf", name = "ssrf_internal_http", paranoia = 2, score = 4, pattern = [[https?\s*://\s*(?:127\.0\.0\.1|0\.0\.0\.0|localhost|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|\[::1\]|::1|\[(?:fc|fd)[0-9a-f:]+\]|\[(?:fe80)[0-9a-f:]+\]|(?:fc|fd)[0-9a-f:]+|fe80:[0-9a-f:]+)]] },

    { id = "944100", tag = "application-attack-java", name = "jndi_lookup", paranoia = 1, score = 5, pattern = [[\$\s*\{\s*jndi\s*:]] },
    { id = "944110", tag = "application-attack-java", name = "jndi_nested_lookup", paranoia = 2, score = 4, pattern = [[\$\s*\{\s*\$\s*\{]] },

    { id = "933110", tag = "application-attack-graphql", name = "graphql_introspection", paranoia = 2, score = 3, pattern = [[__(?:schema|type)\b]] }
}

function _M.resolve_config(site_config, global_config)
    site_config = type(site_config) == "table" and site_config or {}
    global_config = type(global_config) == "table" and global_config or {}

    local enabled = site_config.owasp_crs_enabled
    if enabled == nil then
        enabled = global_config.enabled ~= false
    end

    return {
        enabled = enabled == true,
        paranoia_level = clamp_integer(site_config.owasp_paranoia_level, global_config.paranoia_level or 1, 1, 4),
        inbound_threshold = clamp_integer(site_config.owasp_inbound_threshold, global_config.inbound_threshold or 5, 1, 100),
        max_matches = clamp_integer(site_config.owasp_max_matches, global_config.max_matches or 8, 1, 32)
    }
end

return _M
