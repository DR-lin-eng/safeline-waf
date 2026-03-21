'use strict';
/**
 * LLM Audit Worker
 * Polls llm:audit:queue, calls the configured LLM API,
 * parses the structured verdict, and applies auto-ban via Redis blacklist.
 */

const crypto = require('crypto');

// ── Encryption helpers for API key storage ────────────────────────────────
const ENC_ALGO = 'aes-256-gcm';

function encryptApiKey(plaintext, secret) {
  const key = crypto.createHash('sha256').update(secret).digest();
  const iv  = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ENC_ALGO, key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${tag.toString('hex')}:${enc.toString('hex')}`;
}

function decryptApiKey(ciphertext, secret) {
  const [ivHex, tagHex, encHex] = ciphertext.split(':');
  if (!ivHex || !tagHex || !encHex) return null;
  const key    = crypto.createHash('sha256').update(secret).digest();
  const iv     = Buffer.from(ivHex,  'hex');
  const tag    = Buffer.from(tagHex, 'hex');
  const enc    = Buffer.from(encHex, 'hex');
  const decipher = crypto.createDecipheriv(ENC_ALGO, key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(enc) + decipher.final('utf8');
}

// ── Verdict schema ─────────────────────────────────────────────────────────
// risk_level : "critical" | "high" | "medium" | "low" | "benign"
// attack_type: "sqli" | "xss" | "ssrf" | "rce" | "path_traversal" |
//              "spam" | "scraping" | "credential_stuffing" | "benign" | "other"
// action     : "ban_permanent" | "ban_24h" | "ban_1h" | "challenge" | "log" | "pass"
// confidence : 0.0 – 1.0
// reason     : short human-readable explanation

const SYSTEM_PROMPT = `You are an expert web application firewall security analyst.
Analyze the HTTP request data provided and respond ONLY with a single valid JSON object.
Do NOT include markdown, code fences, or any text outside the JSON.

JSON schema:
{
  "risk_level":  "critical|high|medium|low|benign",
  "attack_type": "sqli|xss|ssrf|rce|path_traversal|spam|scraping|credential_stuffing|benign|other",
  "reason":      "one-sentence explanation (max 120 chars)",
  "action":      "ban_permanent|ban_24h|ban_1h|challenge|log|pass",
  "confidence":  0.0
}

Guidelines:
- ban_permanent: confirmed critical attack (SQLi with data exfil, RCE, auth bypass)
- ban_24h: high-confidence attack or repeated aggression
- ban_1h: medium-confidence attack or aggressive scanning
- challenge: suspicious but not confirmed (bots, scrapers)
- log: low risk, just note it
- pass: clearly benign
- If review metadata contains ban_candidate=true, choose the ban duration based on evidence and confidence
- Treat suggested_ban_ttl as an operator hint when choosing between ban_1h, ban_24h, and ban_permanent
- current_request_disposition describes what the WAF already did to the current request; your action should decide future handling for this IP`;

const VERDICT_JSON_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['risk_level', 'attack_type', 'reason', 'action', 'confidence'],
  properties: {
    risk_level: {
      type: 'string',
      enum: ['critical', 'high', 'medium', 'low', 'benign']
    },
    attack_type: {
      type: 'string',
      enum: ['sqli', 'xss', 'ssrf', 'rce', 'path_traversal', 'spam', 'scraping', 'credential_stuffing', 'benign', 'other']
    },
    reason: {
      type: 'string',
      maxLength: 120
    },
    action: {
      type: 'string',
      enum: ['ban_permanent', 'ban_24h', 'ban_1h', 'challenge', 'log', 'pass']
    },
    confidence: {
      type: 'number',
      minimum: 0,
      maximum: 1
    }
  }
};

function normalizeProviderType(value) {
  const provider = String(value || '').trim();
  if (provider === 'anthropic' || provider === 'openai_responses') {
    return provider;
  }
  return 'openai';
}

function defaultEndpointForProvider(provider) {
  if (provider === 'anthropic') {
    return 'https://api.anthropic.com';
  }
  if (provider === 'openai_responses') {
    return 'https://api.openai.com/v1/responses';
  }
  return 'https://api.openai.com/v1';
}

function defaultModelForProvider(provider) {
  if (provider === 'anthropic') {
    return 'claude-haiku-4-5-20251001';
  }
  if (provider === 'openai_responses') {
    return 'gpt-5.4';
  }
  return 'gpt-4o-mini';
}

function normalizeProviderId(value, fallback) {
  const normalized = String(value || fallback || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, '-')
    .replace(/^-+|-+$/g, '');
  return normalized || String(fallback || 'provider').toLowerCase();
}

function legacyProvidersFromConfig(cfg) {
  if (!cfg || typeof cfg !== 'object') {
    return [];
  }
  if (Array.isArray(cfg.providers)) {
    return cfg.providers;
  }
  if (!cfg.provider && !cfg.api_endpoint && !cfg.model && !cfg.api_key_enc) {
    return [];
  }
  return [{
    id: 'provider-1',
    name: 'Primary',
    provider: cfg.provider,
    api_endpoint: cfg.api_endpoint,
    model: cfg.model,
    api_key_enc: cfg.api_key_enc,
    enabled: cfg.enabled !== false,
    timeout_ms: cfg.timeout_ms,
  }];
}

function normalizeNumber(value, fallback, min, max) {
  let number = Number(value);
  if (!Number.isFinite(number)) {
    number = Number(fallback);
  }
  if (!Number.isFinite(number)) {
    number = min;
  }
  if (number < min) number = min;
  if (number > max) number = max;
  return number;
}

function normalizeLlmConfig(input, existingConfig, jwtSecret) {
  const source = input && typeof input === 'object' ? input : {};
  const existing = existingConfig && typeof existingConfig === 'object' ? existingConfig : {};
  const existingProviders = legacyProvidersFromConfig(existing);
  const existingById = new Map(existingProviders.map((provider, index) => {
    const id = normalizeProviderId(provider && provider.id, `provider-${index + 1}`);
    return [id, provider || {}];
  }));

  const sourceProviders = Array.isArray(source.providers) ? source.providers : legacyProvidersFromConfig(source);
  const normalizedProviders = [];
  const seen = new Set();

  sourceProviders.forEach((provider, index) => {
    const draft = provider && typeof provider === 'object' ? provider : {};
    const providerId = normalizeProviderId(draft.id, `provider-${index + 1}`);
    if (seen.has(providerId)) {
      return;
    }
    seen.add(providerId);

    const previous = existingById.get(providerId) || {};
    const providerType = normalizeProviderType(draft.provider || previous.provider || 'openai_responses');
    let apiKeyEnc = previous.api_key_enc || '';
    if (typeof draft.api_key === 'string' && draft.api_key.trim() && !draft.api_key.startsWith('••')) {
      apiKeyEnc = encryptApiKey(draft.api_key.trim(), jwtSecret);
    } else if (typeof draft.api_key_enc === 'string' && draft.api_key_enc) {
      apiKeyEnc = draft.api_key_enc;
    }

    normalizedProviders.push({
      id: providerId,
      name: String(draft.name || previous.name || `Provider ${index + 1}`).trim() || `Provider ${index + 1}`,
      provider: providerType,
      api_endpoint: String(draft.api_endpoint || previous.api_endpoint || defaultEndpointForProvider(providerType)).trim(),
      model: String(draft.model || previous.model || defaultModelForProvider(providerType)).trim(),
      api_key_enc: apiKeyEnc,
      enabled: draft.enabled !== undefined ? !!draft.enabled : previous.enabled !== false,
      timeout_ms: normalizeNumber(draft.timeout_ms ?? previous.timeout_ms ?? source.timeout_ms ?? existing.timeout_ms ?? 15000, 15000, 3000, 60000),
    });
  });

  if (normalizedProviders.length === 0) {
    normalizedProviders.push({
      id: 'provider-1',
      name: 'Primary',
      provider: 'openai_responses',
      api_endpoint: defaultEndpointForProvider('openai_responses'),
      model: defaultModelForProvider('openai_responses'),
      api_key_enc: '',
      enabled: true,
      timeout_ms: normalizeNumber(source.timeout_ms ?? existing.timeout_ms ?? 15000, 15000, 3000, 60000),
    });
  }

  return {
    enabled: source.enabled !== undefined ? !!source.enabled : !!existing.enabled,
    failover_enabled: source.failover_enabled !== undefined ? !!source.failover_enabled : existing.failover_enabled !== false,
    providers: normalizedProviders,
    autoban_min_confidence: normalizeNumber(source.autoban_min_confidence ?? existing.autoban_min_confidence ?? 0.75, 0.75, 0.5, 1),
    batch_size: Math.floor(normalizeNumber(source.batch_size ?? existing.batch_size ?? 3, 3, 1, 10)),
    call_delay_ms: Math.floor(normalizeNumber(source.call_delay_ms ?? existing.call_delay_ms ?? 200, 200, 0, 10000)),
    verdict_cache_ttl_s: Math.floor(normalizeNumber(source.verdict_cache_ttl_s ?? existing.verdict_cache_ttl_s ?? 600, 600, 60, 86400)),
    timeout_ms: Math.floor(normalizeNumber(source.timeout_ms ?? existing.timeout_ms ?? 15000, 15000, 3000, 60000)),
    audit_triggers: Array.isArray(source.audit_triggers)
      ? source.audit_triggers
      : (Array.isArray(existing.audit_triggers) ? existing.audit_triggers : ['ml_gray_zone', 'payload_suspicious', 'high_block_rate']),
    updated_at: Date.now(),
  };
}

function sanitizeLlmConfigForClient(cfg) {
  if (!cfg || typeof cfg !== 'object') {
    return null;
  }
  const out = JSON.parse(JSON.stringify(cfg));
  if (Array.isArray(out.providers)) {
    out.providers = out.providers.map((provider) => {
      const clone = { ...provider };
      if (clone.api_key_enc) {
        clone.api_key_masked = '••••••••' + clone.api_key_enc.slice(-4);
        delete clone.api_key_enc;
      }
      return clone;
    });
  }
  delete out.api_key_enc;
  delete out.api_key;
  return out;
}

function buildUserPrompt(entry) {
  const metadata = entry.metadata && typeof entry.metadata === 'object' ? entry.metadata : null;
  const metadataText = metadata
    ? `\nReview metadata: ${JSON.stringify(metadata).slice(0, 400)}`
    : '';
  return `Analyze this web request:
IP: ${entry.ip}
Host: ${entry.host || '-'}
Method: ${entry.method}
URI: ${entry.uri}
User-Agent: ${entry.ua || '-'}
Referer: ${entry.referer || '-'}
Body preview: ${entry.body_preview || '(none)'}
WAF trigger reason: ${entry.trigger_reason}
ML risk score: ${entry.ml_score || 0}${metadataText}`;
}

// ── LLM API callers ────────────────────────────────────────────────────────

async function callOpenAICompatible(config, entry) {
  const https  = config.api_endpoint.startsWith('https') ? require('https') : require('http');
  const url    = new URL(`${config.api_endpoint.replace(/\/$/, '')}/chat/completions`);
  const body   = JSON.stringify({
    model:       config.model || 'gpt-4o-mini',
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user',   content: buildUserPrompt(entry) },
    ],
    response_format: { type: 'json_object' },
    max_tokens:  256,
    temperature: 0.1,
  });

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: url.hostname,
      port:     url.port || (url.protocol === 'https:' ? 443 : 80),
      path:     url.pathname + url.search,
      method:   'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${config.api_key}`,
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      let data = '';
      res.on('data', d => { data += d; });
      res.on('end', () => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error(`LLM HTTP ${res.statusCode}: ` + data.slice(0, 200)));
          return;
        }
        try {
          const parsed = JSON.parse(data);
          const content = parsed.choices?.[0]?.message?.content || '';
          resolve(content.trim());
        } catch (e) {
          reject(new Error('LLM response parse error: ' + data.slice(0, 200)));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(parseInt(config.timeout_ms || '15000', 10), () => {
      req.destroy(new Error('LLM request timeout'));
    });
    req.write(body);
    req.end();
  });
}

async function callOpenAIResponses(config, entry) {
  const https = config.api_endpoint.startsWith('https') ? require('https') : require('http');
  const url = new URL(config.api_endpoint);
  const body = JSON.stringify({
    model: config.model || 'gpt-5.4',
    input: [
      {
        role: 'system',
        content: [
          { type: 'input_text', text: SYSTEM_PROMPT }
        ]
      },
      {
        role: 'user',
        content: [
          { type: 'input_text', text: buildUserPrompt(entry) }
        ]
      }
    ],
    text: {
      format: {
        type: 'json_schema',
        name: 'waf_verdict',
        strict: true,
        schema: VERDICT_JSON_SCHEMA
      }
    },
    max_output_tokens: 256,
    temperature: 0.1
  });

  function extractResponseText(parsed) {
    if (typeof parsed.output_text === 'string' && parsed.output_text.trim()) {
      return parsed.output_text.trim();
    }

    if (Array.isArray(parsed.output)) {
      const parts = [];
      for (const item of parsed.output) {
        if (!item || !Array.isArray(item.content)) continue;
        for (const content of item.content) {
          if (!content) continue;
          if (typeof content.text === 'string' && content.text.trim()) {
            parts.push(content.text.trim());
          } else if (
            content.type === 'output_text'
            && typeof content.text === 'string'
            && content.text.trim()
          ) {
            parts.push(content.text.trim());
          }
        }
      }
      if (parts.length > 0) {
        return parts.join('\n').trim();
      }
    }

    return '';
  }

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.api_key}`,
        'Content-Length': Buffer.byteLength(body)
      }
    }, (res) => {
      let data = '';
      res.on('data', d => { data += d; });
      res.on('end', () => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error(`LLM HTTP ${res.statusCode}: ` + data.slice(0, 200)));
          return;
        }
        try {
          const parsed = JSON.parse(data);
          const content = extractResponseText(parsed);
          if (!content) {
            reject(new Error('LLM response parse error: ' + data.slice(0, 200)));
            return;
          }
          resolve(content);
        } catch (e) {
          reject(new Error('LLM response parse error: ' + data.slice(0, 200)));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(parseInt(config.timeout_ms || '15000', 10), () => {
      req.destroy(new Error('LLM request timeout'));
    });
    req.write(body);
    req.end();
  });
}

async function callAnthropicClaude(config, entry) {
  const https = require('https');
  const body  = JSON.stringify({
    model:      config.model || 'claude-haiku-4-5-20251001',
    max_tokens: 256,
    system:     SYSTEM_PROMPT,
    messages: [{ role: 'user', content: buildUserPrompt(entry) }],
  });

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'api.anthropic.com',
      port:     443,
      path:     '/v1/messages',
      method:   'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         config.api_key,
        'anthropic-version': '2023-06-01',
        'Content-Length':    Buffer.byteLength(body),
      },
    }, (res) => {
      let data = '';
      res.on('data', d => { data += d; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          const content = parsed.content?.[0]?.text || '';
          resolve(content.trim());
        } catch (e) {
          reject(new Error('Anthropic response parse error: ' + data.slice(0, 200)));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(parseInt(config.timeout_ms || '15000', 10), () => {
      req.destroy(new Error('Anthropic request timeout'));
    });
    req.write(body);
    req.end();
  });
}

async function callLLM(config, entry) {
  if (config.provider === 'anthropic') {
    return callAnthropicClaude(config, entry);
  }
  if (config.provider === 'openai_responses' || /\/responses\/?$/.test(config.api_endpoint || '')) {
    return callOpenAIResponses(config, entry);
  }
  // Default: OpenAI-compatible (works with OpenAI, DeepSeek, Ollama, etc.)
  return callOpenAICompatible(config, entry);
}

async function callLLMWithFailover(config, entry) {
  const normalized = (!config || !Array.isArray(config.providers))
    ? (() => {
        const providerType = normalizeProviderType(config && config.provider);
        return {
          failover_enabled: config ? config.failover_enabled !== false : true,
          timeout_ms: config ? config.timeout_ms : 15000,
          providers: [{
            id: 'provider-1',
            name: 'Primary',
            enabled: config ? config.enabled !== false : true,
            provider: providerType,
            api_endpoint: (config && config.api_endpoint) || defaultEndpointForProvider(providerType),
            model: (config && config.model) || defaultModelForProvider(providerType),
            api_key: config && config.api_key,
            timeout_ms: config && config.timeout_ms,
          }],
        };
      })()
    : {
        failover_enabled: config.failover_enabled !== false,
        timeout_ms: config.timeout_ms,
        providers: config.providers,
      };
  const providers = Array.isArray(normalized.providers)
    ? normalized.providers.filter((provider) => provider.enabled !== false && provider.api_key)
    : [];

  if (providers.length === 0) {
    throw new Error('No enabled LLM providers configured');
  }

  const errors = [];
  for (const provider of providers) {
    try {
      const text = await callLLM({
        ...normalized,
        ...provider,
        timeout_ms: provider.timeout_ms || normalized.timeout_ms,
      }, entry);
      return {
        text,
        provider,
      };
    } catch (error) {
      errors.push(`[${provider.id}] ${error.message}`);
      if (normalized.failover_enabled === false) {
        break;
      }
    }
  }

  throw new Error(errors.join(' | ') || 'All LLM providers failed');
}

// ── Verdict parser ────────────────────────────────────────────────────────

const VALID_RISK    = new Set(['critical','high','medium','low','benign']);
const VALID_ACTIONS = new Set(['ban_permanent','ban_24h','ban_1h','challenge','log','pass']);

function parseVerdict(rawText) {
  // Strip any markdown code fences
  const clean = rawText.replace(/```json?|```/g, '').trim();

  // Extract JSON substring (the first {...})
  const match = clean.match(/\{[\s\S]*\}/);
  if (!match) throw new Error('No JSON found in LLM response');

  const v = JSON.parse(match[0]);

  // Normalise and validate
  const risk_level  = VALID_RISK.has(v.risk_level)    ? v.risk_level  : 'low';
  const action      = VALID_ACTIONS.has(v.action)     ? v.action      : 'log';
  const confidence  = Math.min(1, Math.max(0, parseFloat(v.confidence) || 0));
  const attack_type = typeof v.attack_type === 'string' ? v.attack_type.slice(0, 40) : 'other';
  const reason      = typeof v.reason      === 'string' ? v.reason.slice(0, 200)     : '';

  return { risk_level, attack_type, action, confidence, reason };
}

// ── Auto-ban helper ────────────────────────────────────────────────────────

const ACTION_TTL = {
  ban_permanent: 0,          // permanent = no expiry (TTL 0 = permanent in our blacklist)
  ban_24h:       86400,
  ban_1h:        3600,
};

async function applyBan(redis, ip, action, reason, autobanMinConfidence) {
  const ttl = ACTION_TTL[action];
  if (ttl === undefined) return;  // not a ban action

  const blacklistKey = `safeline:blacklist:${ip}`;
  if (ttl === 0) {
    await redis.set(blacklistKey, '1');
  } else {
    await redis.setex(blacklistKey, ttl, '1');
  }

  // Also write into the safeline_blacklist shared dict via reload signal
  // (Nginx workers pick it up on next config reload or via Pub/Sub)
  const reloadMsg = JSON.stringify({
    action: 'add',
    ip,
    ttl,
    reason: `LLM audit: ${reason}`,
    source: 'llm_worker',
    timestamp: Date.now(),
  });
  await redis.publish('cluster:blacklist:sync', reloadMsg);

  console.log(`[LLM] Auto-banned ${ip} | action=${action} ttl=${ttl}s | ${reason}`);
}

// ── Main worker class ──────────────────────────────────────────────────────

class LLMWorker {
  constructor(redis, jwtSecret) {
    this.redis         = redis;
    this.jwtSecret     = jwtSecret;
    this.running       = false;
    this.pollInterval  = null;
    this.consecutiveErrors = 0;
    this.MAX_ERRORS    = 10;   // pause if too many consecutive errors
  }

  /** Load LLM config from Redis. Returns null if LLM is not configured. */
  async loadConfig() {
    const raw = await this.redis.get('llm:config');
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    const cfg = normalizeLlmConfig(parsed, parsed, this.jwtSecret);
    if (!cfg.enabled) return null;

    cfg.providers = cfg.providers
      .map((provider) => {
        const resolved = { ...provider };
        if (resolved.api_key_enc && this.jwtSecret) {
          try {
            resolved.api_key = decryptApiKey(resolved.api_key_enc, this.jwtSecret);
          } catch (_) {
            resolved.api_key = resolved.api_key_enc;
          }
        }
        return resolved;
      })
      .filter((provider) => provider.enabled !== false && provider.api_key);

    if (cfg.providers.length === 0) {
      return null;
    }
    return cfg;
  }

  async processOne(config, entryRaw) {
    let entry;
    try {
      entry = JSON.parse(entryRaw);
    } catch (_) {
      return;  // corrupted entry, discard
    }

    const ip = entry.ip;
    if (!ip) return;

    // Skip if this IP already has a fresh verdict
    const existingRaw = await this.redis.get(`llm:verdict:${ip}`);
    if (existingRaw) {
      // Already analysed recently – skip
      return;
    }

    let verdict;
    let resolvedProvider = null;
    try {
      const result = await callLLMWithFailover(config, entry);
      resolvedProvider = result.provider || null;
      const rawText = result.text;
      verdict = parseVerdict(rawText);
    } catch (err) {
      console.warn(`[LLM] Analysis failed for ${ip}: ${err.message}`);
      this.consecutiveErrors++;
      return;
    }

    this.consecutiveErrors = 0;

    // Enrich verdict with metadata
    const fullVerdict = {
      ...verdict,
      ip,
      host:           entry.host,
      method:         entry.method,
      uri:            entry.uri,
      trigger_reason: entry.trigger_reason,
      ml_score:       entry.ml_score,
      analysed_at:    Date.now(),
      model:          resolvedProvider ? resolvedProvider.model : config.model,
      provider:       resolvedProvider ? resolvedProvider.provider : 'openai',
      provider_id:    resolvedProvider ? resolvedProvider.id : null,
      provider_name:  resolvedProvider ? resolvedProvider.name : null,
      metadata:       entry.metadata || null,
    };

    const verdictJson = JSON.stringify(fullVerdict);
    const autobanMinConf = parseFloat(config.autoban_min_confidence || '0.75');

    // Store verdict for Nginx workers (TTL: configurable, default 10 min)
    const verdictTtl = parseInt(config.verdict_cache_ttl_s || '600', 10);
    await this.redis.setex(`llm:verdict:${ip}`, verdictTtl, verdictJson);

    // Append to verdict history list (capped at 2000 entries)
    await this.redis.lpush('llm:verdicts', verdictJson);
    await this.redis.ltrim('llm:verdicts', 0, 1999);

    // Increment stats
    await this.redis.incr('llm:stats:total');
    await this.redis.incr(`llm:stats:risk:${verdict.risk_level}`);
    if (verdict.attack_type !== 'benign') {
      await this.redis.incr(`llm:stats:type:${verdict.attack_type}`);
    }

    // Apply auto-ban if confidence meets threshold
    const isBanCandidate = !!(entry.metadata && entry.metadata.ban_candidate);
    if (ACTION_TTL[verdict.action] !== undefined && (isBanCandidate || verdict.confidence >= autobanMinConf)) {
      await applyBan(this.redis, ip, verdict.action, verdict.reason, autobanMinConf);
      await this.redis.incr('llm:stats:autobanned');
    }

    const riskIcon = { critical:'🔴', high:'🟠', medium:'🟡', low:'🔵', benign:'🟢' }[verdict.risk_level] || '⚪';
    console.log(`[LLM] ${riskIcon} ${ip} | ${verdict.risk_level} | ${verdict.attack_type} | action=${verdict.action} | conf=${verdict.confidence.toFixed(2)} | ${verdict.reason}`);
  }

  async pollOnce() {
    const config = await this.loadConfig();
    if (!config) return;  // LLM not configured

    if (this.consecutiveErrors >= this.MAX_ERRORS) {
      // Back off for 60 seconds
      console.warn(`[LLM] Too many errors (${this.consecutiveErrors}), backing off 60s`);
      await new Promise(r => setTimeout(r, 60000));
      this.consecutiveErrors = 0;
      return;
    }

    // Process up to batchSize entries per poll
    const batchSize = Math.min(parseInt(config.batch_size || '3', 10), 10);

    for (let i = 0; i < batchSize; i++) {
      const result = await this.redis.rpop('llm:audit:queue');
      if (!result) break;  // queue empty
      await this.processOne(config, result);
      // Small delay between LLM calls to respect rate limits
      await new Promise(r => setTimeout(r, parseInt(config.call_delay_ms || '200', 10)));
    }
  }

  start() {
    if (this.running) return;
    this.running = true;
    const interval = 1500;  // poll every 1.5 seconds

    const loop = async () => {
      if (!this.running) return;
      try {
        await this.pollOnce();
      } catch (err) {
        console.error('[LLM] Worker poll error:', err.message);
        this.consecutiveErrors++;
      }
      this.pollInterval = setTimeout(loop, interval);
    };

    this.pollInterval = setTimeout(loop, 2000);  // start after 2s
    console.log('[LLM] Audit worker started');
  }

  stop() {
    this.running = false;
    if (this.pollInterval) clearTimeout(this.pollInterval);
    console.log('[LLM] Audit worker stopped');
  }
}

module.exports = {
  LLMWorker,
  encryptApiKey,
  decryptApiKey,
  normalizeLlmConfigDirect: normalizeLlmConfig,
  sanitizeLlmConfigForClientDirect: sanitizeLlmConfigForClient,
  callLLMDirect:    callLLMWithFailover,
  parseVerdictDirect: parseVerdict,
};
