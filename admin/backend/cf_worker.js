'use strict';
/**
 * Cloudflare Five-Second Shield Worker
 *
 * Reads the rolling attack-score from Redis,
 * and automatically toggles Cloudflare's "Under Attack Mode"
 * on/off for the configured zones.
 *
 * Redis keys consumed / produced:
 *   cf:config           – JSON config (written by cf_routes.js)
 *   cf:state            – JSON    – { active, activated_at?, deactivated_at? }
 *   cf:cooldown_until   – Number  – epoch ms, don't deactivate before this
 *   cf:history          – List    – JSON activation/deactivation events (max 500)
 */

const crypto = require('crypto');

const ATTACK_SCORE_KEY = 'cf:attack:score';
const LEGACY_SCORE_KEY = 'cf:score';
const ATTACK_PEAK_KEY = 'cf:attack:peak';
const LEGACY_PEAK_KEY = 'cf:peak';
const ATTACK_LAST_SEEN_KEY = 'cf:attack:last_seen';
const LEGACY_LAST_ATTACK_AT_KEY = 'cf:last_attack_at';
const CF_BLACKLIST_RULEMAP_PREFIX = 'cf:blacklist:rulemap:';

async function readAttackTelemetry(redis) {
  const [scoreRaw, legacyScoreRaw, peakRaw, legacyPeakRaw, lastSeenRaw, legacyLastRaw] = await Promise.all([
    redis.get(ATTACK_SCORE_KEY),
    redis.get(LEGACY_SCORE_KEY),
    redis.get(ATTACK_PEAK_KEY),
    redis.get(LEGACY_PEAK_KEY),
    redis.get(ATTACK_LAST_SEEN_KEY),
    redis.get(LEGACY_LAST_ATTACK_AT_KEY)
  ]);

  const score = Number(scoreRaw);
  const legacyScore = Number(legacyScoreRaw);
  const peak = Number(peakRaw);
  const legacyPeak = Number(legacyPeakRaw);
  const lastSeen = Number(lastSeenRaw);
  const legacyLast = Number(legacyLastRaw);

  return {
    score: Number.isFinite(score) ? score : (Number.isFinite(legacyScore) ? legacyScore : 0),
    peak: Number.isFinite(peak) ? peak : (Number.isFinite(legacyPeak) ? legacyPeak : 0),
    last_attack_at: Number.isFinite(lastSeen) ? lastSeen * 1000 : (Number.isFinite(legacyLast) ? legacyLast : 0)
  };
}

async function syncAttackTelemetry(redis, telemetry, nowMs = Date.now()) {
  const score = Number.isFinite(Number(telemetry && telemetry.score)) ? Number(telemetry.score) : 0;
  const peak = Number.isFinite(Number(telemetry && telemetry.peak)) ? Number(telemetry.peak) : score;
  const lastAttackAt = Number.isFinite(Number(telemetry && telemetry.last_attack_at))
    ? Number(telemetry.last_attack_at)
    : nowMs;
  const lastSeenSeconds = Math.max(0, Math.floor(lastAttackAt / 1000));

  await Promise.all([
    redis.set(LEGACY_SCORE_KEY, String(score)),
    redis.set(LEGACY_PEAK_KEY, String(peak)),
    redis.set(LEGACY_LAST_ATTACK_AT_KEY, String(lastAttackAt)),
    redis.set(ATTACK_PEAK_KEY, String(peak)),
    redis.set(ATTACK_LAST_SEEN_KEY, String(lastSeenSeconds))
  ]);
}

// ── Token encryption (same pattern as llm_worker) ────────────────────────────
const ENC_ALGO = 'aes-256-gcm';

function encryptToken(plaintext, secret) {
  const key    = crypto.createHash('sha256').update(secret).digest();
  const iv     = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ENC_ALGO, key, iv);
  const enc    = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag    = cipher.getAuthTag();
  return `${iv.toString('hex')}:${tag.toString('hex')}:${enc.toString('hex')}`;
}

function decryptToken(ciphertext, secret) {
  try {
    const [ivHex, tagHex, encHex] = ciphertext.split(':');
    if (!ivHex || !tagHex || !encHex) return null;
    const key      = crypto.createHash('sha256').update(secret).digest();
    const iv       = Buffer.from(ivHex, 'hex');
    const tag      = Buffer.from(tagHex, 'hex');
    const enc      = Buffer.from(encHex, 'hex');
    const decipher = crypto.createDecipheriv(ENC_ALGO, key, iv);
    decipher.setAuthTag(tag);
    return decipher.update(enc) + decipher.final('utf8');
  } catch (_) {
    return null;
  }
}

// ── Cloudflare API client ────────────────────────────────────────────────────
class CfApiClient {
  /**
   * @param {string} token      - API Token (Bearer) or Global API Key
   * @param {number} timeoutMs
   * @param {string} authType   - 'token' (default) | 'global_key'
   * @param {string} authEmail  - required when authType === 'global_key'
   */
  constructor(token, timeoutMs = 10000, authType = 'token', authEmail = '') {
    this.token     = token;
    this.timeoutMs = timeoutMs;
    this.authType  = authType;
    this.authEmail = authEmail;
  }

  _request(method, path, body) {
    const https = require('https');
    return new Promise((resolve, reject) => {
      const bodyStr = body ? JSON.stringify(body) : '';
      let headers;
      if (this.authType === 'global_key') {
        headers = {
          'X-Auth-Email': this.authEmail,
          'X-Auth-Key':   this.token,
          'Content-Type': 'application/json',
        };
      } else {
        headers = {
          'Authorization': `Bearer ${this.token}`,
          'Content-Type':  'application/json',
        };
      }
      if (bodyStr) headers['Content-Length'] = Buffer.byteLength(bodyStr);

      const req = https.request({
        hostname: 'api.cloudflare.com',
        port:     443,
        path:     `/client/v4${path}`,
        method,
        headers,
      }, (res) => {
        let data = '';
        res.on('data', d => { data += d; });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            if (!parsed.success) {
              const msg = (parsed.errors || []).map(e => e.message).join('; ') || 'CF API error';
              return reject(new Error(msg));
            }
            resolve(parsed.result);
          } catch (e) {
            reject(new Error('CF API parse error: ' + data.slice(0, 200)));
          }
        });
      });

      req.on('error', reject);
      req.setTimeout(this.timeoutMs, () => {
        req.destroy(new Error('CF API timeout'));
      });
      if (bodyStr) req.write(bodyStr);
      req.end();
    });
  }

  /** List all zones accessible with the token */
  listZones() {
    return this._request('GET', '/zones?per_page=50&status=active');
  }

  /**
   * Set the security level for a zone.
   * level: 'under_attack' | 'high' | 'medium' | 'low' | 'essentially_off'
   */
  setSecurityLevel(zoneId, level) {
    return this._request('PATCH', `/zones/${zoneId}/settings/security_level`, { value: level });
  }

  /** Get current security level for a zone */
  getSecurityLevel(zoneId) {
    return this._request('GET', `/zones/${zoneId}/settings/security_level`);
  }

  listAccessRules(zoneId, page = 1, perPage = 100) {
    return this._request('GET', `/zones/${zoneId}/firewall/access_rules/rules?page=${page}&per_page=${perPage}`);
  }

  createAccessRule(zoneId, target, value, mode, notes = '') {
    return this._request('POST', `/zones/${zoneId}/firewall/access_rules/rules`, {
      mode,
      notes,
      configuration: {
        target,
        value
      }
    });
  }

  deleteAccessRule(zoneId, ruleId) {
    return this._request('DELETE', `/zones/${zoneId}/firewall/access_rules/rules/${ruleId}`);
  }
}

function normalizeBlacklistSyncMode(mode) {
  const value = String(mode || '').trim().toLowerCase();
  if (['block', 'challenge', 'js_challenge', 'managed_challenge'].includes(value)) {
    return value;
  }
  return 'block';
}

function getAccessRuleTarget(ip) {
  const value = String(ip || '').trim();
  if (!value) {
    return null;
  }
  if (value.includes('/')) {
    return 'ip_range';
  }
  if (value.includes(':')) {
    return 'ip6';
  }
  return 'ip';
}

function buildBlacklistRuleNotes(prefix, ip) {
  const notePrefix = String(prefix || 'SafeLine Risk IP').trim() || 'SafeLine Risk IP';
  return `${notePrefix}: ${ip}`;
}

async function scanRedisKeys(redisClient, pattern, count = 200, maxItems = 5000) {
  const keys = [];
  let cursor = '0';

  do {
    const result = await redisClient.scan(cursor, 'MATCH', pattern, 'COUNT', count);
    cursor = Array.isArray(result) ? String(result[0]) : '0';
    const batch = Array.isArray(result && result[1]) ? result[1] : [];
    for (const key of batch) {
      keys.push(key);
      if (keys.length >= maxItems) {
        return keys;
      }
    }
  } while (cursor !== '0');

  return keys;
}

async function syncBlockedIpToCloudflare(redisClient, jwtSecret, action, ip, options = {}) {
  const normalizedIp = String(ip || '').trim();
  if (!normalizedIp) {
    return { success: false, skipped: true, reason: 'invalid_ip' };
  }

  const cfgRaw = await redisClient.get('cf:config');
  if (!cfgRaw) {
    return { success: true, skipped: true, reason: 'cf_not_configured' };
  }

  const cfg = JSON.parse(cfgRaw);
  if (cfg.blacklist_sync_enabled === false) {
    return { success: true, skipped: true, reason: 'blacklist_sync_disabled' };
  }
  if (!cfg.api_token_enc || !Array.isArray(cfg.zone_ids) || cfg.zone_ids.length === 0) {
    return { success: true, skipped: true, reason: 'cf_credentials_incomplete' };
  }

  const token = decryptToken(cfg.api_token_enc, jwtSecret);
  if (!token) {
    return { success: false, skipped: true, reason: 'token_decrypt_failed' };
  }

  const mode = normalizeBlacklistSyncMode(options.mode || cfg.blacklist_sync_mode);
  const notes = buildBlacklistRuleNotes(cfg.blacklist_sync_notes_prefix, normalizedIp);
  const target = getAccessRuleTarget(normalizedIp);
  if (!target) {
    return { success: false, skipped: true, reason: 'unsupported_target' };
  }

  const client = new CfApiClient(
    token,
    cfg.timeout_ms || 10000,
    cfg.auth_type === 'global_key' ? 'global_key' : 'token',
    cfg.auth_email || ''
  );

  const zoneIds = Array.from(new Set((cfg.zone_ids || []).map((zoneId) => String(zoneId || '').trim()).filter(Boolean)));
  const details = [];

  for (const zoneId of zoneIds) {
    const mappingKey = `${CF_BLACKLIST_RULEMAP_PREFIX}${zoneId}`;
    const existingRuleId = await redisClient.hget(mappingKey, normalizedIp);

    if (action === 'add') {
      if (existingRuleId) {
        details.push({ zone: zoneId, ip: normalizedIp, action, changed: false, rule_id: existingRuleId });
        continue;
      }

      try {
        const created = await client.createAccessRule(zoneId, target, normalizedIp, mode, notes);
        const ruleId = created && created.id ? created.id : null;
        if (ruleId) {
          await redisClient.hset(mappingKey, normalizedIp, ruleId);
        }
        details.push({ zone: zoneId, ip: normalizedIp, action, changed: true, rule_id: ruleId, mode });
      } catch (error) {
        details.push({ zone: zoneId, ip: normalizedIp, action, changed: false, error: error.message || String(error) });
      }
      continue;
    }

    if (!existingRuleId) {
      details.push({ zone: zoneId, ip: normalizedIp, action, changed: false });
      continue;
    }

    try {
      await client.deleteAccessRule(zoneId, existingRuleId);
    } catch (error) {
      details.push({ zone: zoneId, ip: normalizedIp, action, changed: false, rule_id: existingRuleId, error: error.message || String(error) });
      continue;
    }

    await redisClient.hdel(mappingKey, normalizedIp);
    details.push({ zone: zoneId, ip: normalizedIp, action, changed: true, rule_id: existingRuleId });
  }

  return {
    success: details.every((item) => !item.error),
    skipped: false,
    details
  };
}

async function syncRiskBlacklistToCloudflare(redisClient, jwtSecret, cfg, client) {
  if (!cfg || cfg.blacklist_sync_enabled === false) {
    return { success: true, skipped: true, reason: 'blacklist_sync_disabled' };
  }

  const zoneIds = Array.from(new Set((cfg.zone_ids || []).map((zoneId) => String(zoneId || '').trim()).filter(Boolean)));
  if (zoneIds.length === 0) {
    return { success: true, skipped: true, reason: 'no_zones_configured' };
  }

  const blacklistKeys = await scanRedisKeys(redisClient, 'safeline:blacklist:*', 200, Number(cfg.blacklist_sync_max_entries) || 5000);
  const desiredIps = blacklistKeys
    .filter((key) => typeof key === 'string' && key.startsWith('safeline:blacklist:'))
    .map((key) => key.slice('safeline:blacklist:'.length))
    .filter(Boolean);
  const desiredSet = new Set(desiredIps);

  const mode = normalizeBlacklistSyncMode(cfg.blacklist_sync_mode);
  const notesPrefix = cfg.blacklist_sync_notes_prefix;
  const result = {
    success: true,
    skipped: false,
    synced: desiredIps.length,
    created: 0,
    removed: 0,
    errors: []
  };

  for (const zoneId of zoneIds) {
    const mappingKey = `${CF_BLACKLIST_RULEMAP_PREFIX}${zoneId}`;
    const currentMap = await redisClient.hgetall(mappingKey) || {};

    for (const ip of desiredSet) {
      if (currentMap[ip]) {
        continue;
      }

      const target = getAccessRuleTarget(ip);
      if (!target) {
        continue;
      }

      try {
        const created = await client.createAccessRule(zoneId, target, ip, mode, buildBlacklistRuleNotes(notesPrefix, ip));
        const ruleId = created && created.id ? created.id : null;
        if (ruleId) {
          await redisClient.hset(mappingKey, ip, ruleId);
        }
        result.created += 1;
      } catch (error) {
        result.success = false;
        result.errors.push({ zone: zoneId, ip, action: 'add', error: error.message || String(error) });
      }
    }

    for (const [ip, ruleId] of Object.entries(currentMap)) {
      if (desiredSet.has(ip)) {
        continue;
      }

      try {
        await client.deleteAccessRule(zoneId, ruleId);
      } catch (error) {
        result.success = false;
        result.errors.push({ zone: zoneId, ip, action: 'remove', error: error.message || String(error) });
        continue;
      }

      await redisClient.hdel(mappingKey, ip);
      result.removed += 1;
    }
  }

  return result;
}

async function applySecurityLevelToZones(client, zoneIds, targetLevel, options = {}) {
  const normalizedZoneIds = Array.from(new Set(
    (Array.isArray(zoneIds) ? zoneIds : [])
      .map((zoneId) => String(zoneId || '').trim())
      .filter(Boolean)
  ));

  const updatedZones = [];
  const errors = [];

  for (const zoneId of normalizedZoneIds) {
    try {
      const current = await client.getSecurityLevel(zoneId);
      const previousLevel = current && typeof current.value === 'string'
        ? current.value
        : null;

      if (previousLevel === targetLevel) {
        updatedZones.push({
          zone: zoneId,
          previous_level: previousLevel,
          target_level: targetLevel,
          changed: false
        });
        continue;
      }

      await client.setSecurityLevel(zoneId, targetLevel);
      updatedZones.push({
        zone: zoneId,
        previous_level: previousLevel,
        target_level: targetLevel,
        changed: true
      });
    } catch (error) {
      errors.push({
        zone: zoneId,
        error: error.message || String(error)
      });
    }
  }

  const rollbackErrors = [];
  if (errors.length > 0 && options.rollbackOnFailure !== false) {
    for (const zoneResult of updatedZones.filter((item) => item.changed && item.previous_level).reverse()) {
      try {
        await client.setSecurityLevel(zoneResult.zone, zoneResult.previous_level);
        zoneResult.rolled_back = true;
      } catch (rollbackError) {
        rollbackErrors.push({
          zone: zoneResult.zone,
          rollback_target: zoneResult.previous_level,
          error: rollbackError.message || String(rollbackError)
        });
      }
    }
  }

  return {
    success: errors.length === 0 && rollbackErrors.length === 0,
    target_level: targetLevel,
    updated_zones: updatedZones,
    errors,
    rollback_errors: rollbackErrors
  };
}

// ── Worker ───────────────────────────────────────────────────────────────────
class CfShieldWorker {
  constructor(redis, jwtSecret, intervalMs = 15000) {
    this.redis       = redis;
    this.jwtSecret   = jwtSecret;
    this.intervalMs  = intervalMs;
    this._timer      = null;
    this._running    = false;
  }

  start() {
    if (this._timer) return;
    console.log('[CF] Shield worker started (interval:', this.intervalMs, 'ms)');
    this._tick();
    this._timer = setInterval(() => this._tick(), this.intervalMs);
  }

  stop() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
    console.log('[CF] Shield worker stopped');
  }

  async _tick() {
    if (this._running) return; // skip if previous tick still in progress
    this._running = true;
    try {
      await this._evaluate();
    } catch (e) {
      console.error('[CF] Tick error:', e.message);
    } finally {
      this._running = false;
    }
  }

  async _evaluate() {
    const redis = this.redis;

    // Load config
    const cfgRaw = await redis.get('cf:config');
    if (!cfgRaw) return;
    const cfg = JSON.parse(cfgRaw);
    if (!cfg.api_token_enc || !cfg.zone_ids || cfg.zone_ids.length === 0) return;

    const token = decryptToken(cfg.api_token_enc, this.jwtSecret);
    if (!token) {
      console.warn('[CF] Failed to decrypt Cloudflare credentials; re-save API key in the control panel');
      return;
    }

    const activateThreshold   = Number(cfg.activate_threshold)   || 50;
    const deactivateThreshold = Number(cfg.deactivate_threshold) || 10;
    const cooldownMs          = (Number(cfg.cooldown_s)          || 300) * 1000;
    const normalLevel         = cfg.normal_security_level        || 'medium';

    // Read current score
    const telemetry = await readAttackTelemetry(redis);
    const score = telemetry.score;
    const now   = Date.now();

    // Update peak
    const peak = Math.max(telemetry.peak, score);
    if (peak !== telemetry.peak) {
      await syncAttackTelemetry(redis, { score, peak, last_attack_at: telemetry.last_attack_at || now }, now);
    }

    // Read current state
    const stateRaw   = await redis.get('cf:state');
    const state      = stateRaw ? JSON.parse(stateRaw) : { active: false };
    const cooldownTs = Number(await redis.get('cf:cooldown_until')) || 0;

    const client = new CfApiClient(
      token,
      cfg.timeout_ms || 10000,
      cfg.auth_type === 'global_key' ? 'global_key' : 'token',
      cfg.auth_email || ''
    );

    try {
      await syncRiskBlacklistToCloudflare(redis, this.jwtSecret, cfg, client);
    } catch (error) {
      console.error('[CF] Risk IP sync error:', error.message || error);
    }

    if (!cfg.enabled) return;

    if (!state.active && score >= activateThreshold) {
      // ── ACTIVATE ────────────────────────────────────────────────────────
      console.log(`[CF] Score ${score} >= threshold ${activateThreshold} — activating Under Attack Mode`);
      const applyResult = await applySecurityLevelToZones(client, cfg.zone_ids, 'under_attack');
      applyResult.errors.forEach((item) => {
        console.error(`[CF] Zone ${item.zone} activate error:`, item.error);
      });
      applyResult.updated_zones
        .filter((item) => item.changed)
        .forEach((item) => console.log(`[CF] Zone ${item.zone} → under_attack`));

      if (!applyResult.success) {
        const failureEntry = {
          type: 'activate_failed',
          at: now,
          score,
          reason: 'auto',
          errors: applyResult.errors,
          rollback_errors: applyResult.rollback_errors,
          updated_zones: applyResult.updated_zones
        };
        await redis.lpush('cf:history', JSON.stringify(failureEntry));
        await redis.ltrim('cf:history', 0, 499);
        return;
      }

      const newState = { active: true, activated_at: now, score_at_activation: score };
      await redis.set('cf:state', JSON.stringify(newState));
      await syncAttackTelemetry(redis, { score, peak: Math.max(peak, score), last_attack_at: now }, now);

      const entry = {
        type: 'activate',
        at: now,
        score,
        reason: 'auto',
        errors: [],
        updated_zones: applyResult.updated_zones
      };
      await redis.lpush('cf:history', JSON.stringify(entry));
      await redis.ltrim('cf:history', 0, 499);

    } else if (state.active && score <= deactivateThreshold && now > cooldownTs) {
      // ── DEACTIVATE ──────────────────────────────────────────────────────
      console.log(`[CF] Score ${score} <= threshold ${deactivateThreshold} — deactivating (back to ${normalLevel})`);
      const applyResult = await applySecurityLevelToZones(client, cfg.zone_ids, normalLevel);
      applyResult.errors.forEach((item) => {
        console.error(`[CF] Zone ${item.zone} deactivate error:`, item.error);
      });
      applyResult.updated_zones
        .filter((item) => item.changed)
        .forEach((item) => console.log(`[CF] Zone ${item.zone} → ${normalLevel}`));

      if (!applyResult.success) {
        const failureEntry = {
          type: 'deactivate_failed',
          at: now,
          score,
          reason: 'auto',
          errors: applyResult.errors,
          rollback_errors: applyResult.rollback_errors,
          updated_zones: applyResult.updated_zones
        };
        await redis.lpush('cf:history', JSON.stringify(failureEntry));
        await redis.ltrim('cf:history', 0, 499);
        return;
      }

      const newState = { active: false, deactivated_at: now, score_at_deactivation: score };
      await redis.set('cf:state', JSON.stringify(newState));
      // Set cooldown to prevent immediate re-activation
      await redis.set('cf:cooldown_until', String(now + cooldownMs));

      const entry = {
        type: 'deactivate',
        at: now,
        score,
        reason: 'auto',
        errors: [],
        updated_zones: applyResult.updated_zones
      };
      await redis.lpush('cf:history', JSON.stringify(entry));
      await redis.ltrim('cf:history', 0, 499);
    }
    // Otherwise: no state change needed
  }
}

module.exports = {
  encryptToken,
  decryptToken,
  CfApiClient,
  applySecurityLevelToZones,
  syncBlockedIpToCloudflare,
  syncRiskBlacklistToCloudflare,
  CfShieldWorker,
  readAttackTelemetry,
  syncAttackTelemetry,
  ATTACK_SCORE_KEY,
  LEGACY_SCORE_KEY,
  ATTACK_PEAK_KEY,
  LEGACY_PEAK_KEY,
  ATTACK_LAST_SEEN_KEY,
  LEGACY_LAST_ATTACK_AT_KEY
};
