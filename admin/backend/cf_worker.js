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
  const [ivHex, tagHex, encHex] = ciphertext.split(':');
  if (!ivHex || !tagHex || !encHex) return null;
  const key      = crypto.createHash('sha256').update(secret).digest();
  const iv       = Buffer.from(ivHex, 'hex');
  const tag      = Buffer.from(tagHex, 'hex');
  const enc      = Buffer.from(encHex, 'hex');
  const decipher = crypto.createDecipheriv(ENC_ALGO, key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(enc) + decipher.final('utf8');
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
    if (!cfg.enabled) return;
    if (!cfg.api_token_enc || !cfg.zone_ids || cfg.zone_ids.length === 0) return;

    const token = decryptToken(cfg.api_token_enc, this.jwtSecret);
    if (!token) return;

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

    if (!state.active && score >= activateThreshold) {
      // ── ACTIVATE ────────────────────────────────────────────────────────
      console.log(`[CF] Score ${score} >= threshold ${activateThreshold} — activating Under Attack Mode`);
      const errors = [];
      for (const zoneId of cfg.zone_ids) {
        try {
          await client.setSecurityLevel(zoneId, 'under_attack');
          console.log(`[CF] Zone ${zoneId} → under_attack`);
        } catch (e) {
          console.error(`[CF] Zone ${zoneId} activate error:`, e.message);
          errors.push({ zone: zoneId, error: e.message });
        }
      }

      const newState = { active: true, activated_at: now, score_at_activation: score };
      await redis.set('cf:state', JSON.stringify(newState));
      await syncAttackTelemetry(redis, { score, peak: Math.max(peak, score), last_attack_at: now }, now);

      const entry = { type: 'activate', at: now, score, reason: 'auto', errors };
      await redis.lpush('cf:history', JSON.stringify(entry));
      await redis.ltrim('cf:history', 0, 499);

    } else if (state.active && score <= deactivateThreshold && now > cooldownTs) {
      // ── DEACTIVATE ──────────────────────────────────────────────────────
      console.log(`[CF] Score ${score} <= threshold ${deactivateThreshold} — deactivating (back to ${normalLevel})`);
      const errors = [];
      for (const zoneId of cfg.zone_ids) {
        try {
          await client.setSecurityLevel(zoneId, normalLevel);
          console.log(`[CF] Zone ${zoneId} → ${normalLevel}`);
        } catch (e) {
          console.error(`[CF] Zone ${zoneId} deactivate error:`, e.message);
          errors.push({ zone: zoneId, error: e.message });
        }
      }

      const newState = { active: false, deactivated_at: now, score_at_deactivation: score };
      await redis.set('cf:state', JSON.stringify(newState));
      // Set cooldown to prevent immediate re-activation
      await redis.set('cf:cooldown_until', String(now + cooldownMs));

      const entry = { type: 'deactivate', at: now, score, reason: 'auto', errors };
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
