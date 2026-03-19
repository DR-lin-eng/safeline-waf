'use strict';
/**
 * Cloudflare Five-Second Shield API Routes
 * Mounted at /api/cf/*
 *
 * Routes:
 *   GET  /cf/config           – get current config (token masked)
 *   PUT  /cf/config           – save config
 *   GET  /cf/status           – get live score + shield state
 *   GET  /cf/history          – activation history  ?limit=N
 *   DELETE /cf/history        – clear history & reset peak
 *   GET  /cf/zones            – list zones from CF account
 *   POST /cf/test             – test API token connectivity
 *   POST /cf/shield/enable    – manually activate Under Attack Mode
 *   POST /cf/shield/disable   – manually deactivate Under Attack Mode
 */

const {
  encryptToken,
  decryptToken,
  CfApiClient,
  readAttackTelemetry,
  ATTACK_PEAK_KEY,
  LEGACY_PEAK_KEY,
  ATTACK_LAST_SEEN_KEY,
  LEGACY_LAST_ATTACK_AT_KEY
} = require('./cf_worker');

module.exports = function mountCfRoutes(router, redis, jwtSecret) {

  function ok(res, data) {
    return res.json({ success: true, data });
  }
  function fail(res, status, msg) {
    return res.status(status).json({ code: status, message: msg, data: null });
  }

  // ── GET /cf/config ─────────────────────────────────────────────────────────
  router.get('/cf/config', async (_req, res) => {
    try {
      const raw = await redis.get('cf:config');
      if (!raw) return ok(res, {});
      const cfg = JSON.parse(raw);
      const out = { ...cfg };
      if (out.api_token_enc) {
        out.api_token_masked = '••••••••' + out.api_token_enc.slice(-4);
        delete out.api_token_enc;
      }
      return ok(res, out);
    } catch (e) {
      return fail(res, 500, e.message);
    }
  });

  // ── PUT /cf/config ─────────────────────────────────────────────────────────
  router.put('/cf/config', async (req, res) => {
    try {
      const {
        api_token, auth_type, auth_email, zone_ids, enabled,
        activate_threshold, deactivate_threshold,
        cooldown_s, normal_security_level, timeout_ms,
      } = req.body;

      const existingRaw = await redis.get('cf:config');
      const existing    = existingRaw ? JSON.parse(existingRaw) : {};

      let api_token_enc = existing.api_token_enc || '';
      if (api_token && api_token.trim() && !api_token.startsWith('••')) {
        api_token_enc = encryptToken(api_token.trim(), jwtSecret);
      }

      const resolvedAuthType = auth_type === 'global_key' ? 'global_key' : 'token';

      const cfg = {
        api_token_enc,
        auth_type:              resolvedAuthType,
        auth_email:             resolvedAuthType === 'global_key' ? String(auth_email || existing.auth_email || '').trim() : '',
        zone_ids:               Array.isArray(zone_ids) ? zone_ids.filter(Boolean) : (existing.zone_ids || []),
        enabled:                enabled !== undefined ? !!enabled : !!existing.enabled,
        activate_threshold:     Number(activate_threshold)   || existing.activate_threshold   || 50,
        deactivate_threshold:   Number(deactivate_threshold) || existing.deactivate_threshold || 10,
        cooldown_s:             Number(cooldown_s)           || existing.cooldown_s           || 300,
        normal_security_level:  normal_security_level        || existing.normal_security_level || 'medium',
        timeout_ms:             Number(timeout_ms)           || existing.timeout_ms           || 10000,
      };

      await redis.set('cf:config', JSON.stringify(cfg));

      // Return masked copy
      const out = { ...cfg };
      if (out.api_token_enc) {
        out.api_token_masked = '••••••••' + out.api_token_enc.slice(-4);
        delete out.api_token_enc;
      }
      return ok(res, out);
    } catch (e) {
      return fail(res, 500, e.message);
    }
  });

  // ── GET /cf/status ─────────────────────────────────────────────────────────
  router.get('/cf/status', async (_req, res) => {
    try {
      const [telemetry, stateRaw] = await Promise.all([
        readAttackTelemetry(redis),
        redis.get('cf:state')
      ]);
      return ok(res, {
        score: telemetry.score,
        peak: telemetry.peak,
        last_attack_at: telemetry.last_attack_at,
        state: stateRaw ? JSON.parse(stateRaw) : { active: false },
      });
    } catch (e) {
      return fail(res, 500, e.message);
    }
  });

  // ── GET /cf/history ────────────────────────────────────────────────────────
  router.get('/cf/history', async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
      const items = await redis.lrange('cf:history', 0, limit - 1);
      const total = await redis.llen('cf:history');
      return ok(res, {
        items: items.map(i => JSON.parse(i)).reverse(),
        total,
      });
    } catch (e) {
      return fail(res, 500, e.message);
    }
  });

  // ── DELETE /cf/history ─────────────────────────────────────────────────────
  router.delete('/cf/history', async (_req, res) => {
    try {
      await Promise.all([
        redis.del('cf:history'),
        redis.del(ATTACK_PEAK_KEY),
        redis.del(LEGACY_PEAK_KEY),
        redis.del(ATTACK_LAST_SEEN_KEY),
        redis.del(LEGACY_LAST_ATTACK_AT_KEY),
      ]);
      return ok(res, { cleared: true });
    } catch (e) {
      return fail(res, 500, e.message);
    }
  });

  // ── GET /cf/zones ──────────────────────────────────────────────────────────
  router.get('/cf/zones', async (_req, res) => {
    try {
      const raw = await redis.get('cf:config');
      if (!raw) return fail(res, 400, 'CF config not set');
      const cfg = JSON.parse(raw);
      if (!cfg.api_token_enc) return fail(res, 400, 'API token not configured');
      const token = decryptToken(cfg.api_token_enc, jwtSecret);
      const client = new CfApiClient(token, cfg.timeout_ms || 10000, cfg.auth_type, cfg.auth_email);
      const zones  = await client.listZones();
      return ok(res, zones);
    } catch (e) {
      return fail(res, 500, e.message);
    }
  });

  // ── POST /cf/test ─────────────────────���────────────────────────────────────
  router.post('/cf/test', async (_req, res) => {
    try {
      const raw = await redis.get('cf:config');
      if (!raw) return fail(res, 400, 'CF config not set');
      const cfg = JSON.parse(raw);
      if (!cfg.api_token_enc) return fail(res, 400, 'API token not configured');
      const token  = decryptToken(cfg.api_token_enc, jwtSecret);
      const client = new CfApiClient(token, cfg.timeout_ms || 10000, cfg.auth_type, cfg.auth_email);
      try {
        const zones = await client.listZones();
        return ok(res, { connected: true, zones_found: zones.length });
      } catch (e) {
        return ok(res, { connected: false, error: e.message });
      }
    } catch (e) {
      return fail(res, 500, e.message);
    }
  });

  // ── POST /cf/shield/enable ────────────────────────────────────────────��────
  router.post('/cf/shield/enable', async (_req, res) => {
    try {
      const raw = await redis.get('cf:config');
      if (!raw) return fail(res, 400, 'CF config not set');
      const cfg = JSON.parse(raw);
      if (!cfg.api_token_enc) return fail(res, 400, 'API token not configured');
      if (!cfg.zone_ids || cfg.zone_ids.length === 0) return fail(res, 400, 'No Zone IDs configured');

      const token  = decryptToken(cfg.api_token_enc, jwtSecret);
      const client = new CfApiClient(token, cfg.timeout_ms || 10000, cfg.auth_type, cfg.auth_email);
      const errors = [];

      for (const zoneId of cfg.zone_ids) {
        try {
          await client.setSecurityLevel(zoneId, 'under_attack');
        } catch (e) {
          errors.push({ zone: zoneId, error: e.message });
        }
      }

      const now = Date.now();
      const state = { active: true, activated_at: now, manual: true };
      await redis.set('cf:state', JSON.stringify(state));

      // Record history
      const entry = { type: 'activate', at: now, reason: 'manual', errors };
      await redis.lpush('cf:history', JSON.stringify(entry));
      await redis.ltrim('cf:history', 0, 499);

      return ok(res, { activated: true, errors });
    } catch (e) {
      return fail(res, 500, e.message);
    }
  });

  // ── POST /cf/shield/disable ────────────────────────────────────────────────
  router.post('/cf/shield/disable', async (_req, res) => {
    try {
      const raw = await redis.get('cf:config');
      if (!raw) return fail(res, 400, 'CF config not set');
      const cfg = JSON.parse(raw);
      if (!cfg.api_token_enc) return fail(res, 400, 'API token not configured');
      if (!cfg.zone_ids || cfg.zone_ids.length === 0) return fail(res, 400, 'No Zone IDs configured');

      const token  = decryptToken(cfg.api_token_enc, jwtSecret);
      const client = new CfApiClient(token, cfg.timeout_ms || 10000, cfg.auth_type, cfg.auth_email);
      const level  = cfg.normal_security_level || 'medium';
      const errors = [];

      for (const zoneId of cfg.zone_ids) {
        try {
          await client.setSecurityLevel(zoneId, level);
        } catch (e) {
          errors.push({ zone: zoneId, error: e.message });
        }
      }

      const now = Date.now();
      const state = { active: false, deactivated_at: now, manual: true };
      await redis.set('cf:state', JSON.stringify(state));
      // Reset cooldown so worker doesn't re-trigger immediately
      await redis.set('cf:cooldown_until', String(now + (cfg.cooldown_s || 300) * 1000));

      const entry = { type: 'deactivate', at: now, reason: 'manual', errors };
      await redis.lpush('cf:history', JSON.stringify(entry));
      await redis.ltrim('cf:history', 0, 499);

      return ok(res, { deactivated: true, errors });
    } catch (e) {
      return fail(res, 500, e.message);
    }
  });
};
