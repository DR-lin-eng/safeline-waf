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
  applySecurityLevelToZones,
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

  function sanitizeZoneIds(zoneIds, fallback = []) {
    const source = Array.isArray(zoneIds) ? zoneIds : fallback;
    return Array.from(new Set(
      source
        .map((value) => String(value || '').trim())
        .filter(Boolean)
    ));
  }

  async function readStoredConfig() {
    const raw = await redis.get('cf:config');
    return raw ? JSON.parse(raw) : {};
  }

  function buildConfigCandidate(input = {}, existing = {}) {
    const draft = input && typeof input === 'object' ? input : {};
    let api_token_enc = existing.api_token_enc || '';

    if (draft.api_token && String(draft.api_token).trim() && !String(draft.api_token).startsWith('••')) {
      api_token_enc = encryptToken(String(draft.api_token).trim(), jwtSecret);
    }

    const resolvedAuthType = draft.auth_type !== undefined
      ? (draft.auth_type === 'global_key' ? 'global_key' : 'token')
      : (existing.auth_type === 'global_key' ? 'global_key' : 'token');
    const resolvedAuthEmail = resolvedAuthType === 'global_key'
      ? String(draft.auth_email !== undefined ? draft.auth_email : (existing.auth_email || '')).trim()
      : '';

    return {
      api_token_enc,
      auth_type: resolvedAuthType,
      auth_email: resolvedAuthEmail,
      zone_ids: sanitizeZoneIds(draft.zone_ids, existing.zone_ids || []),
      enabled: draft.enabled !== undefined ? !!draft.enabled : !!existing.enabled,
      activate_threshold: Number(draft.activate_threshold) || existing.activate_threshold || 50,
      deactivate_threshold: Number(draft.deactivate_threshold) || existing.deactivate_threshold || 10,
      cooldown_s: Number(draft.cooldown_s) || existing.cooldown_s || 300,
      normal_security_level: draft.normal_security_level || existing.normal_security_level || 'medium',
      timeout_ms: Number(draft.timeout_ms) || existing.timeout_ms || 10000
    };
  }

  function maskConfig(cfg) {
    const out = { ...cfg };
    if (out.api_token_enc) {
      out.api_token_masked = '••••••••' + out.api_token_enc.slice(-4);
      delete out.api_token_enc;
    }
    return out;
  }

  function resolveClientFromConfig(cfg) {
    if (!cfg || !cfg.api_token_enc) {
      throw new Error('API token not configured');
    }

    const token = decryptToken(cfg.api_token_enc, jwtSecret);
    if (!token) {
      throw new Error('Failed to decrypt API token');
    }

    if (cfg.auth_type === 'global_key' && !String(cfg.auth_email || '').trim()) {
      throw new Error('auth_email is required when auth_type is global_key');
    }

    return new CfApiClient(token, cfg.timeout_ms || 10000, cfg.auth_type, cfg.auth_email);
  }

  // ── GET /cf/config ─────────────────────────────────────────────────────────
  router.get('/cf/config', async (_req, res) => {
    try {
      const cfg = await readStoredConfig();
      return ok(res, maskConfig(cfg));
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

      const existing = await readStoredConfig();
      const cfg = buildConfigCandidate({
        api_token,
        auth_type,
        auth_email,
        zone_ids,
        enabled,
        activate_threshold,
        deactivate_threshold,
        cooldown_s,
        normal_security_level,
        timeout_ms
      }, existing);

      if (cfg.auth_type === 'global_key' && !cfg.auth_email) {
        return fail(res, 400, 'auth_email is required when auth_type is global_key');
      }

      await redis.set('cf:config', JSON.stringify(cfg));
      return ok(res, maskConfig(cfg));
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
  async function handleListZones(input, res) {
    try {
      const cfg = buildConfigCandidate(input, await readStoredConfig());
      const client = resolveClientFromConfig(cfg);
      const zones = await client.listZones();
      return ok(res, zones);
    } catch (e) {
      return fail(res, 500, e.message);
    }
  }

  router.get('/cf/zones', async (_req, res) => handleListZones({}, res));
  router.post('/cf/zones', async (req, res) => handleListZones(req.body || {}, res));

  // ── POST /cf/test ─────────────────────���────────────────────────────────────
  router.post('/cf/test', async (req, res) => {
    try {
      const cfg = buildConfigCandidate(req.body || {}, await readStoredConfig());
      const client = resolveClientFromConfig(cfg);
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
      const cfg = await readStoredConfig();
      if (!cfg.api_token_enc) return fail(res, 400, 'API token not configured');
      if (!cfg.zone_ids || cfg.zone_ids.length === 0) return fail(res, 400, 'No Zone IDs configured');

      const client = resolveClientFromConfig(cfg);
      const applyResult = await applySecurityLevelToZones(client, cfg.zone_ids, 'under_attack');

      const now = Date.now();
      const entry = {
        type: applyResult.success ? 'activate' : 'activate_failed',
        at: now,
        reason: 'manual',
        errors: applyResult.errors,
        rollback_errors: applyResult.rollback_errors,
        updated_zones: applyResult.updated_zones
      };
      await redis.lpush('cf:history', JSON.stringify(entry));
      await redis.ltrim('cf:history', 0, 499);

      if (!applyResult.success) {
        return res.status(502).json({
          code: 502,
          message: 'Failed to enable Cloudflare shield for all zones',
          details: applyResult
        });
      }

      const state = { active: true, activated_at: now, manual: true };
      await redis.set('cf:state', JSON.stringify(state));
      return ok(res, { activated: true, updated_zones: applyResult.updated_zones });
    } catch (e) {
      return fail(res, 500, e.message);
    }
  });

  // ── POST /cf/shield/disable ────────────────────────────────────────────────
  router.post('/cf/shield/disable', async (_req, res) => {
    try {
      const cfg = await readStoredConfig();
      if (!cfg.api_token_enc) return fail(res, 400, 'API token not configured');
      if (!cfg.zone_ids || cfg.zone_ids.length === 0) return fail(res, 400, 'No Zone IDs configured');

      const level = cfg.normal_security_level || 'medium';
      const client = resolveClientFromConfig(cfg);
      const applyResult = await applySecurityLevelToZones(client, cfg.zone_ids, level);

      const now = Date.now();
      const entry = {
        type: applyResult.success ? 'deactivate' : 'deactivate_failed',
        at: now,
        reason: 'manual',
        errors: applyResult.errors,
        rollback_errors: applyResult.rollback_errors,
        updated_zones: applyResult.updated_zones
      };
      await redis.lpush('cf:history', JSON.stringify(entry));
      await redis.ltrim('cf:history', 0, 499);

      if (!applyResult.success) {
        return res.status(502).json({
          code: 502,
          message: 'Failed to disable Cloudflare shield for all zones',
          details: applyResult
        });
      }

      const state = { active: false, deactivated_at: now, manual: true };
      await redis.set('cf:state', JSON.stringify(state));
      await redis.set('cf:cooldown_until', String(now + (cfg.cooldown_s || 300) * 1000));
      return ok(res, { deactivated: true, updated_zones: applyResult.updated_zones });
    } catch (e) {
      return fail(res, 500, e.message);
    }
  });
};
