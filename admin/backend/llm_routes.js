'use strict';
/**
 * LLM Audit API Routes — mounted at /api/llm/*
 */
const { encryptApiKey, decryptApiKey } = require('./llm_worker');

module.exports = function mountLlmRoutes(router, redis, jwtSecret) {

  function ok(res, data) {
    return res.json({ success: true, data });
  }
  function err(res, status, msg) {
    return res.status(status).json({ code: status, message: msg, data: null });
  }

  // ── GET /api/llm/config ─────────────────────────────────────────────────
  router.get('/llm/config', async (_req, res) => {
    try {
      const raw = await redis.get('llm:config');
      if (!raw) return ok(res, null);
      const cfg = JSON.parse(raw);
      // Never expose the actual key
      if (cfg.api_key_enc) {
        cfg.api_key_masked = '••••••••' + cfg.api_key_enc.slice(-4);
        delete cfg.api_key_enc;
      }
      ok(res, cfg);
    } catch (e) {
      err(res, 500, e.message);
    }
  });

  // ── PUT /api/llm/config ─────────────────────────────────────────────────
  // Body fields: provider, api_endpoint, model, api_key (plain, will be encrypted),
  //              enabled, autoban_min_confidence, batch_size, call_delay_ms,
  //              verdict_cache_ttl_s, timeout_ms, audit_triggers[]
  router.put('/llm/config', async (req, res) => {
    try {
      const {
        provider, api_endpoint, model, api_key,
        enabled, autoban_min_confidence, batch_size,
        call_delay_ms, verdict_cache_ttl_s, timeout_ms,
        audit_triggers,
      } = req.body;

      // Load existing config to preserve encrypted key if no new key provided
      const existingRaw = await redis.get('llm:config');
      const existing    = existingRaw ? JSON.parse(existingRaw) : {};

      let api_key_enc = existing.api_key_enc || '';
      if (api_key && api_key.trim() && !api_key.startsWith('••')) {
        api_key_enc = encryptApiKey(api_key.trim(), jwtSecret);
      }

      const cfg = {
        provider:               provider    || existing.provider    || 'openai',
        api_endpoint:           api_endpoint || existing.api_endpoint || 'https://api.openai.com/v1',
        model:                  model       || existing.model       || 'gpt-4o-mini',
        api_key_enc,
        enabled:                enabled !== undefined ? !!enabled : !!existing.enabled,
        autoban_min_confidence: parseFloat(autoban_min_confidence ?? existing.autoban_min_confidence ?? 0.75),
        batch_size:             parseInt(batch_size ?? existing.batch_size ?? 3, 10),
        call_delay_ms:          parseInt(call_delay_ms ?? existing.call_delay_ms ?? 200, 10),
        verdict_cache_ttl_s:    parseInt(verdict_cache_ttl_s ?? existing.verdict_cache_ttl_s ?? 600, 10),
        timeout_ms:             parseInt(timeout_ms ?? existing.timeout_ms ?? 15000, 10),
        audit_triggers:         Array.isArray(audit_triggers) ? audit_triggers
                                  : (existing.audit_triggers || ['ml_gray_zone','payload_suspicious','high_block_rate']),
        updated_at:             Date.now(),
      };

      await redis.set('llm:config', JSON.stringify(cfg));

      // Reflect enabled state to shared dict key for Lua workers
      await redis.set('llm:enabled', cfg.enabled ? 'true' : 'false');

      // Mask key before returning
      const out = { ...cfg, api_key_masked: '••••••••' + api_key_enc.slice(-4) };
      delete out.api_key_enc;
      ok(res, out);
    } catch (e) {
      err(res, 500, e.message);
    }
  });

  // ── GET /api/llm/stats ──────────────────────────────────────────────────
  router.get('/llm/stats', async (_req, res) => {
    try {
      const [total, autobanned, queueLen] = await Promise.all([
        redis.get('llm:stats:total'),
        redis.get('llm:stats:autobanned'),
        redis.llen('llm:audit:queue'),
      ]);

      const riskKeys    = ['critical','high','medium','low','benign'];
      const riskCounts  = {};
      for (const k of riskKeys) {
        riskCounts[k] = parseInt(await redis.get(`llm:stats:risk:${k}`) || '0', 10);
      }

      ok(res, {
        total_analysed:  parseInt(total     || '0', 10),
        total_autobanned: parseInt(autobanned || '0', 10),
        queue_length:    parseInt(queueLen   || '0', 10),
        by_risk:         riskCounts,
      });
    } catch (e) {
      err(res, 500, e.message);
    }
  });

  // ── GET /api/llm/verdicts ───────────────────────────────────────────────
  router.get('/llm/verdicts', async (req, res) => {
    try {
      const limit  = Math.min(parseInt(req.query.limit  || '50',  10), 500);
      const offset = Math.max(parseInt(req.query.offset || '0',   10), 0);
      const filter = req.query.risk;  // optional: critical|high|medium|low|benign

      const raw = await redis.lrange('llm:verdicts', offset, offset + limit - 1);
      let items = raw.map(r => { try { return JSON.parse(r); } catch { return null; } })
                     .filter(Boolean);

      if (filter && filter !== 'all') {
        items = items.filter(v => v.risk_level === filter);
      }

      ok(res, { items, total: await redis.llen('llm:verdicts') });
    } catch (e) {
      err(res, 500, e.message);
    }
  });

  // ── DELETE /api/llm/verdicts ────────────────────────────────────────────
  router.delete('/llm/verdicts', async (_req, res) => {
    try {
      await redis.del('llm:verdicts');
      ok(res, { cleared: true });
    } catch (e) {
      err(res, 500, e.message);
    }
  });

  // ── POST /api/llm/queue ─────────────────────────────────────────────────
  // Manually queue a specific IP for LLM review from the admin UI
  router.post('/llm/queue', async (req, res) => {
    try {
      const { ip, reason } = req.body;
      if (!ip || typeof ip !== 'string') return err(res, 400, 'ip is required');

      const entry = JSON.stringify({
        ip,
        host:           '-',
        method:         'MANUAL',
        uri:            '-',
        ua:             '-',
        referer:        '-',
        body_preview:   '',
        trigger_reason: reason || 'manual_admin_review',
        ml_score:       0,
        queued_at:      Math.floor(Date.now() / 1000),
      });

      const qlen = await redis.llen('llm:audit:queue');
      if (qlen >= 2000) return err(res, 429, 'Queue is full, try again later');

      await redis.lpush('llm:audit:queue', entry);
      ok(res, { queued: ip });
    } catch (e) {
      err(res, 500, e.message);
    }
  });

  // ── DELETE /api/llm/queue ───────────────────────────────────────────────
  router.delete('/llm/queue', async (_req, res) => {
    try {
      await redis.del('llm:audit:queue');
      ok(res, { cleared: true });
    } catch (e) {
      err(res, 500, e.message);
    }
  });

  // ── GET /api/llm/verdict/:ip ────────────────────────────────────────────
  router.get('/llm/verdict/:ip', async (req, res) => {
    try {
      const raw = await redis.get(`llm:verdict:${req.params.ip}`);
      if (!raw) return ok(res, null);
      ok(res, JSON.parse(raw));
    } catch (e) {
      err(res, 500, e.message);
    }
  });

  // ── DELETE /api/llm/verdict/:ip ─────────────────────────────────────────
  router.delete('/llm/verdict/:ip', async (req, res) => {
    try {
      await redis.del(`llm:verdict:${req.params.ip}`);
      ok(res, { cleared: req.params.ip });
    } catch (e) {
      err(res, 500, e.message);
    }
  });

  // ── POST /api/llm/test ──────────────────────────────────────────────────
  // Send a test request to verify LLM connectivity
  router.post('/llm/test', async (_req, res) => {
    try {
      const raw = await redis.get('llm:config');
      if (!raw) return err(res, 404, 'LLM not configured');
      const cfg = JSON.parse(raw);
      if (cfg.api_key_enc) {
        try { cfg.api_key = decryptApiKey(cfg.api_key_enc, jwtSecret); }
        catch (_) { cfg.api_key = cfg.api_key_enc; }
      }
      if (!cfg.api_key) return err(res, 400, 'API key not set');

      const { callLLMDirect, parseVerdictDirect } = require('./llm_worker');
      const testEntry = {
        ip: '1.2.3.4', host: 'test.example.com', method: 'GET',
        uri: '/test?id=1+OR+1=1--', ua: 'curl/7.0', referer: '',
        body_preview: '', trigger_reason: 'connectivity_test', ml_score: 0.8,
      };

      const text    = await callLLMDirect(cfg, testEntry);
      const verdict = parseVerdictDirect(text);
      ok(res, { connected: true, sample_verdict: verdict });
    } catch (e) {
      ok(res, { connected: false, error: e.message });
    }
  });
};
