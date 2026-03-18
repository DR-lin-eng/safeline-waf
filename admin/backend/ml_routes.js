/**
 * ML Management Routes for SafeLine WAF
 * Mounted at /api/ml/* via apiRouter
 */
'use strict';

const multer = require('multer');
const crypto = require('crypto');

// Multer: model JSON files, max 50 MB, memory storage
const modelUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (file.mimetype === 'application/json' ||
        file.originalname.endsWith('.json')) {
      cb(null, true);
    } else {
      cb(new Error('Only JSON model files are accepted'));
    }
  }
});

/**
 * @param {import('express').Router} router  - apiRouter (already auth-gated)
 * @param {import('ioredis').Redis}  redis   - shared ioredis client
 * @param {object}                  cluster - ClusterManager instance (optional)
 */
module.exports = function mountMlRoutes(router, redis, cluster) {

  // ── Helpers ────────────────────────────────────────────────────────────

  function sendErr(res, status, msg) {
    return res.status(status).json({ code: status, message: msg, data: null });
  }

  function ok(res, data) {
    return res.json({ success: true, data });
  }

  /** Broadcast ml:model:reload to all Nginx workers via Redis Pub/Sub */
  async function broadcastModelReload(version) {
    const payload = JSON.stringify({
      action:    'reload',
      version,
      timestamp: Date.now(),
      source:    process.env.NODE_ID || 'admin-backend',
    });
    await redis.publish('ml:model:reload', payload);
  }

  /** Return all version keys sorted by upload time (newest first) */
  async function listModelVersions() {
    const keys = await redis.keys('ml:model:*:meta');
    const models = [];
    for (const key of keys) {
      const raw = await redis.get(key);
      if (!raw) continue;
      try {
        models.push(JSON.parse(raw));
      } catch (_) { /* skip corrupt entries */ }
    }
    models.sort((a, b) => (b.uploaded_at || 0) - (a.uploaded_at || 0));
    return models;
  }

  // ── GET /api/ml/status ──────────────────────────────────────────────────
  router.get('/ml/status', async (_req, res) => {
    try {
      const activeVersion  = await redis.get('ml:model:active');
      const previousVersion = await redis.get('ml:model:previous');
      const canaryPct      = await redis.get('ml:canary_pct');

      let meta = null;
      if (activeVersion) {
        const raw = await redis.get(`ml:model:${activeVersion}:meta`);
        if (raw) meta = JSON.parse(raw);
      }

      ok(res, {
        active_version:   activeVersion || null,
        previous_version: previousVersion || null,
        canary_pct:       parseInt(canaryPct || '100', 10),
        model_meta:       meta,
      });
    } catch (err) {
      sendErr(res, 500, err.message);
    }
  });

  // ── GET /api/ml/models ──────────────────────────────────────────────────
  router.get('/ml/models', async (_req, res) => {
    try {
      const activeVersion = await redis.get('ml:model:active');
      const models = await listModelVersions();
      for (const m of models) {
        m.active = m.version === activeVersion;
      }
      ok(res, models);
    } catch (err) {
      sendErr(res, 500, err.message);
    }
  });

  // ── GET /api/ml/models/:version ─────────────────────────────────────────
  router.get('/ml/models/:version', async (req, res) => {
    const { version } = req.params;
    try {
      const raw = await redis.get(`ml:model:${version}:meta`);
      if (!raw) return sendErr(res, 404, 'Model version not found');
      const meta = JSON.parse(raw);
      meta.active = (await redis.get('ml:model:active')) === version;
      ok(res, meta);
    } catch (err) {
      sendErr(res, 500, err.message);
    }
  });

  // ── POST /api/ml/models/upload ──────────────────────────────────────────
  // Upload model weights JSON + optional metadata fields
  router.post('/ml/models/upload',
    (req, res, next) => {
      const handler = modelUpload.single('model');
      handler(req, res, (uploadErr) => {
        if (uploadErr) return sendErr(res, 400, uploadErr.message);
        next();
      });
    },
    async (req, res) => {
      try {
        if (!req.file) return sendErr(res, 400, 'Missing model file');

        // Parse weights JSON
        let weightsData;
        try {
          weightsData = JSON.parse(req.file.buffer.toString('utf8'));
        } catch (_) {
          return sendErr(res, 400, 'Invalid JSON in model file');
        }

        // Basic structure validation
        if (!Array.isArray(weightsData.weights) || weightsData.weights.length === 0) {
          return sendErr(res, 400, 'Model must have a non-empty "weights" array');
        }
        if (typeof weightsData.intercept !== 'number') {
          return sendErr(res, 400, 'Model must have a numeric "intercept"');
        }

        // Generate or use provided version
        const version = req.body.version ||
          `v${new Date().toISOString().slice(0,10).replace(/-/g,'')}-${crypto.randomBytes(4).toString('hex')}`;

        // Ensure version isn't already used
        const existing = await redis.get(`ml:model:${version}:meta`);
        if (existing) return sendErr(res, 409, `Version "${version}" already exists`);

        // Compute checksum
        const checksum = crypto.createHash('sha256')
          .update(req.file.buffer).digest('hex');

        // Build metadata
        const meta = {
          version,
          algorithm:      req.body.algorithm      || weightsData.algorithm || 'logistic_regression',
          feature_count:  weightsData.weights.length,
          threshold:      parseFloat(weightsData.threshold || 0.5),
          accuracy:       parseFloat(req.body.accuracy       || 0),
          f1_score:       parseFloat(req.body.f1_score       || 0),
          trained_at:     req.body.trained_at     || new Date().toISOString(),
          description:    req.body.description    || '',
          checksum,
          uploaded_at:    Date.now(),
          uploaded_by:    (req.user && req.user.username) || 'admin',
          size_bytes:     req.file.size,
        };

        // Store in Redis (weights TTL: 90 days; meta TTL: 90 days)
        const TTL = 90 * 86400;
        await redis.set(`ml:model:${version}:weights`, req.file.buffer.toString('utf8'), 'EX', TTL);
        await redis.set(`ml:model:${version}:meta`,    JSON.stringify(meta),              'EX', TTL);

        console.log(`[ML] Model uploaded: ${version} (${meta.feature_count} features, checksum: ${checksum.slice(0,8)})`);
        ok(res, { version, meta });
      } catch (err) {
        sendErr(res, 500, err.message);
      }
    }
  );

  // ── PUT /api/ml/models/:version/activate ───────────────────────────────
  router.put('/ml/models/:version/activate', async (req, res) => {
    const { version } = req.params;
    try {
      const raw = await redis.get(`ml:model:${version}:meta`);
      if (!raw) return sendErr(res, 404, 'Model version not found');

      // Preserve current as "previous" for rollback
      const current = await redis.get('ml:model:active');
      if (current && current !== version) {
        await redis.set('ml:model:previous', current);
      }

      await redis.set('ml:model:active', version);
      await broadcastModelReload(version);

      console.log(`[ML] Model activated: ${version} (replaced: ${current || 'none'})`);
      ok(res, { active_version: version, previous_version: current || null });
    } catch (err) {
      sendErr(res, 500, err.message);
    }
  });

  // ── POST /api/ml/models/rollback ────────────────────────────────────────
  router.post('/ml/models/rollback', async (_req, res) => {
    try {
      const previous = await redis.get('ml:model:previous');
      if (!previous) return sendErr(res, 404, 'No previous model version to roll back to');

      const raw = await redis.get(`ml:model:${previous}:meta`);
      if (!raw) return sendErr(res, 404, `Previous model ${previous} no longer exists in Redis`);

      const current = await redis.get('ml:model:active');
      await redis.set('ml:model:active', previous);
      await redis.del('ml:model:previous');
      await broadcastModelReload(previous);

      console.log(`[ML] Rolled back: ${current} → ${previous}`);
      ok(res, { active_version: previous, rolled_back_from: current });
    } catch (err) {
      sendErr(res, 500, err.message);
    }
  });

  // ── DELETE /api/ml/models/:version ─────────────────────────────────────
  router.delete('/ml/models/:version', async (req, res) => {
    const { version } = req.params;
    try {
      // Cannot delete the active model
      const active = await redis.get('ml:model:active');
      if (active === version) {
        return sendErr(res, 409, 'Cannot delete the active model. Activate another model first.');
      }

      const weightKey = `ml:model:${version}:weights`;
      const metaKey   = `ml:model:${version}:meta`;
      const deleted = await redis.del(weightKey, metaKey);

      if (deleted === 0) return sendErr(res, 404, 'Model version not found');

      console.log(`[ML] Model deleted: ${version}`);
      ok(res, { deleted: version });
    } catch (err) {
      sendErr(res, 500, err.message);
    }
  });

  // ── GET /api/ml/metrics ─────────────────────────────────────────────────
  // Aggregates inference counters stored by ml_inference.lua
  router.get('/ml/metrics', async (req, res) => {
    try {
      const get = (k) => redis.get(k).then(v => parseInt(v || '0', 10));

      const [total, attacks, benign, latSum, latCount, cacheHits] = await Promise.all([
        get('ml:metrics:predictions:total'),
        get('ml:metrics:predictions:attack'),
        get('ml:metrics:predictions:benign'),
        get('ml:metrics:latency:sum_us'),
        get('ml:metrics:latency:count'),
        get('ml:metrics:cache_hits'),
      ]);

      const avgLatMs = latCount > 0 ? (latSum / latCount / 1000).toFixed(3) : 0;
      const cacheHitRate = total > 0 ? (cacheHits / total).toFixed(4) : 0;

      // Time-series: last 60 buckets (10s each = last 10 minutes)
      const now    = Math.floor(Date.now() / 1000);
      const bucket = now - (now % 10);
      const trend  = [];
      for (let i = 59; i >= 0; i--) {
        const b  = bucket - i * 10;
        trend.push({ ts: b,
          total:   parseInt(await redis.get(`ml:trend:total:${b}`)   || '0', 10),
          attacks: parseInt(await redis.get(`ml:trend:attacks:${b}`) || '0', 10),
        });
      }

      ok(res, {
        predictions_total: total,
        predictions_attack: attacks,
        predictions_benign: benign,
        avg_latency_ms: parseFloat(avgLatMs),
        cache_hit_rate: parseFloat(cacheHitRate),
        trend,
        active_version: await redis.get('ml:model:active'),
      });
    } catch (err) {
      sendErr(res, 500, err.message);
    }
  });

  // ── GET /api/ml/samples ─────────────────────────────────────────────────
  router.get('/ml/samples', async (req, res) => {
    try {
      const days = Math.min(parseInt(req.query.days || '7', 10), 30);
      const stats = [];

      for (let i = 0; i < days; i++) {
        const d = new Date(Date.now() - i * 86400000);
        const dateStr = d.toISOString().slice(0, 10);

        const [benignLen, attackLen] = await Promise.all([
          redis.llen(`ml:samples:${dateStr}:benign`),
          redis.llen(`ml:samples:${dateStr}:attack`),
        ]);

        stats.push({ date: dateStr, benign: benignLen, attack: attackLen });
      }

      const totalBenign = stats.reduce((s, d) => s + d.benign, 0);
      const totalAttack = stats.reduce((s, d) => s + d.attack, 0);

      ok(res, {
        total_benign: totalBenign,
        total_attack: totalAttack,
        total:        totalBenign + totalAttack,
        by_day:       stats,
      });
    } catch (err) {
      sendErr(res, 500, err.message);
    }
  });

  // ── GET /api/ml/samples/:date/export ───────────────────────────────────
  // Returns up to 1000 raw samples for a given date as NDJSON
  router.get('/ml/samples/:date/export', async (req, res) => {
    const { date } = req.params;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return sendErr(res, 400, 'Invalid date format');

    const label = req.query.label === 'attack' ? 'attack' : 'benign';
    const limit = Math.min(parseInt(req.query.limit || '1000', 10), 5000);

    try {
      const items = await redis.lrange(`ml:samples:${date}:${label}`, 0, limit - 1);
      res.setHeader('Content-Type', 'application/x-ndjson');
      res.setHeader('Content-Disposition', `attachment; filename="samples-${date}-${label}.ndjson"`);
      res.send(items.join('\n'));
    } catch (err) {
      sendErr(res, 500, err.message);
    }
  });

  // ── POST /api/ml/canary ─────────────────────────────────────────────────
  // Set canary percentage (0–100). Nginx workers read ml:canary_pct from Redis.
  router.post('/ml/canary', async (req, res) => {
    const pct = parseInt(req.body.percentage, 10);
    if (isNaN(pct) || pct < 0 || pct > 100) {
      return sendErr(res, 400, 'percentage must be 0–100');
    }
    try {
      await redis.set('ml:canary_pct', String(pct));
      ok(res, { canary_pct: pct });
    } catch (err) {
      sendErr(res, 500, err.message);
    }
  });

  // ── GET /api/ml/cluster ─────────────────────────────────────────────────
  // Shows which model version each cluster node is running (from heartbeat data)
  router.get('/ml/cluster', async (_req, res) => {
    try {
      const keys = await redis.keys('cluster:nodes:*');
      const nodes = [];
      for (const key of keys) {
        const data = await redis.hgetall(key);
        if (!data || !data.node_id) continue;
        nodes.push({
          node_id:       data.node_id,
          hostname:      data.hostname,
          status:        data.status,
          ml_version:    data.ml_version    || null,
          ml_loaded_at:  data.ml_loaded_at  || null,
        });
      }
      const active = await redis.get('ml:model:active');
      const inSync  = nodes.filter(n => n.ml_version === active).length;
      ok(res, { active_version: active, nodes, in_sync: inSync, total: nodes.length });
    } catch (err) {
      sendErr(res, 500, err.message);
    }
  });

};
