'use strict';
/**
 * Attack Map API Routes
 * Mounted at /api/map/*
 *
 * GET /map/attack-data   – geo-resolved blocked IPs with counts
 * GET /map/stats         – summary stats for the map header cards
 */

const https = require('https');

// Private / reserved IP ranges – skip geo lookup
const PRIVATE_IP_RE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1$|localhost)/i;

/**
 * Batch geo-lookup via ip-api.com (free, no key required, max 100/batch)
 * Returns Map<ip, {country, countryCode, city, lat, lon}>
 */
function batchGeoLookup(ips) {
  return new Promise((resolve) => {
    if (!ips.length) return resolve(new Map());

    const body = JSON.stringify(ips.map(ip => ({ query: ip, fields: 'query,country,countryCode,city,lat,lon,status' })));

    const req = https.request({
      hostname: 'ip-api.com',
      path: '/batch?fields=query,country,countryCode,city,lat,lon,status',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      let data = '';
      res.on('data', d => { data += d; });
      res.on('end', () => {
        try {
          const arr = JSON.parse(data);
          const map = new Map();
          for (const item of arr) {
            if (item.status === 'success') {
              map.set(item.query, {
                country: item.country || 'Unknown',
                countryCode: (item.countryCode || 'XX').toLowerCase(),
                city: item.city || '',
                lat: item.lat || 0,
                lon: item.lon || 0,
              });
            }
          }
          resolve(map);
        } catch (_) {
          resolve(new Map());
        }
      });
    });

    req.on('error', () => resolve(new Map()));
    req.setTimeout(8000, () => { req.destroy(); resolve(new Map()); });
    req.write(body);
    req.end();
  });
}

/**
 * Resolve a list of IPs with Redis cache.
 * Cache key: map:geo:<ip>  TTL: 86400s
 */
async function resolveIps(ips, redis) {
  const result = new Map();
  const needLookup = [];

  for (const ip of ips) {
    if (PRIVATE_IP_RE.test(ip)) {
      result.set(ip, { country: '内网', countryCode: 'xx', city: '', lat: 0, lon: 0, private: true });
      continue;
    }
    const cached = await redis.get(`map:geo:${ip}`);
    if (cached) {
      try { result.set(ip, JSON.parse(cached)); } catch (_) {}
    } else {
      needLookup.push(ip);
    }
  }

  // Batch in chunks of 100
  for (let i = 0; i < needLookup.length; i += 100) {
    const chunk = needLookup.slice(i, i + 100);
    const geoMap = await batchGeoLookup(chunk);
    for (const ip of chunk) {
      const geo = geoMap.get(ip) || { country: 'Unknown', countryCode: 'xx', city: '', lat: 0, lon: 0 };
      result.set(ip, geo);
      // Cache the result
      await redis.set(`map:geo:${ip}`, JSON.stringify(geo), 'EX', 86400);
    }
  }

  return result;
}

module.exports = function mountMapRoutes(router, redis) {

  function ok(res, data) {
    return res.json({ success: true, data });
  }
  function fail(res, status, msg) {
    return res.status(status).json({ code: status, message: msg, data: null });
  }

  // ── GET /map/attack-data ────────────────────────────────────────────────────
  // Query params:
  //   limit  (default 500, max 2000) – how many recent log entries to scan
  //   only_blocked (default true)    – only include blocked requests
  router.get('/map/attack-data', async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit || '500', 10) || 500, 2000);
      const onlyBlocked = req.query.only_blocked !== 'false';

      const raw = await redis.lrange('safeline:logs', 0, limit - 1);
      const logs = raw.map(l => { try { return JSON.parse(l); } catch (_) { return null; } }).filter(Boolean);

      // Filter and aggregate IP -> count
      const ipCount = new Map();
      const ipFirstSeen = new Map();
      const ipReasons = new Map();

      for (const log of logs) {
        if (onlyBlocked && !log.is_blocked) continue;
        const ip = log.client_ip || log.ip;
        if (!ip) continue;

        ipCount.set(ip, (ipCount.get(ip) || 0) + 1);
        if (!ipFirstSeen.has(ip)) ipFirstSeen.set(ip, log.timestamp);
        if (log.reason && !ipReasons.has(ip)) ipReasons.set(ip, log.reason);
      }

      if (ipCount.size === 0) {
        return ok(res, { points: [], stats: { total: 0, countries: 0, top_ips: [], top_countries: [] } });
      }

      // Geo-resolve all unique IPs
      const uniqueIps = Array.from(ipCount.keys());
      const geoMap = await resolveIps(uniqueIps, redis);

      // Build points array
      const points = [];
      const countryCount = new Map();

      for (const [ip, count] of ipCount.entries()) {
        const geo = geoMap.get(ip);
        if (!geo || geo.private || (geo.lat === 0 && geo.lon === 0)) continue;

        points.push({
          ip,
          lat: geo.lat,
          lon: geo.lon,
          country: geo.country,
          countryCode: geo.countryCode,
          city: geo.city,
          count,
          reason: ipReasons.get(ip) || '',
        });

        countryCount.set(geo.country, (countryCount.get(geo.country) || 0) + count);
      }

      // Top IPs
      const top_ips = Array.from(ipCount.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([ip, count]) => {
          const geo = geoMap.get(ip) || {};
          return { ip, count, country: geo.country || 'Unknown', city: geo.city || '' };
        });

      // Top countries
      const top_countries = Array.from(countryCount.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([country, count]) => ({ country, count }));

      const stats = {
        total: Array.from(ipCount.values()).reduce((a, b) => a + b, 0),
        unique_ips: ipCount.size,
        countries: countryCount.size,
        top_ips,
        top_countries,
      };

      return ok(res, { points, stats });
    } catch (e) {
      console.error('[MapRoutes] attack-data error:', e.message);
      return fail(res, 500, e.message);
    }
  });

  // ── GET /map/stats ──────────────────────────────────────────────────────────
  // Lightweight stats without full geo resolution (uses cached geo only)
  router.get('/map/stats', async (req, res) => {
    try {
      const raw = await redis.lrange('safeline:logs', 0, 499);
      const logs = raw.map(l => { try { return JSON.parse(l); } catch (_) { return null; } }).filter(Boolean);

      const blocked = logs.filter(l => l.is_blocked);
      const total = logs.length;
      const totalBlocked = blocked.length;
      const blockRate = total > 0 ? ((totalBlocked / total) * 100).toFixed(1) : '0.0';

      // Count unique IPs in blocked
      const uniqueBlockedIps = new Set(blocked.map(l => l.client_ip || l.ip).filter(Boolean));

      return ok(res, {
        total_requests: total,
        total_blocked: totalBlocked,
        block_rate: parseFloat(blockRate),
        unique_attacker_ips: uniqueBlockedIps.size,
      });
    } catch (e) {
      return fail(res, 500, e.message);
    }
  });

  // ── DELETE /map/geo-cache ───────────────────────────────────────────────────
  // Flush all cached geo entries (for debugging)
  router.delete('/map/geo-cache', async (_req, res) => {
    try {
      const keys = await redis.keys('map:geo:*');
      if (keys.length) await redis.del(...keys);
      return ok(res, { cleared: keys.length });
    } catch (e) {
      return fail(res, 500, e.message);
    }
  });
};
