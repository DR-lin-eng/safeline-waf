const Redis = require('ioredis');

class ClusterManager {
  constructor() {
    const envRole = process.env.NODE_ROLE || 'secondary';
    this.redisClient = null;
    this.pubClient = null;
    this.subClient = null;
    this.nodeId = process.env.NODE_ID || `node-${Date.now()}`;
    this.nodeRole = envRole === 'worker' ? 'secondary' : envRole;
    this.heartbeatInterval = parseInt(process.env.HEARTBEAT_INTERVAL || '30') * 1000;
    this.nodeTimeout = 90; // seconds
    this.heartbeatTimer = null;
    this.initialized = false;
  }

  _createRedis() {
    return new Redis({
      host: process.env.REDIS_HOST || 'redis',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD || undefined,
      retryStrategy: (times) => {
        if (times > 10) return null;
        return Math.min(times * 100, 3000);
      },
      lazyConnect: false,
    });
  }

  async initialize() {
    if (this.initialized) {
      return;
    }

    this.redisClient = this._createRedis();
    this.pubClient   = this._createRedis();
    this.subClient   = this._createRedis();

    await this.registerSelf();
    this.startHeartbeat();
    this.initialized = true;

    console.log(`[Cluster] Node ${this.nodeId} initialized as ${this.nodeRole}`);
  }

  async registerNode(nodeId, metadata) {
    const nodeKey = `cluster:nodes:${nodeId}`;
    const nodeData = {
      node_id:       nodeId,
      hostname:      metadata.hostname || 'unknown',
      ip:            metadata.ip || 'unknown',
      role:          metadata.role === 'worker' ? 'secondary' : (metadata.role || 'secondary'),
      status:        'online',
      last_seen:     Date.now(),
      version:       metadata.version || '1.0.0',
      registered_at: metadata.registered_at || Date.now()
    };

    await this.redisClient.hset(nodeKey, nodeData);
    await this.redisClient.expire(nodeKey, 120);

    console.log(`[Cluster] Node registered: ${nodeId}`);
    return nodeData;
  }

  async registerSelf() {
    const os = require('os');
    const metadata = {
      hostname:      os.hostname(),
      ip:            this.getLocalIP(),
      role:          this.nodeRole,
      version:       process.env.APP_VERSION || '1.0.0',
      registered_at: Date.now()
    };
    return await this.registerNode(this.nodeId, metadata);
  }

  getLocalIP() {
    const os = require('os');
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
      for (const iface of interfaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal) {
          return iface.address;
        }
      }
    }
    return '127.0.0.1';
  }

  async updateHeartbeat(nodeId) {
    const nodeKey = `cluster:nodes:${nodeId || this.nodeId}`;
    try {
      await this.redisClient.hset(nodeKey, 'last_seen', Date.now(), 'status', 'online');
      await this.redisClient.expire(nodeKey, 120);
      return true;
    } catch (err) {
      console.error(`[Cluster] Heartbeat failed for ${nodeId}:`, err.message);
      return false;
    }
  }

  startHeartbeat() {
    if (this.heartbeatTimer) {
      return;
    }

    this.heartbeatTimer = setInterval(async () => {
      await this.updateHeartbeat(this.nodeId);
    }, this.heartbeatInterval);

    console.log(`[Cluster] Heartbeat started (interval: ${this.heartbeatInterval}ms)`);
  }

  stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  async getClusterStatus() {
    if (!this.redisClient || !this.initialized) {
      return {
        total: 0,
        online: 0,
        offline: 0,
        nodes: []
      };
    }

    const keys = await this.redisClient.keys('cluster:nodes:*');
    const nodes = [];
    const now = Date.now();

    for (const key of keys) {
      const nodeData = await this.redisClient.hgetall(key);
      if (!nodeData || !nodeData.node_id) continue;

      const lastSeen = parseInt(nodeData.last_seen || '0');
      const isOnline = (now - lastSeen) < (this.nodeTimeout * 1000);

      nodes.push({
        id:           nodeData.node_id,
        hostname:     nodeData.hostname,
        ip:           nodeData.ip,
        role:         nodeData.role,
        status:       isOnline ? 'online' : 'offline',
        last_seen:    lastSeen,
        version:      nodeData.version,
        registered_at: parseInt(nodeData.registered_at || '0')
      });
    }

    return {
      total:   nodes.length,
      online:  nodes.filter(n => n.status === 'online').length,
      offline: nodes.filter(n => n.status === 'offline').length,
      nodes:   nodes.sort((a, b) => b.last_seen - a.last_seen)
    };
  }

  async broadcastConfigReload() {
    if (!this.redisClient || !this.pubClient || !this.initialized) {
      return { version: null, broadcasted_at: Date.now(), skipped: true };
    }

    const version = Date.now();
    await this.redisClient.set('cluster:config:version', version);
    await this.pubClient.publish('cluster:config:reload', JSON.stringify({
      version,
      timestamp: Date.now(),
      source: this.nodeId
    }));
    console.log(`[Cluster] Config reload broadcasted (version: ${version})`);
    return { version, broadcasted_at: Date.now() };
  }

  async syncBlacklist(entries) {
    if (!Array.isArray(entries)) {
      throw new Error('Entries must be an array');
    }
    if (!this.pubClient || !this.initialized) {
      return { synced: 0, broadcasted_at: Date.now(), skipped: true };
    }
    await this.pubClient.publish('cluster:blacklist:sync', JSON.stringify({
      action:    'sync',
      entries,
      timestamp: Date.now(),
      source:    this.nodeId
    }));
    console.log(`[Cluster] Blacklist sync broadcasted (${entries.length} entries)`);
    return { synced: entries.length, broadcasted_at: Date.now() };
  }

  async getClusterStats() {
    const status = await this.getClusterStatus();
    return {
      cluster: {
        total_nodes:  status.total,
        online_nodes: status.online,
        offline_nodes: status.offline
      },
      requests: { total: 0, blocked: 0, rate: 0 },
      updated_at: Date.now()
    };
  }

  async removeNode(nodeId) {
    if (!this.redisClient || !this.initialized) {
      return true;
    }
    await this.redisClient.del(`cluster:nodes:${nodeId}`);
    console.log(`[Cluster] Node removed: ${nodeId}`);
    return true;
  }

  async cleanup() {
    if (!this.redisClient || !this.initialized) {
      return { removed: 0, checked: 0 };
    }

    const now = Date.now();
    const maxAge = 5 * 60 * 1000;
    const keys = await this.redisClient.keys('cluster:nodes:*');

    let removed = 0;
    for (const key of keys) {
      const nodeData = await this.redisClient.hgetall(key);
      if (!nodeData || !nodeData.last_seen) continue;
      if ((now - parseInt(nodeData.last_seen)) > maxAge) {
        await this.redisClient.del(key);
        removed++;
        console.log(`[Cluster] Removed stale node: ${nodeData.node_id}`);
      }
    }
    return { removed, checked: keys.length };
  }

  async shutdown() {
    if (!this.initialized) {
      this.stopHeartbeat();
      return;
    }

    console.log(`[Cluster] Shutting down node ${this.nodeId}`);
    const nodeKey = `cluster:nodes:${this.nodeId}`;
    if (this.redisClient) {
      try {
        await this.redisClient.hset(nodeKey, 'status', 'offline');
      } catch (error) {
        console.warn(`[Cluster] Failed to mark node offline during shutdown: ${error.message}`);
      }
    }

    this.stopHeartbeat();

    if (this.redisClient) await this.redisClient.quit().catch(() => {});
    if (this.pubClient)   await this.pubClient.quit().catch(() => {});
    if (this.subClient)   await this.subClient.quit().catch(() => {});

    this.redisClient = null;
    this.pubClient = null;
    this.subClient = null;
    this.initialized = false;
  }

  // ── ML Model Synchronisation ──────────────────────────────────────────

  async broadcastModelReload(version) {
    await this.pubClient.publish('ml:model:reload', JSON.stringify({
      action:    'reload',
      version,
      timestamp: Date.now(),
      source:    this.nodeId,
    }));
    console.log(`[ML] Model reload broadcasted: ${version}`);
    return { version, broadcasted_at: Date.now() };
  }

  async activateModel(version) {
    const previous = await this.redisClient.get('ml:model:active');
    if (previous && previous !== version) {
      await this.redisClient.set('ml:model:previous', previous);
    }
    await this.redisClient.set('ml:model:active', version);
    await this.broadcastModelReload(version);
    console.log(`[ML] Model activated cluster-wide: ${version}`);
    return { active_version: version, previous_version: previous || null };
  }

  async rollbackModel() {
    const previous = await this.redisClient.get('ml:model:previous');
    if (!previous) throw new Error('No previous model version available');

    const current = await this.redisClient.get('ml:model:active');
    await this.redisClient.set('ml:model:active', previous);
    await this.redisClient.del('ml:model:previous');
    await this.broadcastModelReload(previous);

    console.log(`[ML] Model rolled back: ${current} → ${previous}`);
    return { active_version: previous, rolled_back_from: current };
  }

  async reportModelVersion(version) {
    const nodeKey = `cluster:nodes:${this.nodeId}`;
    try {
      await this.redisClient.hset(nodeKey, 'ml_version', version, 'ml_loaded_at', Date.now());
    } catch (err) {
      console.warn(`[ML] Failed to report model version: ${err.message}`);
    }
  }
}

module.exports = ClusterManager;
