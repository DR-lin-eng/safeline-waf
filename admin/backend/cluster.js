const Redis = require('ioredis');

class ClusterManager {
  constructor() {
    this.redisClient = null;
    this.pubClient = null;
    this.subClient = null;
    this.nodeId = process.env.NODE_ID || `node-${Date.now()}`;
    this.nodeRole = process.env.NODE_ROLE || 'worker';
    this.heartbeatInterval = parseInt(process.env.HEARTBEAT_INTERVAL || '30') * 1000;
    this.nodeTimeout = 90; // seconds
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
    this.redisClient = this._createRedis();
    this.pubClient   = this._createRedis();
    this.subClient   = this._createRedis();

    await this.registerSelf();
    this.startHeartbeat();

    console.log(`[Cluster] Node ${this.nodeId} initialized as ${this.nodeRole}`);
  }

  async registerNode(nodeId, metadata) {
    const nodeKey = `cluster:nodes:${nodeId}`;
    const nodeData = {
      node_id:       nodeId,
      hostname:      metadata.hostname || 'unknown',
      ip:            metadata.ip || 'unknown',
      role:          metadata.role || 'worker',
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
    setInterval(async () => {
      await this.updateHeartbeat(this.nodeId);
    }, this.heartbeatInterval);

    console.log(`[Cluster] Heartbeat started (interval: ${this.heartbeatInterval}ms)`);
  }

  async getClusterStatus() {
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
    await this.redisClient.del(`cluster:nodes:${nodeId}`);
    console.log(`[Cluster] Node removed: ${nodeId}`);
    return true;
  }

  async cleanup() {
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
    console.log(`[Cluster] Shutting down node ${this.nodeId}`);
    const nodeKey = `cluster:nodes:${this.nodeId}`;
    await this.redisClient.hset(nodeKey, 'status', 'offline');

    if (this.redisClient) this.redisClient.quit();
    if (this.pubClient)   this.pubClient.quit();
    if (this.subClient)   this.subClient.quit();
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


class ClusterManager {
  constructor() {
    this.redisClient = null;
    this.pubClient = null;
    this.subClient = null;
    this.nodeId = process.env.NODE_ID || `node-${Date.now()}`;
    this.nodeRole = process.env.NODE_ROLE || 'worker';
    this.heartbeatInterval = parseInt(process.env.HEARTBEAT_INTERVAL || '30') * 1000;
    this.nodeTimeout = 90; // seconds
  }

  async initialize() {
    const redisConfig = {
      host: process.env.REDIS_HOST || 'redis',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD || undefined,
      retry_strategy: (options) => {
        if (options.error && options.error.code === 'ECONNREFUSED') {
          return new Error('Redis connection refused');
        }
        if (options.total_retry_time > 1000 * 60 * 60) {
          return new Error('Redis retry time exhausted');
        }
        if (options.attempt > 10) {
          return undefined;
        }
        return Math.min(options.attempt * 100, 3000);
      }
    };

    this.redisClient = redis.createClient(redisConfig);
    this.pubClient = redis.createClient(redisConfig);
    this.subClient = redis.createClient(redisConfig);

    // Promisify Redis commands
    this.redisClient.hset = promisify(this.redisClient.hset).bind(this.redisClient);
    this.redisClient.hgetall = promisify(this.redisClient.hgetall).bind(this.redisClient);
    this.redisClient.keys = promisify(this.redisClient.keys).bind(this.redisClient);
    this.redisClient.expire = promisify(this.redisClient.expire).bind(this.redisClient);
    this.redisClient.del = promisify(this.redisClient.del).bind(this.redisClient);
    this.redisClient.set = promisify(this.redisClient.set).bind(this.redisClient);
    this.redisClient.get = promisify(this.redisClient.get).bind(this.redisClient);
    this.pubClient.publish = promisify(this.pubClient.publish).bind(this.pubClient);

    await this.registerSelf();
    this.startHeartbeat();

    console.log(`[Cluster] Node ${this.nodeId} initialized as ${this.nodeRole}`);
  }

  async registerNode(nodeId, metadata) {
    const nodeKey = `cluster:nodes:${nodeId}`;
    const nodeData = {
      node_id: nodeId,
      hostname: metadata.hostname || 'unknown',
      ip: metadata.ip || 'unknown',
      role: metadata.role || 'worker',
      status: 'online',
      last_seen: Date.now(),
      version: metadata.version || '1.0.0',
      registered_at: metadata.registered_at || Date.now()
    };

    await this.redisClient.hset(nodeKey, nodeData);
    await this.redisClient.expire(nodeKey, 120); // 2 minutes TTL

    console.log(`[Cluster] Node registered: ${nodeId}`);
    return nodeData;
  }

  async registerSelf() {
    const os = require('os');
    const metadata = {
      hostname: os.hostname(),
      ip: this.getLocalIP(),
      role: this.nodeRole,
      version: process.env.APP_VERSION || '1.0.0',
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
      await this.redisClient.hset(nodeKey, 'last_seen', Date.now());
      await this.redisClient.hset(nodeKey, 'status', 'online');
      await this.redisClient.expire(nodeKey, 120);
      return true;
    } catch (err) {
      console.error(`[Cluster] Heartbeat failed for ${nodeId}:`, err.message);
      return false;
    }
  }

  startHeartbeat() {
    setInterval(async () => {
      await this.updateHeartbeat(this.nodeId);
    }, this.heartbeatInterval);

    console.log(`[Cluster] Heartbeat started (interval: ${this.heartbeatInterval}ms)`);
  }

  async getClusterStatus() {
    const pattern = 'cluster:nodes:*';
    const keys = await this.redisClient.keys(pattern);

    const nodes = [];
    const now = Date.now();

    for (const key of keys) {
      const nodeData = await this.redisClient.hgetall(key);
      if (!nodeData || !nodeData.node_id) continue;

      const lastSeen = parseInt(nodeData.last_seen || '0');
      const isOnline = (now - lastSeen) < (this.nodeTimeout * 1000);

      nodes.push({
        id: nodeData.node_id,
        hostname: nodeData.hostname,
        ip: nodeData.ip,
        role: nodeData.role,
        status: isOnline ? 'online' : 'offline',
        last_seen: lastSeen,
        version: nodeData.version,
        registered_at: parseInt(nodeData.registered_at || '0')
      });
    }

    return {
      total: nodes.length,
      online: nodes.filter(n => n.status === 'online').length,
      offline: nodes.filter(n => n.status === 'offline').length,
      nodes: nodes.sort((a, b) => b.last_seen - a.last_seen)
    };
  }

  async broadcastConfigReload() {
    const version = Date.now();
    await this.redisClient.set('cluster:config:version', version);

    const message = JSON.stringify({
      version,
      timestamp: Date.now(),
      source: this.nodeId
    });

    await this.pubClient.publish('cluster:config:reload', message);
    console.log(`[Cluster] Config reload broadcasted (version: ${version})`);

    return { version, broadcasted_at: Date.now() };
  }

  async syncBlacklist(entries) {
    if (!Array.isArray(entries)) {
      throw new Error('Entries must be an array');
    }

    const message = JSON.stringify({
      action: 'sync',
      entries,
      timestamp: Date.now(),
      source: this.nodeId
    });

    await this.pubClient.publish('cluster:blacklist:sync', message);
    console.log(`[Cluster] Blacklist sync broadcasted (${entries.length} entries)`);

    return { synced: entries.length, broadcasted_at: Date.now() };
  }

  async getClusterStats() {
    const status = await this.getClusterStatus();

    // Aggregate stats from all nodes (placeholder - extend as needed)
    const stats = {
      cluster: {
        total_nodes: status.total,
        online_nodes: status.online,
        offline_nodes: status.offline
      },
      requests: {
        total: 0,
        blocked: 0,
        rate: 0
      },
      updated_at: Date.now()
    };

    return stats;
  }

  async removeNode(nodeId) {
    const nodeKey = `cluster:nodes:${nodeId}`;
    await this.redisClient.del(nodeKey);
    console.log(`[Cluster] Node removed: ${nodeId}`);
    return true;
  }

  async cleanup() {
    const now = Date.now();
    const maxAge = 5 * 60 * 1000; // 5 minutes

    const pattern = 'cluster:nodes:*';
    const keys = await this.redisClient.keys(pattern);

    let removed = 0;
    for (const key of keys) {
      const nodeData = await this.redisClient.hgetall(key);
      if (!nodeData || !nodeData.last_seen) continue;

      const lastSeen = parseInt(nodeData.last_seen);
      if ((now - lastSeen) > maxAge) {
        await this.redisClient.del(key);
        removed++;
        console.log(`[Cluster] Removed stale node: ${nodeData.node_id}`);
      }
    }

    return { removed, checked: keys.length };
  }

  async shutdown() {
    console.log(`[Cluster] Shutting down node ${this.nodeId}`);

    const nodeKey = `cluster:nodes:${this.nodeId}`;
    await this.redisClient.hset(nodeKey, 'status', 'offline');

    if (this.redisClient) this.redisClient.quit();
    if (this.pubClient) this.pubClient.quit();
    if (this.subClient) this.subClient.quit();
  }

  // ── ML Model Synchronisation ──────────────────────────────────────────

  /**
   * Broadcast ml:model:reload to all Nginx workers on every node.
   * Workers subscribe to this channel in init_worker.lua.
   */
  async broadcastModelReload(version) {
    const message = JSON.stringify({
      action:    'reload',
      version,
      timestamp: Date.now(),
      source:    this.nodeId,
    });
    await this.pubClient.publish('ml:model:reload', message);
    console.log(`[ML] Model reload broadcasted: ${version}`);
    return { version, broadcasted_at: Date.now() };
  }

  /**
   * Activate a model version cluster-wide:
   * 1. Save current as "previous" for rollback
   * 2. Set ml:model:active
   * 3. Broadcast reload signal
   */
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

  /**
   * Rollback to the previous model version.
   */
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

  /**
   * Update this node's ml_version in its heartbeat record.
   * Called by init_worker.lua indirectly via Redis key update.
   */
  async reportModelVersion(version) {
    const nodeKey = `cluster:nodes:${this.nodeId}`;
    try {
      await this.redisClient.hset(nodeKey, 'ml_version', version);
      await this.redisClient.hset(nodeKey, 'ml_loaded_at', Date.now());
    } catch (err) {
      console.warn(`[ML] Failed to report model version: ${err.message}`);
    }
  }
}

module.exports = ClusterManager;
