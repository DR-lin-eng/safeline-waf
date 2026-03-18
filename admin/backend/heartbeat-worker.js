const ClusterManager = require('./cluster');

class HeartbeatWorker {
  constructor(clusterManager) {
    this.cluster = clusterManager;
    this.checkInterval = 30000; // 30 seconds
    this.nodeTimeout = 90; // seconds
    this.cleanupInterval = 300000; // 5 minutes
  }

  start() {
    console.log('[HeartbeatWorker] Starting health monitoring...');

    // Periodic health check
    setInterval(() => {
      this.checkNodeHealth();
    }, this.checkInterval);

    // Periodic cleanup of stale nodes
    setInterval(() => {
      this.cleanupStaleNodes();
    }, this.cleanupInterval);

    // Initial checks
    setTimeout(() => {
      this.checkNodeHealth();
      this.cleanupStaleNodes();
    }, 5000);
  }

  async checkNodeHealth() {
    try {
      const status = await this.cluster.getClusterStatus();
      const now = Date.now();

      for (const node of status.nodes) {
        const timeSinceLastSeen = (now - node.last_seen) / 1000;

        if (timeSinceLastSeen > this.nodeTimeout && node.status === 'online') {
          console.warn(`[HeartbeatWorker] Node ${node.id} is unresponsive (${Math.floor(timeSinceLastSeen)}s)`);
          // Status will be automatically marked as offline by getClusterStatus
        }
      }

      console.log(`[HeartbeatWorker] Health check complete: ${status.online}/${status.total} nodes online`);
    } catch (err) {
      console.error('[HeartbeatWorker] Health check failed:', err.message);
    }
  }

  async cleanupStaleNodes() {
    try {
      const result = await this.cluster.cleanup();
      if (result.removed > 0) {
        console.log(`[HeartbeatWorker] Cleanup: removed ${result.removed} stale nodes`);
      }
    } catch (err) {
      console.error('[HeartbeatWorker] Cleanup failed:', err.message);
    }
  }
}

module.exports = HeartbeatWorker;
