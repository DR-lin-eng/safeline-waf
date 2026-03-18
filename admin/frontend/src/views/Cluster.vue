<template>
  <div class="cluster">
    <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
      <h1 class="h2">集群管理</h1>
      <div class="btn-toolbar mb-2 mb-md-0">
        <button type="button" class="btn btn-sm btn-outline-secondary mr-2" @click="refreshAll" :disabled="loading || syncing">
          <i class="bi bi-arrow-repeat"></i> 刷新
        </button>
        <button type="button" class="btn btn-sm btn-primary" @click="syncCluster" :disabled="syncing || !cluster.enabled">
          <i class="bi bi-cloud-arrow-up"></i>
          {{ syncing ? '同步中...' : '手动同步' }}
        </button>
      </div>
    </div>

    <div class="row mb-3">
      <div class="col-md-12">
        <div class="alert alert-info" role="alert">
          <i class="bi bi-info-circle-fill mr-2"></i>
          支持主副节点部署：主节点负责配置发布，从节点按周期拉取或接收同步。
        </div>
      </div>
    </div>

    <div v-if="loading" class="text-center py-5">
      <div class="spinner-border text-primary" role="status">
        <span class="sr-only">加载中...</span>
      </div>
      <p class="mt-2">加载集群信息...</p>
    </div>

    <div v-else>
      <div class="row mb-4">
        <div class="col-md-4">
          <div class="card text-white bg-primary">
            <div class="card-body">
              <h6 class="card-title">当前节点</h6>
              <h5 class="mb-1">{{ cluster.current.id || '-' }}</h5>
              <small>角色：{{ cluster.current.role === 'primary' ? '主节点' : '从节点' }}</small>
            </div>
          </div>
        </div>
        <div class="col-md-4">
          <div class="card text-white bg-success">
            <div class="card-body">
              <h6 class="card-title">健康节点数</h6>
              <h3 class="mb-1">{{ healthyCount }}/{{ cluster.nodes.length }}</h3>
              <small>集群状态：{{ healthyCount === cluster.nodes.length ? '正常' : '部分异常' }}</small>
            </div>
          </div>
        </div>
        <div class="col-md-4">
          <div class="card" :class="cluster.enabled ? 'border-success' : 'border-secondary'">
            <div class="card-body">
              <h6 class="card-title">集群模式</h6>
              <h5 class="mb-1">{{ cluster.enabled ? '已启用' : '未启用' }}</h5>
              <small class="text-muted">主节点地址：{{ cluster.current.primary_api_url || '-' }}</small>
            </div>
          </div>
        </div>
      </div>

      <div class="row mb-4">
        <div class="col-md-12">
          <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
              <h5 class="card-title mb-0">节点状态</h5>
              <span class="badge" :class="healthyCount === cluster.nodes.length ? 'badge-success' : 'badge-warning'">
                {{ healthyCount === cluster.nodes.length ? '全部在线' : '存在异常' }}
              </span>
            </div>
            <div class="card-body">
              <div v-if="cluster.nodes.length === 0" class="text-muted">暂无节点</div>
              <div v-else class="table-responsive">
                <table class="table table-hover">
                  <thead>
                    <tr>
                      <th>节点ID</th>
                      <th>角色</th>
                      <th>状态</th>
                      <th>同步</th>
                      <th>说明</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="node in cluster.nodes" :key="node.id">
                      <td>{{ node.id }}</td>
                      <td>{{ node.role === 'primary' ? '主节点' : '从节点' }}</td>
                      <td>
                        <span class="badge" :class="node.healthy ? 'badge-success' : 'badge-danger'">
                          {{ node.healthy ? '健康' : '异常' }}
                        </span>
                      </td>
                      <td>
                        <span class="badge" :class="node.sync ? 'badge-info' : 'badge-secondary'">
                          {{ node.sync ? '已启用' : '关闭' }}
                        </span>
                      </td>
                      <td class="text-muted">{{ node.message || '-' }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="row mb-4" v-if="cluster.redis_nodes && cluster.redis_nodes.length > 0">
        <div class="col-md-12">
          <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
              <h5 class="card-title mb-0">Redis 集群节点 (实时心跳)</h5>
              <span class="badge badge-info">
                {{ cluster.redis_stats.online }}/{{ cluster.redis_stats.total }} 在线
              </span>
            </div>
            <div class="card-body">
              <div class="table-responsive">
                <table class="table table-hover">
                  <thead>
                    <tr>
                      <th>节点ID</th>
                      <th>主机名</th>
                      <th>IP地址</th>
                      <th>角色</th>
                      <th>状态</th>
                      <th>最后心跳</th>
                      <th>版本</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="node in cluster.redis_nodes" :key="node.id">
                      <td><code>{{ node.id }}</code></td>
                      <td>{{ node.hostname }}</td>
                      <td>{{ node.ip }}</td>
                      <td>{{ node.role }}</td>
                      <td>
                        <span class="badge" :class="node.status === 'online' ? 'badge-success' : 'badge-danger'">
                          {{ node.status === 'online' ? '在线' : '离线' }}
                        </span>
                      </td>
                      <td>{{ formatLastSeen(node.last_seen) }}</td>
                      <td>{{ node.version || '-' }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="row">
        <div class="col-md-12">
          <div class="card">
            <div class="card-header">
              <h5 class="card-title mb-0">多核心运行建议</h5>
            </div>
            <div class="card-body">
              <div class="row">
                <div class="col-md-3 mb-3">
                  <div class="metric-item">
                    <div class="text-muted">CPU核心数</div>
                    <div class="metric-value">{{ runtime.cpu_cores || '-' }}</div>
                  </div>
                </div>
                <div class="col-md-3 mb-3">
                  <div class="metric-item">
                    <div class="text-muted">估算清洗能力</div>
                    <div class="metric-value">{{ formatNumber(runtime.estimated_capacity_rps) }} RPS</div>
                  </div>
                </div>
                <div class="col-md-3 mb-3">
                  <div class="metric-item">
                    <div class="text-muted">建议连接数</div>
                    <div class="metric-value">{{ formatNumber(runtime.suggested_worker_connections) }}</div>
                  </div>
                </div>
                <div class="col-md-3 mb-3">
                  <div class="metric-item">
                    <div class="text-muted">建议FD上限</div>
                    <div class="metric-value">{{ formatNumber(runtime.suggested_worker_rlimit_nofile) }}</div>
                  </div>
                </div>
              </div>

              <div class="table-responsive mt-2">
                <table class="table table-sm table-bordered">
                  <thead>
                    <tr>
                      <th>阈值项</th>
                      <th>建议值</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>URL 阈值</td>
                      <td>{{ runtime.suggested_ddos_thresholds.url_threshold }}</td>
                    </tr>
                    <tr>
                      <td>IP 阈值</td>
                      <td>{{ runtime.suggested_ddos_thresholds.ip_threshold }}</td>
                    </tr>
                    <tr>
                      <td>全局压力阈值</td>
                      <td>{{ runtime.suggested_ddos_thresholds.global_threshold }}</td>
                    </tr>
                    <tr>
                      <td>全局硬阈值</td>
                      <td>{{ runtime.suggested_ddos_thresholds.global_hard_threshold }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios';
import { getApiErrorMessage, shouldHandleLocally } from '../utils/http';

export default {
  name: 'Cluster',
  data() {
    return {
      loading: true,
      syncing: false,
      cluster: {
        enabled: false,
        current: {},
        nodes: []
      },
      runtime: {
        cpu_cores: 0,
        estimated_capacity_rps: 0,
        suggested_worker_connections: 0,
        suggested_worker_rlimit_nofile: 0,
        suggested_ddos_thresholds: {
          url_threshold: 0,
          ip_threshold: 0,
          global_threshold: 0,
          global_hard_threshold: 0
        }
      }
    };
  },
  computed: {
    healthyCount() {
      return this.cluster.nodes.filter((node) => node.healthy).length;
    }
  },
  created() {
    this.refreshAll();
  },
  methods: {
    async refreshAll() {
      this.loading = true;
      try {
        const [statusResp, runtimeResp, nodesResp] = await Promise.all([
          axios.get('/cluster/status'),
          axios.get('/runtime/profile'),
          axios.get('/cluster/nodes').catch(() => ({ data: { success: false } }))
        ]);

        if (statusResp.data && statusResp.data.success) {
          this.cluster = statusResp.data.data;
        }

        if (runtimeResp.data && runtimeResp.data.success) {
          this.runtime = runtimeResp.data.data;
        }

        // Add Redis cluster nodes if available
        if (nodesResp.data && nodesResp.data.success) {
          this.cluster.redis_nodes = nodesResp.data.data.nodes || [];
          this.cluster.redis_stats = {
            total: nodesResp.data.data.total || 0,
            online: nodesResp.data.data.online || 0,
            offline: nodesResp.data.data.offline || 0
          };
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '获取集群信息失败，请稍后重试。'));
        }
      } finally {
        this.loading = false;
      }
    },
    async syncCluster() {
      this.syncing = true;
      try {
        const response = await axios.post('/cluster/sync');
        if (response.data && response.data.success) {
          this.$toast.success('集群同步已触发。');
          await this.refreshAll();
        } else {
          this.$toast.error((response.data && response.data.message) || '集群同步失败。');
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '同步请求失败，请稍后重试。'));
        }
      } finally {
        this.syncing = false;
      }
    },
    formatNumber(value) {
      const number = Number(value || 0);
      return Number.isFinite(number) ? number.toLocaleString() : '-';
    },
    formatLastSeen(timestamp) {
      if (!timestamp) return 'N/A';
      const now = Date.now();
      const diff = Math.floor((now - timestamp) / 1000);

      if (diff < 60) return `${diff}秒前`;
      if (diff < 3600) return `${Math.floor(diff / 60)}分钟前`;
      if (diff < 86400) return `${Math.floor(diff / 3600)}小时前`;
      return `${Math.floor(diff / 86400)}天前`;
    }
  }
};
</script>

<style scoped>
.card {
  border-radius: 0.5rem;
}

.metric-item {
  border: 1px solid #e9ecef;
  border-radius: 0.4rem;
  padding: 0.75rem;
  height: 100%;
}

.metric-value {
  font-size: 1.2rem;
  font-weight: 600;
}
</style>
