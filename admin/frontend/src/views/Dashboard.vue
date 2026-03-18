<template>
  <div class="dashboard">
    <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
      <h1 class="h2">仪表盘</h1>
      <div class="btn-toolbar mb-2 mb-md-0">
        <button type="button" class="btn btn-sm btn-outline-secondary" @click="refreshStats" :disabled="loading">
          <i class="bi bi-arrow-repeat"></i> 刷新数据
        </button>
      </div>
    </div>

    <div v-if="loading" class="text-center py-4">
      <div class="spinner-border text-primary" role="status">
        <span class="sr-only">加载中...</span>
      </div>
      <p class="mt-2">加载仪表盘数据...</p>
    </div>

    <div class="row mb-4">
      <div class="col-md-4">
        <div class="card text-white bg-primary mb-3">
          <div class="card-body">
            <div class="d-flex justify-content-between align-items-center">
              <div>
                <h6 class="card-title">总请求数</h6>
                <h3 class="card-text">{{ stats.total_requests.toLocaleString() }}</h3>
              </div>
              <div class="display-4">
                <i class="bi bi-graph-up"></i>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="card text-white bg-success mb-3">
          <div class="card-body">
            <div class="d-flex justify-content-between align-items-center">
              <div>
                <h6 class="card-title">通过请求数</h6>
                <h3 class="card-text">{{ (stats.total_requests - stats.blocked_requests).toLocaleString() }}</h3>
              </div>
              <div class="display-4">
                <i class="bi bi-check-circle"></i>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="card text-white bg-danger mb-3">
          <div class="card-body">
            <div class="d-flex justify-content-between align-items-center">
              <div>
                <h6 class="card-title">阻止请求数</h6>
                <h3 class="card-text">{{ stats.blocked_requests.toLocaleString() }}</h3>
              </div>
              <div class="display-4">
                <i class="bi bi-shield"></i>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="row mb-4">
      <div class="col-md-12">
        <div class="card border-danger" v-if="attackStatus.active">
          <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="card-title mb-0">DDoS 攻击摘要</h5>
            <router-link to="/monitor" class="btn btn-sm btn-outline-danger">
              进入监控大屏 <i class="bi bi-arrow-right"></i>
            </router-link>
          </div>
          <div class="card-body">
            <div class="row">
              <div class="col-md-4 mb-3 mb-md-0">
                <div class="text-muted small">当前状态</div>
                <div class="h5 text-danger mb-0">正在被攻击</div>
              </div>
              <div class="col-md-4 mb-3 mb-md-0">
                <div class="text-muted small">攻击目标</div>
                <div class="font-weight-bold">{{ attackStatus.target_summary.label || '暂无攻击目标' }}</div>
              </div>
              <div class="col-md-2 col-6">
                <div class="text-muted small">攻击分数</div>
                <div class="font-weight-bold">{{ formatNumber(attackStatus.score) }}</div>
              </div>
              <div class="col-md-2 col-6">
                <div class="text-muted small">CF Shield</div>
                <div class="font-weight-bold" :class="attackStatus.shield_state.active ? 'text-danger' : 'text-success'">
                  {{ attackStatus.shield_state.active ? '已开启' : '未开启' }}
                </div>
              </div>
            </div>
          </div>
        </div>
        <div class="card border-success" v-else>
          <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="card-title mb-0">DDoS 攻击摘要</h5>
            <router-link to="/monitor" class="btn btn-sm btn-outline-primary">
              查看监控详情 <i class="bi bi-arrow-right"></i>
            </router-link>
          </div>
          <div class="card-body d-flex justify-content-between align-items-center flex-wrap">
            <div>
              <div class="text-muted small">当前状态</div>
              <div class="h5 text-success mb-1">已恢复</div>
              <div class="text-muted small">最近攻击时间：{{ formatPublishedAt(attackStatus.last_attack_at) }}</div>
            </div>
            <div class="mt-3 mt-md-0 text-md-right">
              <div class="text-muted small">最近目标</div>
              <div class="font-weight-bold">{{ attackStatus.target_summary.label || '暂无攻击目标' }}</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="row mb-4">
      <div class="col-md-12">
        <div class="card">
          <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="card-title mb-0">快照状态</h5>
            <button
              type="button"
              class="btn btn-sm btn-outline-secondary"
              @click="fetchSnapshotStatus"
              :disabled="snapshotLoading"
            >
              <i class="bi bi-arrow-clockwise"></i> 刷新
            </button>
          </div>
          <div class="card-body">
            <div v-if="snapshotLoading" class="text-muted">加载中...</div>
            <div v-else class="d-flex flex-wrap">
              <div class="mr-4 mb-2">
                <div class="text-muted small">当前版本</div>
                <div><code>{{ snapshotStatus.active_version || '-' }}</code></div>
              </div>
              <div class="mb-2">
                <div class="text-muted small">发布时间</div>
                <div>{{ formatPublishedAt(snapshotStatus.published_at) }}</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="row mb-4">
      <div class="col-md-12">
        <div class="card">
          <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="card-title mb-0">集群状态</h5>
            <router-link to="/cluster" class="btn btn-sm btn-outline-primary">
              查看详情 <i class="bi bi-arrow-right"></i>
            </router-link>
          </div>
          <div class="card-body">
            <div v-if="clusterLoading" class="text-muted">加载中...</div>
            <div v-else-if="clusterStats.total > 0" class="d-flex flex-wrap">
              <div class="mr-4 mb-2">
                <div class="text-muted small">总节点数</div>
                <div class="h4 mb-0">{{ clusterStats.total }}</div>
              </div>
              <div class="mr-4 mb-2">
                <div class="text-muted small">在线节点</div>
                <div class="h4 mb-0 text-success">{{ clusterStats.online }}</div>
              </div>
              <div class="mb-2">
                <div class="text-muted small">离线节点</div>
                <div class="h4 mb-0 text-danger">{{ clusterStats.offline }}</div>
              </div>
            </div>
            <div v-else class="text-muted">
              集群功能未启用或无节点注册
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="row mb-4">
      <div class="col-md-12">
        <div class="card">
          <div class="card-header">
            <h5 class="card-title mb-0">最近日志</h5>
          </div>
          <div class="card-body">
            <div v-if="logs.length === 0" class="text-center py-4">
              <p class="text-muted">暂无日志数据</p>
            </div>
            <div v-else class="table-responsive">
              <table class="table table-sm table-hover">
                <thead>
                  <tr>
                    <th>时间</th>
                    <th>IP地址</th>
                    <th>方法</th>
                    <th>URI</th>
                    <th>状态</th>
                    <th>原因</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(log, index) in logs.slice(0, 10)" :key="index" :class="{'table-danger': log.is_blocked}">
                    <td>{{ formatDate(log.timestamp) }}</td>
                    <td>{{ log.client_ip }}</td>
                    <td>{{ log.method }}</td>
                    <td class="text-truncate" style="max-width: 300px;">{{ log.uri }}</td>
                    <td>
                      <span v-if="log.is_blocked" class="badge badge-danger">已阻止</span>
                      <span v-else class="badge badge-success">通过</span>
                    </td>
                    <td>{{ log.reason || '-' }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div class="text-center mt-3">
              <router-link to="/logs" class="btn btn-sm btn-outline-primary">查看所有日志</router-link>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios';
import moment from 'moment';
import { getApiErrorMessage, shouldHandleLocally } from '../utils/http';

function getEmptyAttackStatus() {
  return {
    active: false,
    score: 0,
    peak: 0,
    last_attack_at: 0,
    shield_state: {
      active: false
    },
    target_summary: {
      label: '暂无攻击目标'
    }
  };
}

export default {
  name: 'Dashboard',
  data() {
    return {
      loading: true,
      snapshotLoading: false,
      clusterLoading: false,
      stats: {
        total_requests: 0,
        blocked_requests: 0,
        sites: {}
      },
      logs: [],
      attackStatus: getEmptyAttackStatus(),
      snapshotStatus: {
        active_version: null,
        published_at: null
      },
      clusterStats: {
        total: 0,
        online: 0,
        offline: 0
      }
    };
  },
  created() {
    this.fetchData();
    this.fetchSnapshotStatus();
    this.fetchClusterStats();
    },
  methods: {
    async fetchData() {
      this.loading = true;
      try {
        const [statsResponse, logsResponse, attackResponse] = await Promise.all([
          axios.get('/stats'),
          axios.get('/logs?limit=10'),
          axios.get('/monitor/attack-status', { params: { limit: 10 } })
        ]);

        if (statsResponse.data.success) {
          this.stats = statsResponse.data.data;
        }

        if (logsResponse.data.success) {
          this.logs = logsResponse.data.data;
        }

        if (attackResponse.data && attackResponse.data.success) {
          this.attackStatus = attackResponse.data.data || getEmptyAttackStatus();
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '获取仪表盘数据失败，请稍后重试。'));
        }
      } finally {
        this.loading = false;
      }
    },
    async fetchSnapshotStatus() {
      this.snapshotLoading = true;
      try {
        const response = await axios.get('/snapshot/status');
        const payload = response && response.data ? response.data : null;
        if (payload && payload.code === 0) {
          this.snapshotStatus = payload.data || { active_version: null, published_at: null };
        } else {
          this.$toast.error((payload && payload.message) || '获取快照状态失败。');
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '获取快照状态失败，请稍后重试。'));
        }
      } finally {
        this.snapshotLoading = false;
      }
    },
    async fetchClusterStats() {
      this.clusterLoading = true;
      try {
        const response = await axios.get('/cluster/nodes');
        if (response.data && response.data.success) {
          const data = response.data.data;
          this.clusterStats = {
            total: data.total || 0,
            online: data.online || 0,
            offline: data.offline || 0
          };
        }
      } catch (error) {
        console.log('Cluster stats not available');
      } finally {
        this.clusterLoading = false;
      }
    },
    refreshStats() {
      this.fetchData();
      this.fetchSnapshotStatus();
      this.fetchClusterStats();
    },
    formatNumber(value) {
      const numeric = Number(value || 0);
      return Number.isFinite(numeric) ? numeric.toLocaleString() : '0';
    },
    formatDate(timestamp) {
      return moment.unix(timestamp).format('YYYY-MM-DD HH:mm:ss');
    },
    formatPublishedAt(value) {
      if (!value) {
        return '-';
      }

      const parsed = moment(value);
      return parsed.isValid() ? parsed.format('YYYY-MM-DD HH:mm:ss') : String(value);
    }
  }
};
</script>

<style scoped>
.card {
  border-radius: 0.5rem;
}
.card-header {
  background-color: rgba(0, 0, 0, 0.03);
}
.display-4 {
  font-size: 2.5rem;
  opacity: 0.8;
}
</style>
