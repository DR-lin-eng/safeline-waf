<template>
  <div class="monitor-page">
    <div class="d-flex justify-content-between align-items-center flex-wrap pt-3 pb-2 mb-3 border-bottom">
      <h1 class="h2">监控大屏</h1>
      <div class="btn-toolbar mb-2 mb-md-0">
        <span class="text-muted mr-3">最近刷新：{{ formatDateTime(lastUpdatedAt) }}</span>
        <button class="btn btn-sm btn-outline-secondary mr-2" @click="refreshAll" :disabled="loading">
          <i class="bi bi-arrow-repeat"></i> 刷新
        </button>
        <button class="btn btn-sm btn-outline-primary" @click="toggleAutoRefresh">
          <i class="bi" :class="autoRefreshEnabled ? 'bi-pause-circle' : 'bi-play-circle'"></i>
          {{ autoRefreshEnabled ? '暂停自动刷新' : '开启自动刷新' }}
        </button>
      </div>
    </div>

    <div v-if="error" class="alert alert-danger" role="alert">
      {{ error }}
    </div>

    <div class="card mb-4" :class="attackStatus.active ? 'border-danger' : 'border-success'">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span>攻击态摘要</span>
        <span class="badge" :class="attackStatus.active ? 'badge-danger' : 'badge-success'">
          {{ attackStatus.active ? '正在被攻击' : '已恢复' }}
        </span>
      </div>
      <div class="card-body">
        <div class="row">
          <div class="col-lg-3 col-md-6 mb-3 mb-lg-0">
            <div class="text-muted small">当前攻击目标</div>
            <div class="font-weight-bold">{{ attackStatus.target_summary.label || '暂无攻击目标' }}</div>
          </div>
          <div class="col-lg-2 col-md-6 mb-3 mb-lg-0">
            <div class="text-muted small">攻击分数</div>
            <div class="font-weight-bold">{{ formatNumber(attackStatus.score) }}</div>
          </div>
          <div class="col-lg-2 col-md-6 mb-3 mb-lg-0">
            <div class="text-muted small">峰值</div>
            <div class="font-weight-bold">{{ formatNumber(attackStatus.peak) }}</div>
          </div>
          <div class="col-lg-2 col-md-6 mb-3 mb-lg-0">
            <div class="text-muted small">CF Shield</div>
            <div class="font-weight-bold" :class="attackStatus.shield_state.active ? 'text-danger' : 'text-success'">
              {{ attackStatus.shield_state.active ? '已开启' : '未开启' }}
            </div>
          </div>
          <div class="col-lg-3 col-md-12">
            <div class="text-muted small">最近攻击时间</div>
            <div class="font-weight-bold">{{ formatDateTime(attackStatus.last_attack_at) }}</div>
          </div>
        </div>
        <div v-if="attackStatus.recent_events.length" class="mt-3 pt-3 border-top">
          <div class="text-muted small mb-2">最近状态变更</div>
          <div
            v-for="event in attackStatus.recent_events.slice(0, 3)"
            :key="`${event.type}-${event.at}`"
            class="small mb-1"
          >
            <strong>{{ formatAttackEvent(event.type) }}</strong>
            <span class="text-muted ml-2">{{ formatDateTime(event.at) }}</span>
            <span v-if="event.score" class="ml-2">分数 {{ formatNumber(event.score) }}</span>
          </div>
        </div>
      </div>
    </div>

    <div class="row mb-4">
      <div class="col-md-2 col-6 mb-3">
        <div class="card metric-card border-primary">
          <div class="card-body">
            <div class="metric-title">总请求</div>
            <div class="metric-value text-primary">{{ formatNumber(overview.totals.total_requests) }}</div>
          </div>
        </div>
      </div>
      <div class="col-md-2 col-6 mb-3">
        <div class="card metric-card border-success">
          <div class="card-body">
            <div class="metric-title">放行请求</div>
            <div class="metric-value text-success">{{ formatNumber(overview.totals.allowed_requests) }}</div>
          </div>
        </div>
      </div>
      <div class="col-md-2 col-6 mb-3">
        <div class="card metric-card border-danger">
          <div class="card-body">
            <div class="metric-title">拦截请求</div>
            <div class="metric-value text-danger">{{ formatNumber(overview.totals.blocked_requests) }}</div>
          </div>
        </div>
      </div>
      <div class="col-md-2 col-6 mb-3">
        <div class="card metric-card border-warning">
          <div class="card-body">
            <div class="metric-title">拦截率</div>
            <div class="metric-value text-warning">{{ formatPercent(overview.totals.block_rate) }}</div>
          </div>
        </div>
      </div>
      <div class="col-md-2 col-6 mb-3">
        <div class="card metric-card border-info">
          <div class="card-body">
            <div class="metric-title">Redis状态</div>
            <div class="metric-value" :class="health.redis.ok ? 'text-success' : 'text-danger'">
              {{ health.redis.ok ? '正常' : '异常' }}
            </div>
            <small class="text-muted">{{ health.redis.latency_ms }} ms</small>
          </div>
        </div>
      </div>
      <div class="col-md-2 col-6 mb-3">
        <div class="card metric-card border-info">
          <div class="card-body">
            <div class="metric-title">Nginx状态</div>
            <div class="metric-value" :class="health.nginx.ok ? 'text-success' : 'text-danger'">
              {{ health.nginx.ok ? '正常' : '异常' }}
            </div>
            <small class="text-muted">{{ health.nginx.latency_ms }} ms</small>
          </div>
        </div>
      </div>
    </div>

    <div class="row mb-4">
      <div class="col-lg-8 mb-3">
        <div class="card h-100">
          <div class="card-header">请求趋势（10秒粒度）</div>
          <div class="card-body">
            <div v-if="trendPoints.length === 0" class="text-muted text-center py-4">暂无趋势数据</div>
            <div v-else>
              <div
                v-for="point in trendPoints"
                :key="point.timestamp"
                class="trend-row"
              >
                <div class="trend-time">{{ formatTime(point.timestamp * 1000) }}</div>
                <div class="trend-bars">
                  <div class="progress trend-progress">
                    <div
                      class="progress-bar bg-primary"
                      :style="{ width: barWidth(point.total_requests) }"
                    ></div>
                  </div>
                  <div class="progress trend-progress mt-1">
                    <div
                      class="progress-bar bg-danger"
                      :style="{ width: barWidth(point.blocked_requests) }"
                    ></div>
                  </div>
                </div>
                <div class="trend-values">
                  <span class="text-primary">{{ formatNumber(point.total_requests) }}</span> /
                  <span class="text-danger">{{ formatNumber(point.blocked_requests) }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="col-lg-4 mb-3">
        <div class="card h-100">
          <div class="card-header">系统信息</div>
          <div class="card-body">
            <div class="mb-2"><strong>主机名：</strong>{{ overview.system.backend_hostname || '-' }}</div>
            <div class="mb-2"><strong>PID：</strong>{{ overview.system.backend_pid || '-' }}</div>
            <div class="mb-2"><strong>后端内存：</strong>{{ formatNumber(overview.system.backend_memory_mb) }} MB</div>
            <div class="mb-2"><strong>后端运行：</strong>{{ formatNumber(overview.system.backend_uptime_seconds) }} 秒</div>
            <div class="mb-2"><strong>LoadAvg：</strong>{{ formatLoad(overview.system.backend_loadavg) }}</div>
            <hr />
            <div class="small text-muted">
              数据来源：{{ overview.source.nginx_metrics_ok ? 'Nginx + Redis' : 'Redis(部分)'}}
            </div>
            <div v-if="!overview.source.nginx_metrics_ok" class="small text-danger mt-2">
              {{ formatNginxError(overview.source.nginx_metrics_error) }}
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="row mb-4">
      <div class="col-lg-3 col-md-6 mb-3">
        <div class="card h-100">
          <div class="card-header">Top Sites</div>
          <div class="card-body p-0">
            <table class="table table-sm mb-0">
              <tbody>
                <tr v-for="item in overview.top.sites" :key="`site-${item.name}`">
                  <td class="text-truncate" style="max-width: 180px;">{{ item.name }}</td>
                  <td class="text-right">{{ formatNumber(item.score) }}</td>
                </tr>
                <tr v-if="overview.top.sites.length === 0"><td class="text-center text-muted" colspan="2">暂无</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
      <div class="col-lg-3 col-md-6 mb-3">
        <div class="card h-100">
          <div class="card-header">Top IPs</div>
          <div class="card-body p-0">
            <table class="table table-sm mb-0">
              <tbody>
                <tr v-for="item in overview.top.ips" :key="`ip-${item.name}`">
                  <td class="text-truncate" style="max-width: 180px;">{{ item.name }}</td>
                  <td class="text-right">{{ formatNumber(item.score) }}</td>
                </tr>
                <tr v-if="overview.top.ips.length === 0"><td class="text-center text-muted" colspan="2">暂无</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
      <div class="col-lg-3 col-md-6 mb-3">
        <div class="card h-100">
          <div class="card-header">Top URIs</div>
          <div class="card-body p-0">
            <table class="table table-sm mb-0">
              <tbody>
                <tr v-for="item in overview.top.uris" :key="`uri-${item.name}`">
                  <td class="text-truncate" style="max-width: 180px;">{{ item.name }}</td>
                  <td class="text-right">{{ formatNumber(item.score) }}</td>
                </tr>
                <tr v-if="overview.top.uris.length === 0"><td class="text-center text-muted" colspan="2">暂无</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
      <div class="col-lg-3 col-md-6 mb-3">
        <div class="card h-100">
          <div class="card-header">Top Block Reasons</div>
          <div class="card-body p-0">
            <table class="table table-sm mb-0">
              <tbody>
                <tr v-for="item in overview.top.block_reasons" :key="`reason-${item.name}`">
                  <td class="text-truncate" style="max-width: 180px;">{{ item.name }}</td>
                  <td class="text-right">{{ formatNumber(item.score) }}</td>
                </tr>
                <tr v-if="overview.top.block_reasons.length === 0"><td class="text-center text-muted" colspan="2">暂无</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">实时日志（最近 {{ overview.recent_logs.length }} 条）</div>
      <div class="card-body p-0">
        <div class="table-responsive">
          <table class="table table-sm table-hover mb-0">
            <thead>
              <tr>
                <th>时间</th>
                <th>IP</th>
                <th>方法</th>
                <th>URI</th>
                <th>结果</th>
                <th>原因</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="(log, index) in overview.recent_logs"
                :key="`log-${index}`"
                :class="{ 'table-danger': log.is_blocked }"
              >
                <td>{{ formatDateTime(log.timestamp * 1000) }}</td>
                <td>{{ log.client_ip || '-' }}</td>
                <td>{{ log.method || '-' }}</td>
                <td class="text-truncate" style="max-width: 420px;">{{ log.uri || '-' }}</td>
                <td>
                  <span class="badge" :class="log.is_blocked ? 'badge-danger' : 'badge-success'">
                    {{ log.is_blocked ? '拦截' : '放行' }}
                  </span>
                </td>
                <td>{{ log.reason || '-' }}</td>
              </tr>
              <tr v-if="overview.recent_logs.length === 0">
                <td colspan="6" class="text-center text-muted py-3">暂无日志</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios';

function getEmptyOverview() {
  return {
    totals: {
      total_requests: 0,
      blocked_requests: 0,
      allowed_requests: 0,
      block_rate: 0
    },
    trend: [],
    sites: {},
    block_reasons: {},
    top: {
      sites: [],
      ips: [],
      uris: [],
      block_reasons: []
    },
    recent_logs: [],
    source: {
      nginx_metrics_ok: false,
      nginx_metrics_error: null
    },
    system: {
      backend_uptime_seconds: 0,
      backend_pid: null,
      backend_memory_mb: 0,
      backend_loadavg: [],
      backend_hostname: ''
    }
  };
}

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
    },
    recent_events: [],
    notifications: []
  };
}

export default {
  name: 'Monitor',
  data() {
    return {
      loading: false,
      error: '',
      lastUpdatedAt: 0,
      autoRefreshEnabled: true,
      autoTimer: null,
      overview: getEmptyOverview(),
      attackStatus: getEmptyAttackStatus(),
      shownAttackNotifications: {},
      health: {
        redis: { ok: false, latency_ms: 0 },
        nginx: { ok: false, latency_ms: 0 }
      }
    };
  },
  computed: {
    trendPoints() {
      const points = Array.isArray(this.overview.trend) ? this.overview.trend : [];
      if (points.length <= 24) {
        return points;
      }
      return points.slice(points.length - 24);
    },
    maxTrendValue() {
      const maxValue = this.trendPoints.reduce((max, point) => {
        const value = Number(point.total_requests || 0);
        return value > max ? value : max;
      }, 0);
      return maxValue > 0 ? maxValue : 1;
    }
  },
  created() {
    this.refreshAll();
    this.startAutoRefresh();
  },
  beforeDestroy() {
    this.stopAutoRefresh();
  },
  methods: {
    async refreshAll() {
      this.loading = true;
      this.error = '';
      try {
        const [overviewResp, healthResp, attackResp] = await Promise.all([
          axios.get('/monitor/overview', { params: { limit: 20 } }),
          axios.get('/monitor/health'),
          axios.get('/monitor/attack-status', { params: { limit: 20 } })
        ]);

        if (overviewResp.data && overviewResp.data.success) {
          this.overview = overviewResp.data.data || getEmptyOverview();
          this.lastUpdatedAt = Date.now();
        } else {
          this.error = (overviewResp.data && overviewResp.data.message) || '获取监控数据失败';
        }

        if (healthResp.data && healthResp.data.data) {
          this.health = healthResp.data.data;
        }

        if (attackResp.data && attackResp.data.success) {
          this.attackStatus = attackResp.data.data || getEmptyAttackStatus();
          this.showAttackNotifications(this.attackStatus.notifications);
        }
      } catch (error) {
        this.error = (error.response && error.response.data && error.response.data.message) || '获取监控数据失败';
      } finally {
        this.loading = false;
      }
    },
    startAutoRefresh() {
      this.stopAutoRefresh();
      this.autoTimer = setInterval(() => {
        if (this.autoRefreshEnabled) {
          this.refreshAll();
        }
      }, 5000);
    },
    stopAutoRefresh() {
      if (this.autoTimer) {
        clearInterval(this.autoTimer);
        this.autoTimer = null;
      }
    },
    toggleAutoRefresh() {
      this.autoRefreshEnabled = !this.autoRefreshEnabled;
    },
    showAttackNotifications(notifications) {
      if (!Array.isArray(notifications)) {
        return;
      }

      notifications.forEach((item) => {
        if (!item || !item.key || this.shownAttackNotifications[item.key]) {
          return;
        }

        this.shownAttackNotifications = {
          ...this.shownAttackNotifications,
          [item.key]: true
        };

        const level = item.level || 'info';
        const message = item.message || '攻击状态已更新';
        if (this.$toast && typeof this.$toast[level] === 'function') {
          this.$toast[level](message);
        } else if (this.$toast && typeof this.$toast.info === 'function') {
          this.$toast.info(message);
        }
      });
    },
    formatAttackEvent(type) {
      if (type === 'activate') {
        return '进入攻击态';
      }
      if (type === 'deactivate') {
        return '攻击恢复';
      }
      return type || '状态更新';
    },
    formatNumber(value) {
      const number = Number(value || 0);
      return Number.isFinite(number) ? number.toLocaleString() : '0';
    },
    formatPercent(value) {
      const number = Number(value || 0);
      if (!Number.isFinite(number)) {
        return '0.00%';
      }
      return `${(number * 100).toFixed(2)}%`;
    },
    formatLoad(loadavg) {
      if (!Array.isArray(loadavg) || loadavg.length === 0) {
        return '-';
      }
      return loadavg.map((item) => Number(item || 0).toFixed(2)).join(' / ');
    },
    barWidth(value) {
      const number = Number(value || 0);
      const percent = (number / this.maxTrendValue) * 100;
      return `${Math.max(2, Math.min(100, percent))}%`;
    },
    formatTime(timestamp) {
      if (!timestamp) {
        return '-';
      }
      const date = new Date(timestamp);
      return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
    },
    formatDateTime(timestamp) {
      if (!timestamp) {
        return '-';
      }
      const date = new Date(timestamp);
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${this.formatTime(timestamp)}`;
    },
    formatNginxError(error) {
      if (!error) {
        return '';
      }
      if (typeof error === 'string') {
        return error;
      }
      if (error.message) {
        return error.message;
      }
      try {
        return JSON.stringify(error);
      } catch (_) {
        return 'unknown nginx metrics error';
      }
    }
  }
};
</script>

<style scoped>
.metric-card {
  height: 100%;
}

.metric-title {
  color: #6c757d;
  font-size: 0.9rem;
}

.metric-value {
  font-size: 1.5rem;
  font-weight: 700;
}

.trend-row {
  display: flex;
  align-items: center;
  margin-bottom: 0.45rem;
}

.trend-time {
  width: 90px;
  font-size: 0.8rem;
  color: #6c757d;
}

.trend-bars {
  flex: 1;
}

.trend-progress {
  height: 7px;
}

.trend-values {
  width: 100px;
  text-align: right;
  font-size: 0.85rem;
}
</style>
