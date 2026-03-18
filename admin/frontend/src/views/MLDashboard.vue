<template>
  <div class="ml-dashboard">
    <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
      <h1 class="h2"><i class="bi bi-cpu mr-2"></i>ML 分析仪表盘</h1>
      <div class="btn-toolbar mb-2 mb-md-0">
        <button class="btn btn-sm btn-outline-secondary mr-2" @click="loadData" :disabled="loading">
          <i class="bi bi-arrow-repeat"></i> 刷新
        </button>
      </div>
    </div>

    <div v-if="loading" class="text-center py-5">
      <div class="spinner-border text-primary" role="status"></div>
      <p class="mt-2 text-muted">加载中...</p>
    </div>

    <template v-else>
      <!-- 状态卡片 -->
      <div class="row mb-4">
        <div class="col-md-3">
          <div class="card mb-3" :class="status.active_version ? 'border-success' : 'border-warning'">
            <div class="card-body">
              <h6 class="card-title text-muted">当前模型</h6>
              <h5 class="card-text font-weight-bold">
                <span v-if="status.active_version" class="text-success">
                  <i class="bi bi-check-circle-fill mr-1"></i>{{ status.active_version }}
                </span>
                <span v-else class="text-warning">
                  <i class="bi bi-exclamation-triangle-fill mr-1"></i>未加载
                </span>
              </h5>
            </div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card text-white bg-primary mb-3">
            <div class="card-body">
              <h6 class="card-title">总预测数</h6>
              <h4 class="card-text">{{ metrics.predictions_total.toLocaleString() }}</h4>
            </div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card text-white bg-danger mb-3">
            <div class="card-body">
              <h6 class="card-title">攻击检测数</h6>
              <h4 class="card-text">{{ metrics.predictions_attack.toLocaleString() }}</h4>
            </div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card text-white bg-info mb-3">
            <div class="card-body">
              <h6 class="card-title">平均推理延迟</h6>
              <h4 class="card-text">{{ metrics.avg_latency_ms }} ms</h4>
            </div>
          </div>
        </div>
      </div>

      <!-- Canary 控制 -->
      <div class="card mb-4">
        <div class="card-header d-flex justify-content-between align-items-center">
          <span><i class="bi bi-sliders mr-2"></i>Canary 流量控制</span>
          <span class="badge badge-info">当前: {{ status.canary_pct }}%</span>
        </div>
        <div class="card-body">
          <p class="text-muted small mb-3">
            控制经过 ML 引擎处理的流量比例（0% = 全部关闭，100% = 全部启用）。
          </p>
          <div class="form-row align-items-center">
            <div class="col-auto">
              <label class="mb-0">ML 流量比例</label>
            </div>
            <div class="col-md-4">
              <input type="range" class="form-control-range mx-3" min="0" max="100" step="5"
                v-model.number="canaryInput" />
            </div>
            <div class="col-auto">
              <span class="font-weight-bold">{{ canaryInput }}%</span>
            </div>
            <div class="col-auto">
              <button class="btn btn-sm btn-primary ml-2" @click="setCanary" :disabled="savingCanary">
                <span v-if="savingCanary" class="spinner-border spinner-border-sm mr-1"></span>
                应用
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- 预测趋势 -->
      <div class="card mb-4">
        <div class="card-header"><i class="bi bi-bar-chart-line mr-2"></i>近10分钟预测趋势（每10秒）</div>
        <div class="card-body p-2">
          <div v-if="metrics.trend && metrics.trend.length" class="trend-chart">
            <div class="trend-bars d-flex align-items-end" style="height:100px; gap:2px;">
              <div
                v-for="(bucket, i) in metrics.trend"
                :key="i"
                class="trend-bar-wrap flex-fill d-flex flex-column align-items-center justify-content-end"
                :title="`${new Date(bucket.ts * 1000).toLocaleTimeString()} | 总: ${bucket.total} 攻: ${bucket.attacks}`"
              >
                <div class="bg-danger" :style="{height: barHeight(bucket.attacks) + 'px', minWidth: '4px', width:'100%'}"></div>
                <div class="bg-primary" :style="{height: barHeight(bucket.total - bucket.attacks) + 'px', minWidth: '4px', width:'100%'}"></div>
              </div>
            </div>
            <div class="d-flex justify-content-between mt-1">
              <small class="text-muted">10分钟前</small>
              <small class="text-muted">现在</small>
            </div>
            <div class="mt-1">
              <span class="badge badge-primary mr-2">■ 正常</span>
              <span class="badge badge-danger">■ 攻击</span>
            </div>
          </div>
          <p v-else class="text-muted text-center py-3">暂无趋势数据</p>
        </div>
      </div>

      <!-- 集群 ML 状态 -->
      <div class="card mb-4">
        <div class="card-header"><i class="bi bi-diagram-3 mr-2"></i>集群 ML 状态</div>
        <div class="card-body p-0">
          <div v-if="cluster.nodes && cluster.nodes.length" class="table-responsive">
            <table class="table table-sm table-hover mb-0">
              <thead class="thead-light">
                <tr>
                  <th>节点</th>
                  <th>状态</th>
                  <th>已加载模型</th>
                  <th>加载时间</th>
                  <th>同步状态</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="node in cluster.nodes" :key="node.node_id">
                  <td>{{ node.hostname || node.node_id }}</td>
                  <td>
                    <span class="badge" :class="node.status === 'online' ? 'badge-success' : 'badge-secondary'">
                      {{ node.status === 'online' ? '在线' : '离线' }}
                    </span>
                  </td>
                  <td><code>{{ node.ml_version || '未加载' }}</code></td>
                  <td>{{ node.ml_loaded_at ? new Date(parseInt(node.ml_loaded_at)).toLocaleString() : '-' }}</td>
                  <td>
                    <span v-if="node.ml_version === cluster.active_version" class="text-success">
                      <i class="bi bi-check-circle-fill"></i> 同步
                    </span>
                    <span v-else-if="cluster.active_version" class="text-warning">
                      <i class="bi bi-exclamation-circle-fill"></i> 待同步
                    </span>
                    <span v-else class="text-muted">-</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <p v-else class="text-muted text-center py-3">暂无节点数据</p>
        </div>
      </div>
    </template>
  </div>
</template>

<script>
import axios from 'axios'
import toast from '../toast'

export default {
  name: 'MLDashboard',
  data() {
    return {
      loading: true,
      savingCanary: false,
      canaryInput: 100,
      status: { active_version: null, previous_version: null, canary_pct: 100 },
      metrics: { predictions_total: 0, predictions_attack: 0, predictions_benign: 0, avg_latency_ms: 0, trend: [] },
      cluster: { nodes: [], active_version: null, in_sync: 0, total: 0 },
    }
  },
  mounted() {
    this.loadData()
  },
  methods: {
    async loadData() {
      this.loading = true
      try {
        const [statusRes, metricsRes, clusterRes] = await Promise.all([
          axios.get('/ml/status'),
          axios.get('/ml/metrics'),
          axios.get('/ml/cluster'),
        ])
        this.status  = statusRes.data.data  || this.status
        this.metrics = metricsRes.data.data || this.metrics
        this.cluster = clusterRes.data.data || this.cluster
        this.canaryInput = this.status.canary_pct
      } catch (err) {
        toast.error('加载数据失败: ' + (err.response?.data?.message || err.message))
      } finally {
        this.loading = false
      }
    },
    async setCanary() {
      this.savingCanary = true
      try {
        await axios.post('/ml/canary', { percentage: this.canaryInput })
        this.status.canary_pct = this.canaryInput
        toast.success(`Canary 已设置为 ${this.canaryInput}%`)
      } catch (err) {
        toast.error('设置失败: ' + (err.response?.data?.message || err.message))
      } finally {
        this.savingCanary = false
      }
    },
    barHeight(val) {
      if (!this.metrics.trend || !this.metrics.trend.length) return 0
      const maxVal = Math.max(...this.metrics.trend.map(b => b.total), 1)
      return Math.round((val / maxVal) * 90)
    },
  },
}
</script>

<style scoped>
.trend-bars { overflow: hidden; }
</style>
