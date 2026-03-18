<template>
  <div class="ml-training">
    <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
      <h1 class="h2"><i class="bi bi-database mr-2"></i>训练数据</h1>
      <button class="btn btn-sm btn-outline-secondary" @click="loadData" :disabled="loading">
        <i class="bi bi-arrow-repeat"></i> 刷新
      </button>
    </div>

    <div v-if="loading" class="text-center py-5">
      <div class="spinner-border text-primary" role="status"></div>
    </div>

    <template v-else>
      <!-- 统计卡片 -->
      <div class="row mb-4">
        <div class="col-md-4">
          <div class="card text-white bg-primary mb-3">
            <div class="card-body">
              <h6 class="card-title">总样本数（7天）</h6>
              <h4 class="card-text">{{ stats.total.toLocaleString() }}</h4>
            </div>
          </div>
        </div>
        <div class="col-md-4">
          <div class="card text-white bg-success mb-3">
            <div class="card-body">
              <h6 class="card-title">良性样本</h6>
              <h4 class="card-text">{{ stats.total_benign.toLocaleString() }}</h4>
            </div>
          </div>
        </div>
        <div class="col-md-4">
          <div class="card text-white bg-danger mb-3">
            <div class="card-body">
              <h6 class="card-title">攻击样本</h6>
              <h4 class="card-text">{{ stats.total_attack.toLocaleString() }}</h4>
            </div>
          </div>
        </div>
      </div>

      <!-- 每日分布 -->
      <div class="card mb-4">
        <div class="card-header"><i class="bi bi-calendar3 mr-2"></i>每日样本分布（近7天）</div>
        <div class="card-body p-0">
          <div class="table-responsive">
            <table class="table table-sm table-hover mb-0">
              <thead class="thead-light">
                <tr>
                  <th>日期</th>
                  <th>良性</th>
                  <th>攻击</th>
                  <th>占比</th>
                  <th>导出</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="day in stats.by_day" :key="day.date">
                  <td>{{ day.date }}</td>
                  <td>{{ day.benign.toLocaleString() }}</td>
                  <td>{{ day.attack.toLocaleString() }}</td>
                  <td>
                    <div class="progress" style="height:14px; width:120px;">
                      <div class="progress-bar bg-success"
                        :style="{width: attackRatio(day) + '%'}"
                        :title="`攻击占比 ${attackRatio(day)}%`">
                      </div>
                    </div>
                    <small class="text-muted">{{ attackRatio(day) }}% 攻击</small>
                  </td>
                  <td>
                    <div class="btn-group btn-group-sm">
                      <button class="btn btn-outline-secondary"
                        @click="exportSamples(day.date, 'benign')"
                        :disabled="day.benign === 0" title="导出良性样本">
                        <i class="bi bi-download"></i> 良性
                      </button>
                      <button class="btn btn-outline-danger"
                        @click="exportSamples(day.date, 'attack')"
                        :disabled="day.attack === 0" title="导出攻击样本">
                        <i class="bi bi-download"></i> 攻击
                      </button>
                    </div>
                  </td>
                </tr>
                <tr v-if="!stats.by_day || !stats.by_day.length">
                  <td colspan="5" class="text-center text-muted py-3">暂无采样数据</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- 采样说明 -->
      <div class="card mb-4">
        <div class="card-header"><i class="bi bi-info-circle mr-2"></i>采样策略说明</div>
        <div class="card-body">
          <ul class="mb-0 text-muted small">
            <li>攻击请求（WAF 拦截）：<strong>100% 采样</strong>，保存到 Redis 并按日期分类存储</li>
            <li>良性请求（正常放行）：<strong>1% 随机采样</strong>，用于平衡训练集</li>
            <li>样本保留：<strong>7天</strong>（到期自动清理）</li>
            <li>每类每日最多保存：<strong>50,000 条</strong>（超出后 FIFO 丢弃最旧记录）</li>
            <li>采样功能需要在环境变量中设置 <code>ML_ENABLED=true</code> 并激活 ML 模型</li>
          </ul>
        </div>
      </div>
    </template>
  </div>
</template>

<script>
import axios from 'axios'
import toast from '../toast'

export default {
  name: 'MLTraining',
  data() {
    return {
      loading: true,
      stats: { total: 0, total_benign: 0, total_attack: 0, by_day: [] },
    }
  },
  mounted() {
    this.loadData()
  },
  methods: {
    async loadData() {
      this.loading = true
      try {
        const res = await axios.get('/ml/samples', { params: { days: 7 } })
        this.stats = res.data.data || this.stats
      } catch (err) {
        toast.error('加载数据失败: ' + (err.response?.data?.message || err.message))
      } finally {
        this.loading = false
      }
    },
    attackRatio(day) {
      const total = day.benign + day.attack
      if (total === 0) return 0
      return Math.round((day.attack / total) * 100)
    },
    exportSamples(date, label) {
      const token = localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token')
      const url = `/safeline-admin-api/ml/samples/${date}/export?label=${label}&limit=5000`
      // Trigger download via a temporary anchor
      const a = document.createElement('a')
      a.href = url
      a.download = `samples-${date}-${label}.ndjson`
      // Append auth header is not possible for direct download; use fetch instead
      fetch(url, { headers: { Authorization: `Bearer ${token}` } })
        .then(r => r.blob())
        .then(blob => {
          const bUrl = URL.createObjectURL(blob)
          a.href = bUrl
          document.body.appendChild(a)
          a.click()
          URL.revokeObjectURL(bUrl)
          document.body.removeChild(a)
        })
        .catch(err => toast.error('导出失败: ' + err.message))
    },
  },
}
</script>
