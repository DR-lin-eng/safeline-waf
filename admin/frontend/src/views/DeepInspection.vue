<template>
  <div>
    <div class="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-2">
      <div>
        <h2 class="h4 mb-1">深度包解析</h2>
        <div class="text-muted small">展示请求的分层还原、混淆评分与语义命中特征</div>
      </div>
      <div class="d-flex gap-2">
        <button class="btn btn-sm btn-outline-secondary" @click="refreshAll">
          <i class="bi bi-arrow-clockwise mr-1"></i>刷新
        </button>
      </div>
    </div>

    <div class="row mb-4">
      <div class="col-md-3 mb-3">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-body">
            <div class="text-muted small mb-1">解析记录</div>
            <div class="h3 mb-0 text-primary">{{ stats.total || 0 }}</div>
          </div>
        </div>
      </div>
      <div class="col-md-3 mb-3">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-body">
            <div class="text-muted small mb-1">高混淆请求</div>
            <div class="h3 mb-0 text-danger">{{ stats.high_obfuscation_count || 0 }}</div>
          </div>
        </div>
      </div>
      <div class="col-md-3 mb-3">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-body">
            <div class="text-muted small mb-1">主要攻击类型</div>
            <div class="h6 mb-0 text-dark">{{ topAttackClass }}</div>
          </div>
        </div>
      </div>
      <div class="col-md-3 mb-3">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-body">
            <div class="text-muted small mb-1">最近触发</div>
            <div class="h6 mb-0 text-dark">{{ formatTime(stats.latest_timestamp) }}</div>
          </div>
        </div>
      </div>
    </div>

    <div class="card border-0 shadow-sm mb-4">
      <div class="card-body">
        <div class="row">
          <div class="col-md-2 mb-2">
            <label class="small text-muted mb-1">攻击类型</label>
            <select v-model="filters.attack_class" class="form-control form-control-sm" @change="loadEvents(true)">
              <option value="">全部</option>
              <option v-for="option in attackClassOptions" :key="option" :value="option">{{ option }}</option>
            </select>
          </div>
          <div class="col-md-2 mb-2">
            <label class="small text-muted mb-1">触发原因</label>
            <input v-model.trim="filters.trigger_reason" class="form-control form-control-sm" placeholder="payload_sqli" @keyup.enter="loadEvents(true)" />
          </div>
          <div class="col-md-2 mb-2">
            <label class="small text-muted mb-1">IP</label>
            <input v-model.trim="filters.ip" class="form-control form-control-sm" placeholder="192.168.1.10" @keyup.enter="loadEvents(true)" />
          </div>
          <div class="col-md-3 mb-2">
            <label class="small text-muted mb-1">URI</label>
            <input v-model.trim="filters.uri" class="form-control form-control-sm" placeholder="/login" @keyup.enter="loadEvents(true)" />
          </div>
          <div class="col-md-3 mb-2">
            <label class="small text-muted mb-1">Request ID</label>
            <div class="input-group input-group-sm">
              <input v-model.trim="filters.request_id" class="form-control" placeholder="req_..." @keyup.enter="loadEvents(true)" />
              <div class="input-group-append">
                <button class="btn btn-primary" @click="loadEvents(true)">筛选</button>
                <button class="btn btn-outline-secondary" @click="resetFilters">重置</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="row">
      <div class="col-lg-7 mb-4">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-body">
            <div class="d-flex justify-content-between align-items-center mb-3">
              <div class="card-title small font-weight-bold text-muted text-uppercase mb-0">解析事件</div>
              <span class="small text-muted">共 {{ total }} 条</span>
            </div>

            <div v-if="loading" class="text-center py-5">
              <div class="spinner-border text-primary" role="status"></div>
              <div class="small text-muted mt-2">加载深度解析记录...</div>
            </div>

            <div v-else-if="events.length === 0" class="text-center text-muted py-5">
              暂无解析记录
            </div>

            <div v-else class="table-responsive">
              <table class="table table-sm table-hover mb-0 align-middle">
                <thead class="thead-light">
                  <tr>
                    <th>时间</th>
                    <th>IP / URI</th>
                    <th>分类</th>
                    <th>风险</th>
                    <th>来源</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(item, index) in events" :key="item.request_id || (item.timestamp + '-' + index)" :class="{ 'table-danger': item.is_blocked }">
                    <td class="small text-nowrap text-muted">{{ formatTime(item.timestamp) }}</td>
                    <td>
                      <div class="small text-monospace">{{ item.ip || '-' }}</div>
                      <div class="small text-muted text-truncate inspection-uri" :title="item.uri">{{ item.uri || '-' }}</div>
                    </td>
                    <td>
                      <span class="badge" :class="attackClassBadge(item.attack_class)">{{ item.attack_class || 'unknown' }}</span>
                      <div class="small text-muted mt-1">{{ item.trigger_reason || '-' }}</div>
                    </td>
                    <td>
                      <div class="small">{{ formatPercent(item.confidence) }}</div>
                      <div class="small text-muted">混淆 {{ item.obfusc_score || 0 }}</div>
                    </td>
                    <td>
                      <div class="small">{{ item.source || '-' }}</div>
                      <div class="small text-muted">{{ item.label || '-' }}</div>
                    </td>
                    <td class="text-right">
                      <button class="btn btn-sm btn-outline-secondary" @click="selectEvent(item)">
                        详情
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div v-if="total > pageSize" class="mt-3 d-flex justify-content-between align-items-center">
              <span class="small text-muted">第 {{ page + 1 }} 页</span>
              <div>
                <button class="btn btn-sm btn-outline-secondary mr-1" @click="prevPage" :disabled="page === 0">上一页</button>
                <button class="btn btn-sm btn-outline-secondary" @click="nextPage" :disabled="(page + 1) * pageSize >= total">下一页</button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="col-lg-5 mb-4">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-body" v-if="selectedEvent">
            <div class="d-flex justify-content-between align-items-start mb-3">
              <div>
                <div class="card-title small font-weight-bold text-muted text-uppercase mb-1">解析详情</div>
                <div class="small text-monospace text-muted">{{ selectedEvent.request_id }}</div>
              </div>
              <span class="badge" :class="selectedEvent.is_blocked ? 'badge-danger' : 'badge-success'">
                {{ selectedEvent.is_blocked ? '已阻止' : '已通过' }}
              </span>
            </div>

            <div class="row small mb-3">
              <div class="col-6 mb-2"><strong>IP：</strong>{{ selectedEvent.ip || '-' }}</div>
              <div class="col-6 mb-2"><strong>方法：</strong>{{ selectedEvent.method || '-' }}</div>
              <div class="col-12 mb-2"><strong>URI：</strong>{{ selectedEvent.uri || '-' }}</div>
              <div class="col-6 mb-2"><strong>来源：</strong>{{ selectedEvent.source || '-' }}</div>
              <div class="col-6 mb-2"><strong>标签：</strong>{{ selectedEvent.label || '-' }}</div>
              <div class="col-6 mb-2"><strong>匹配：</strong>{{ selectedEvent.matched_signature || '-' }}</div>
              <div class="col-6 mb-2"><strong>得分：</strong>{{ selectedEvent.score || 0 }}</div>
              <div class="col-6 mb-2"><strong>分类：</strong>{{ selectedEvent.attack_class || '-' }}</div>
              <div class="col-6 mb-2"><strong>置信度：</strong>{{ formatPercent(selectedEvent.confidence) }}</div>
              <div class="col-6 mb-2"><strong>SQL 命中：</strong>{{ selectedEvent.sql_hits || 0 }}</div>
              <div class="col-6 mb-2"><strong>XSS 命中：</strong>{{ selectedEvent.xss_hits || 0 }}</div>
            </div>

            <div class="mb-3">
              <div class="small font-weight-bold text-muted mb-2">编码层</div>
              <div v-if="selectedEvent.encoding_layers && selectedEvent.encoding_layers.length" class="d-flex flex-wrap gap-2">
                <span v-for="(layer, index) in selectedEvent.encoding_layers" :key="layer + index" class="badge badge-light border">{{ layer }}</span>
              </div>
              <div v-else class="small text-muted">未检测到编码展开链路</div>
            </div>

            <div class="mb-3">
              <div class="small font-weight-bold text-muted mb-2">原始 Preview</div>
              <pre class="inspection-pre">{{ selectedEvent.body_preview || '-' }}</pre>
            </div>

            <div>
              <div class="small font-weight-bold text-muted mb-2">标准化 Preview</div>
              <pre class="inspection-pre">{{ selectedEvent.normalized_preview || '-' }}</pre>
            </div>
          </div>

          <div v-else class="card-body d-flex align-items-center justify-content-center text-muted">
            选择一条解析记录查看详情
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios'
import { getApiErrorMessage, shouldHandleLocally } from '../utils/http'

export default {
  name: 'DeepInspection',
  data() {
    return {
      stats: {},
      events: [],
      total: 0,
      page: 0,
      pageSize: 20,
      loading: false,
      selectedEvent: null,
      filters: {
        request_id: '',
        ip: '',
        uri: '',
        trigger_reason: '',
        attack_class: ''
      }
    }
  },
  computed: {
    attackClassOptions() {
      return Object.keys(this.stats.attack_classes || {}).sort()
    },
    topAttackClass() {
      const entries = Object.entries(this.stats.attack_classes || {})
      if (!entries.length) {
        return '暂无数据'
      }
      entries.sort((a, b) => b[1] - a[1])
      return entries[0][0]
    }
  },
  created() {
    this.applyRouteQuery()
    this.refreshAll()
  },
  watch: {
    '$route.query': {
      handler() {
        this.applyRouteQuery()
        this.loadEvents(true)
      }
    }
  },
  methods: {
    applyRouteQuery() {
      this.filters.request_id = String(this.$route.query.request_id || '')
      this.filters.ip = String(this.$route.query.ip || '')
      this.filters.uri = String(this.$route.query.uri || '')
      this.filters.trigger_reason = String(this.$route.query.trigger_reason || '')
      this.filters.attack_class = String(this.$route.query.attack_class || '')
    },
    async refreshAll() {
      await Promise.all([this.loadStats(), this.loadEvents(true)])
    },
    async loadStats() {
      try {
        const { data } = await axios.get('/inspection/stats')
        if (data.success) {
          this.stats = data.data || {}
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '获取深度解析统计失败。'))
        }
      }
    },
    async loadEvents(reset = false) {
      if (reset) {
        this.page = 0
      }

      this.loading = true
      try {
        const params = {
          limit: this.pageSize,
          offset: this.page * this.pageSize
        }

        Object.entries(this.filters).forEach(([key, value]) => {
          if (value) {
            params[key] = value
          }
        })

        const { data } = await axios.get('/inspection/events', { params })
        if (data.success) {
          this.events = data.data.items || []
          this.total = data.data.total || 0

          if (this.filters.request_id) {
            await this.loadEventDetail(this.filters.request_id)
          } else if (this.events.length > 0) {
            this.selectedEvent = this.events[0]
          } else {
            this.selectedEvent = null
          }
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '获取深度解析列表失败。'))
        }
      } finally {
        this.loading = false
      }
    },
    async loadEventDetail(requestId) {
      if (!requestId) {
        return
      }

      if (this.filters && this.filters.request_id) {
        this.selectedEvent = null
      }
      try {
        const { data } = await axios.get(`/inspection/events/${encodeURIComponent(requestId)}`)
        if (data.success) {
          this.selectedEvent = data.data || null
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '获取深度解析详情失败。'))
        }
      }
    },
    async selectEvent(item) {
      this.selectedEvent = item
      if (item && item.request_id) {
        await this.loadEventDetail(item.request_id)
      }
    },
    resetFilters() {
      this.filters = {
        request_id: '',
        ip: '',
        uri: '',
        trigger_reason: '',
        attack_class: ''
      }
      this.$router.replace({ name: 'DeepInspection', query: {} }).catch(() => {})
      this.loadEvents(true)
    },
    prevPage() {
      if (this.page > 0) {
        this.page -= 1
        this.loadEvents()
      }
    },
    nextPage() {
      if ((this.page + 1) * this.pageSize < this.total) {
        this.page += 1
        this.loadEvents()
      }
    },
    formatTime(ts) {
      if (!ts) {
        return '-'
      }
      return new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false })
    },
    formatPercent(value) {
      const number = Number(value || 0)
      return `${Math.round(number * 100)}%`
    },
    attackClassBadge(attackClass) {
      const map = {
        sqli: 'badge-danger',
        xss: 'badge-warning',
        path_traversal: 'badge-info',
        command_injection: 'badge-danger',
        ssrf: 'badge-primary',
        benign: 'badge-success',
        unknown: 'badge-secondary'
      }
      return map[attackClass] || 'badge-secondary'
    }
  }
}
</script>

<style scoped>
.gap-2 {
  gap: 0.5rem;
}

.inspection-uri {
  max-width: 220px;
}

.inspection-pre {
  background: #f8f9fa;
  border: 1px solid #e9ecef;
  border-radius: 0.5rem;
  padding: 0.75rem;
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 220px;
  overflow-y: auto;
}
</style>
