<template>
  <div>
    <div class="d-flex justify-content-between align-items-center mb-4">
      <h2 class="h4 mb-0">LLM 流量审计</h2>
      <div class="d-flex gap-2">
        <button class="btn btn-sm btn-outline-secondary" @click="loadStats">
          <i class="bi bi-arrow-clockwise mr-1"></i>刷新
        </button>
        <button
          class="btn btn-sm"
          :class="llmConfig.enabled ? 'btn-success' : 'btn-outline-secondary'"
          @click="showConfigModal = true"
        >
          <i class="bi bi-gear mr-1"></i>配置
        </button>
      </div>
    </div>

    <!-- Stats Cards -->
    <div class="row mb-4">
      <div class="col-md-3 mb-3">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-body">
            <div class="text-muted small mb-1">已分析请求</div>
            <div class="h3 mb-0 text-primary">{{ stats.total_analysed || 0 }}</div>
          </div>
        </div>
      </div>
      <div class="col-md-3 mb-3">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-body">
            <div class="text-muted small mb-1">自动封禁 IP</div>
            <div class="h3 mb-0 text-danger">{{ stats.total_autobanned || 0 }}</div>
          </div>
        </div>
      </div>
      <div class="col-md-3 mb-3">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-body">
            <div class="text-muted small mb-1">待审队列</div>
            <div class="h3 mb-0 text-warning">{{ stats.queue_length || 0 }}</div>
          </div>
        </div>
      </div>
      <div class="col-md-3 mb-3">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-body">
            <div class="text-muted small mb-1">高危 (Critical/High)</div>
            <div class="h3 mb-0 text-danger">
              {{ (stats.by_risk && (stats.by_risk.critical + stats.by_risk.high)) || 0 }}
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Risk Breakdown -->
    <div class="row mb-4" v-if="stats.by_risk">
      <div class="col-md-8 mb-3">
        <div class="card border-0 shadow-sm">
          <div class="card-body">
            <div class="card-title small font-weight-bold text-muted text-uppercase mb-3">风险等级分布</div>
            <div v-for="(label, key) in riskLevels" :key="key" class="mb-2">
              <div class="d-flex justify-content-between small mb-1">
                <span>
                  <span class="badge mr-1" :class="riskBadge[key]">{{ label }}</span>
                </span>
                <span class="text-muted">{{ stats.by_risk[key] || 0 }}</span>
              </div>
              <div class="progress" style="height:6px">
                <div
                  class="progress-bar"
                  :class="riskBarClass[key]"
                  :style="{ width: riskPercent(key) + '%' }"
                ></div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="col-md-4 mb-3">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-body d-flex flex-column justify-content-between">
            <div class="card-title small font-weight-bold text-muted text-uppercase mb-3">队列操作</div>
            <div>
              <div class="form-group">
                <label class="small">手动加入审计队列</label>
                <div class="input-group input-group-sm">
                  <input v-model="manualIp" class="form-control" placeholder="输入 IP 地址" />
                  <div class="input-group-append">
                    <button class="btn btn-primary" @click="queueIp" :disabled="!manualIp">加入</button>
                  </div>
                </div>
              </div>
              <button class="btn btn-sm btn-outline-danger w-100" @click="clearQueue">
                <i class="bi bi-trash mr-1"></i>清空队列
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Verdict History -->
    <div class="card border-0 shadow-sm mb-4">
      <div class="card-body">
        <div class="d-flex justify-content-between align-items-center mb-3">
          <div class="card-title small font-weight-bold text-muted text-uppercase mb-0">裁决历史</div>
          <div class="d-flex align-items-center gap-2">
            <select v-model="riskFilter" class="form-control form-control-sm" style="width:130px" @change="loadVerdicts(true)">
              <option value="all">全部等级</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="benign">Benign</option>
            </select>
            <button class="btn btn-sm btn-outline-danger" @click="clearVerdicts">
              <i class="bi bi-trash"></i>
            </button>
          </div>
        </div>

        <div class="table-responsive">
          <table class="table table-sm table-hover mb-0">
            <thead class="thead-light">
              <tr>
                <th>IP</th>
                <th>风险</th>
                <th>攻击类型</th>
                <th>动作</th>
                <th>置信度</th>
                <th>原因</th>
                <th>时间</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="verdicts.length === 0">
                <td colspan="8" class="text-center text-muted py-4">暂无裁决记录</td>
              </tr>
              <tr v-for="v in verdicts" :key="v.ip + v.analysed_at">
                <td class="text-monospace small">{{ v.ip }}</td>
                <td>
                  <span class="badge" :class="riskBadge[v.risk_level]">{{ v.risk_level }}</span>
                </td>
                <td class="small">{{ v.attack_type }}</td>
                <td>
                  <span class="badge" :class="actionBadge(v.action)">{{ v.action }}</span>
                </td>
                <td class="small">{{ (v.confidence * 100).toFixed(0) }}%</td>
                <td class="small text-muted" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" :title="v.reason">
                  {{ v.reason }}
                </td>
                <td class="small text-muted text-nowrap">{{ formatTime(v.analysed_at) }}</td>
                <td>
                  <button class="btn btn-xs btn-outline-secondary py-0 px-1" @click="clearVerdict(v.ip)">
                    <i class="bi bi-x"></i>
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div v-if="totalVerdicts > pageSize" class="mt-3 d-flex justify-content-between align-items-center">
          <span class="small text-muted">共 {{ totalVerdicts }} 条</span>
          <div>
            <button class="btn btn-sm btn-outline-secondary mr-1" @click="prevPage" :disabled="page === 0">上一页</button>
            <button class="btn btn-sm btn-outline-secondary" @click="nextPage" :disabled="(page + 1) * pageSize >= totalVerdicts">下一页</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Config Modal -->
    <div v-if="showConfigModal" class="modal-backdrop" @click.self="showConfigModal = false">
      <div class="modal-dialog modal-lg">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">LLM 配置</h5>
            <button type="button" class="close" @click="showConfigModal = false">&times;</button>
          </div>
          <div class="modal-body">
            <div class="d-flex justify-content-between align-items-center mb-3">
              <label class="small font-weight-bold mb-0">LLM 提供商组</label>
              <button class="btn btn-sm btn-outline-primary" @click="addProvider">新增提供商</button>
            </div>

            <div v-for="(provider, index) in editConfig.providers" :key="provider.id || index" class="border rounded p-3 mb-3">
              <div class="form-row">
                <div class="form-group col-md-3">
                  <label class="small font-weight-bold">名称</label>
                  <input v-model="provider.name" class="form-control form-control-sm" placeholder="Primary / Fallback" />
                </div>
                <div class="form-group col-md-3">
                  <label class="small font-weight-bold">LLM 提供商</label>
                  <select v-model="provider.provider" class="form-control form-control-sm" @change="handleProviderChange(provider)">
                    <option value="openai">OpenAI 兼容</option>
                    <option value="openai_responses">OpenAI Responses</option>
                    <option value="anthropic">Anthropic Claude</option>
                  </select>
                </div>
                <div class="form-group col-md-3">
                  <label class="small font-weight-bold">模型名称</label>
                  <input v-model="provider.model" class="form-control form-control-sm" placeholder="gpt-4o-mini / gpt-5.4 / claude-haiku-4-5-20251001" />
                </div>
                <div class="form-group col-md-2">
                  <label class="small font-weight-bold">启用</label>
                  <div class="custom-control custom-switch mt-2">
                    <input :id="`llm-provider-enabled-${index}`" v-model="provider.enabled" type="checkbox" class="custom-control-input" />
                    <label class="custom-control-label" :for="`llm-provider-enabled-${index}`">启用</label>
                  </div>
                </div>
                <div class="form-group col-md-1 d-flex align-items-end">
                  <button class="btn btn-sm btn-outline-danger w-100" @click="removeProvider(index)" :disabled="editConfig.providers.length <= 1">删</button>
                </div>
              </div>
              <div class="form-row">
                <div class="form-group" :class="provider.provider !== 'anthropic' ? 'col-md-8' : 'col-md-6'">
                  <label class="small font-weight-bold">API Endpoint</label>
                  <input v-model="provider.api_endpoint" class="form-control form-control-sm" :placeholder="endpointPlaceholderFor(provider)" />
                </div>
                <div class="form-group" :class="provider.provider !== 'anthropic' ? 'col-md-4' : 'col-md-6'">
                  <label class="small font-weight-bold">请求超时 (ms)</label>
                  <input v-model.number="provider.timeout_ms" type="number" min="3000" max="60000" class="form-control form-control-sm" />
                </div>
              </div>
              <div class="form-group mb-0">
                <label class="small font-weight-bold">API Key</label>
                <input
                  v-model="provider.api_key"
                  class="form-control form-control-sm"
                  type="password"
                  :placeholder="provider.api_key_masked || '输入 API Key（留空保持不变）'"
                />
              </div>
            </div>
            <div class="form-row">
              <div class="form-group col-md-4">
                <label class="small font-weight-bold">自动封禁置信度阈值</label>
                <input v-model.number="editConfig.autoban_min_confidence" type="number" step="0.05" min="0.5" max="1" class="form-control form-control-sm" />
                <small class="text-muted">0.5 ~ 1.0，默认 0.75</small>
              </div>
              <div class="form-group col-md-4">
                <label class="small font-weight-bold">批量大小</label>
                <input v-model.number="editConfig.batch_size" type="number" min="1" max="10" class="form-control form-control-sm" />
              </div>
              <div class="form-group col-md-4">
                <label class="small font-weight-bold">调用间隔 (ms)</label>
                <input v-model.number="editConfig.call_delay_ms" type="number" min="100" max="5000" class="form-control form-control-sm" />
              </div>
            </div>
            <div class="form-row">
              <div class="form-group col-md-6">
                <label class="small font-weight-bold">裁决缓存 TTL (秒)</label>
                <input v-model.number="editConfig.verdict_cache_ttl_s" type="number" min="60" max="86400" class="form-control form-control-sm" />
              </div>
              <div class="form-group col-md-6">
                <label class="small font-weight-bold">全局默认超时 (ms)</label>
                <input v-model.number="editConfig.timeout_ms" type="number" min="3000" max="60000" class="form-control form-control-sm" />
              </div>
            </div>
            <div class="form-group">
              <div class="custom-control custom-switch">
                <input type="checkbox" class="custom-control-input" id="llmEnabled" v-model="editConfig.enabled" />
                <label class="custom-control-label" for="llmEnabled">启用 LLM 审计</label>
              </div>
            </div>
            <div class="form-group mb-0">
              <div class="custom-control custom-switch">
                <input type="checkbox" class="custom-control-input" id="llmFailoverEnabled" v-model="editConfig.failover_enabled" />
                <label class="custom-control-label" for="llmFailoverEnabled">启用故障转移</label>
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button class="btn btn-sm btn-outline-secondary mr-2" @click="testConnection" :disabled="testing">
              <span v-if="testing" class="spinner-border spinner-border-sm mr-1"></span>
              {{ testing ? '测试中…' : '测试连接' }}
            </button>
            <button class="btn btn-sm btn-secondary mr-2" @click="showConfigModal = false">取消</button>
            <button class="btn btn-sm btn-primary" @click="saveConfig" :disabled="saving">
              <span v-if="saving" class="spinner-border spinner-border-sm mr-1"></span>
              {{ saving ? '保存中…' : '保存' }}
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios'

const authHeaders = () => {
  const token = localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token')
  return { Authorization: `Bearer ${token}` }
}

export default {
  name: 'LLMAudit',
  data() {
    return {
      stats: {},
      verdicts: [],
      totalVerdicts: 0,
      page: 0,
      pageSize: 20,
      riskFilter: 'all',
      llmConfig: {},
      editConfig: {},
      showConfigModal: false,
      saving: false,
      testing: false,
      manualIp: '',
      riskLevels: {
        critical: 'Critical',
        high: 'High',
        medium: 'Medium',
        low: 'Low',
        benign: 'Benign',
      },
      riskBadge: {
        critical: 'badge-danger',
        high: 'badge-warning',
        medium: 'badge-info',
        low: 'badge-secondary',
        benign: 'badge-success',
      },
      riskBarClass: {
        critical: 'bg-danger',
        high: 'bg-warning',
        medium: 'bg-info',
        low: 'bg-secondary',
        benign: 'bg-success',
      },
    }
  },
  created() {
    this.loadAll()
  },
  computed: {
  },
  methods: {
    buildDefaultProvider() {
      return {
        id: `provider-${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
        name: 'Primary',
        provider: 'openai_responses',
        api_endpoint: 'https://api.openai.com/v1/responses',
        model: 'gpt-5.4',
        api_key: '',
        enabled: true,
        timeout_ms: 15000,
      }
    },
    endpointPlaceholderFor(provider) {
      return provider && provider.provider === 'openai_responses'
        ? 'https://api.openai.com/v1/responses'
        : provider && provider.provider === 'anthropic'
          ? 'https://api.anthropic.com'
          : 'https://api.openai.com/v1'
    },
    async loadAll() {
      await Promise.all([this.loadStats(), this.loadConfig(), this.loadVerdicts(true)])
    },
    async loadStats() {
      try {
        const { data } = await axios.get('/llm/stats', { headers: authHeaders() })
        if (data.success) this.stats = data.data || {}
      } catch (_) {}
    },
    async loadConfig() {
      try {
        const { data } = await axios.get('/llm/config', { headers: authHeaders() })
        if (data.success) {
          this.llmConfig = data.data || {}
          this.editConfig = {
            enabled: true,
            failover_enabled: true,
            providers: [this.buildDefaultProvider()],
            ...this.llmConfig,
            api_key: '',
          }
          if (!Array.isArray(this.editConfig.providers) || this.editConfig.providers.length === 0) {
            this.editConfig.providers = [this.buildDefaultProvider()]
          }
          this.editConfig.providers = this.editConfig.providers.map((provider, index) => ({
            ...this.buildDefaultProvider(),
            name: index === 0 ? 'Primary' : `Fallback ${index}`,
            ...provider,
            api_key: '',
          }))
        }
      } catch (_) {}
    },
    async loadVerdicts(reset) {
      if (reset) this.page = 0
      const offset = this.page * this.pageSize
      try {
        const params = { limit: this.pageSize, offset }
        if (this.riskFilter !== 'all') params.risk = this.riskFilter
        const { data } = await axios.get('/llm/verdicts', { headers: authHeaders(), params })
        if (data.success) {
          this.verdicts = data.data.items || []
          this.totalVerdicts = data.data.total || 0
        }
      } catch (_) {}
    },
    async saveConfig() {
      this.saving = true
      try {
        const payload = { ...this.editConfig }
        payload.providers = (payload.providers || []).map((provider) => {
          const clone = { ...provider }
          if (!clone.api_key) delete clone.api_key
          return clone
        })
        const { data } = await axios.put('/llm/config', payload, { headers: authHeaders() })
        if (data.success) {
          this.llmConfig = data.data || {}
          this.showConfigModal = false
          this.$root.$emit('toast', { level: 'success', message: 'LLM 配置已保存' })
        }
      } catch (e) {
        this.$root.$emit('toast', { level: 'error', message: '保存失败：' + (e.message || '') })
      } finally {
        this.saving = false
      }
    },
    async testConnection() {
      this.testing = true
      try {
        const payload = { ...this.editConfig }
        payload.providers = (payload.providers || []).map((provider) => {
          const clone = { ...provider }
          if (!clone.api_key) delete clone.api_key
          return clone
        })
        const { data } = await axios.post('/llm/test', payload, { headers: authHeaders() })
        if (data.success && data.data && data.data.connected) {
          const providerName = data.data.provider_name || data.data.provider_id || 'provider'
          this.$root.$emit('toast', { level: 'success', message: `连接成功：${providerName}` })
        } else {
          const msg = (data.data && data.data.error) || '连接失败'
          this.$root.$emit('toast', { level: 'error', message: msg })
        }
      } catch (e) {
        this.$root.$emit('toast', { level: 'error', message: '测试出错：' + (e.message || '') })
      } finally {
        this.testing = false
      }
    },
    handleProviderChange(provider) {
      if (!provider) return
      if (provider.provider === 'openai_responses') {
        if (!provider.api_endpoint || provider.api_endpoint === 'https://api.openai.com/v1') {
          provider.api_endpoint = 'https://api.openai.com/v1/responses'
        }
        if (!provider.model || provider.model === 'gpt-4o-mini') {
          provider.model = 'gpt-5.4'
        }
      } else if (provider.provider === 'openai') {
        if (!provider.api_endpoint || provider.api_endpoint === 'https://api.openai.com/v1/responses') {
          provider.api_endpoint = 'https://api.openai.com/v1'
        }
        if (!provider.model || provider.model === 'gpt-5.4') {
          provider.model = 'gpt-4o-mini'
        }
      } else if (provider.provider === 'anthropic') {
        if (!provider.api_endpoint) {
          provider.api_endpoint = 'https://api.anthropic.com'
        }
        if (!provider.model || provider.model === 'gpt-4o-mini' || provider.model === 'gpt-5.4') {
          provider.model = 'claude-haiku-4-5-20251001'
        }
      }
    },
    addProvider() {
      const provider = this.buildDefaultProvider()
      provider.name = `Fallback ${this.editConfig.providers.length}`
      this.editConfig.providers = [...this.editConfig.providers, provider]
    },
    removeProvider(index) {
      if ((this.editConfig.providers || []).length <= 1) return
      this.editConfig.providers = this.editConfig.providers.filter((_, currentIndex) => currentIndex !== index)
    },
    async queueIp() {
      if (!this.manualIp) return
      try {
        const { data } = await axios.post('/llm/queue', { ip: this.manualIp, reason: 'manual_admin_review' }, { headers: authHeaders() })
        if (data.success) {
          this.manualIp = ''
          this.$root.$emit('toast', { level: 'success', message: 'IP 已加入审计队列' })
          await this.loadStats()
        }
      } catch (e) {
        this.$root.$emit('toast', { level: 'error', message: '加入队列失败' })
      }
    },
    async clearQueue() {
      if (!confirm('确认清空审计队列？')) return
      try {
        await axios.delete('/llm/queue', { headers: authHeaders() })
        this.$root.$emit('toast', { level: 'success', message: '队列已清空' })
        await this.loadStats()
      } catch (_) {}
    },
    async clearVerdicts() {
      if (!confirm('确认清空所有裁决历史？')) return
      try {
        await axios.delete('/llm/verdicts', { headers: authHeaders() })
        this.verdicts = []
        this.totalVerdicts = 0
        this.$root.$emit('toast', { level: 'success', message: '裁决历史已清空' })
      } catch (_) {}
    },
    async clearVerdict(ip) {
      try {
        await axios.delete(`/llm/verdict/${encodeURIComponent(ip)}`, { headers: authHeaders() })
        this.verdicts = this.verdicts.filter(v => v.ip !== ip)
      } catch (_) {}
    },
    prevPage() {
      if (this.page > 0) { this.page--; this.loadVerdicts() }
    },
    nextPage() {
      if ((this.page + 1) * this.pageSize < this.totalVerdicts) { this.page++; this.loadVerdicts() }
    },
    riskPercent(key) {
      const total = Object.values(this.stats.by_risk || {}).reduce((a, b) => a + b, 0)
      if (!total) return 0
      return Math.round(((this.stats.by_risk[key] || 0) / total) * 100)
    },
    actionBadge(action) {
      const map = {
        ban_permanent: 'badge-danger',
        ban_24h: 'badge-danger',
        ban_1h: 'badge-warning',
        challenge: 'badge-info',
        log: 'badge-secondary',
        pass: 'badge-success',
      }
      return map[action] || 'badge-secondary'
    },
    formatTime(ts) {
      if (!ts) return '-'
      return new Date(ts).toLocaleString('zh-CN', { hour12: false })
    },
  },
}
</script>

<style scoped>
.modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.5);
  z-index: 1040;
  display: flex;
  align-items: center;
  justify-content: center;
}
.modal-dialog {
  width: 100%;
  max-width: 680px;
  margin: 1rem;
}
.modal-content {
  background: #fff;
  border-radius: 0.5rem;
  overflow: hidden;
}
.gap-2 { gap: 0.5rem; }
.btn-xs { font-size: 0.7rem; }
</style>
