<template>
  <div>
    <div class="d-flex justify-content-between align-items-center mb-4">
      <h2 class="h4 mb-0">Cloudflare 五秒盾</h2>
      <div class="d-flex gap-2">
        <button class="btn btn-sm btn-outline-secondary" @click="loadAll">
          <i class="bi bi-arrow-clockwise mr-1"></i>刷新
        </button>
        <button
          class="btn btn-sm"
          :class="cfConfig.enabled ? 'btn-warning' : 'btn-outline-secondary'"
          @click="showConfigModal = true"
        >
          <i class="bi bi-gear mr-1"></i>配置
        </button>
      </div>
    </div>

    <!-- Status Cards -->
    <div class="row mb-4">
      <!-- Shield Status -->
      <div class="col-md-3 mb-3">
        <div class="card border-0 shadow-sm h-100" :class="shieldActive ? 'border-danger' : ''">
          <div class="card-body">
            <div class="text-muted small mb-1">防护状态</div>
            <div class="d-flex align-items-center">
              <span
                class="badge mr-2"
                :class="shieldActive ? 'badge-danger' : 'badge-success'"
                style="font-size:0.85rem; padding:0.4em 0.7em;"
              >
                {{ shieldActive ? '🔴 攻击模式' : '🟢 正常' }}
              </span>
            </div>
            <div class="text-muted small mt-2" v-if="shieldActive && status.state && status.state.activated_at">
              激活于 {{ formatTime(status.state.activated_at) }}
            </div>
          </div>
        </div>
      </div>

      <!-- Attack Score -->
      <div class="col-md-3 mb-3">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-body">
            <div class="text-muted small mb-1">当前攻击分值</div>
            <div class="h3 mb-0" :class="scoreColor">{{ status.score || 0 }}</div>
            <div class="progress mt-2" style="height:4px;">
              <div
                class="progress-bar"
                :class="scoreBarClass"
                :style="{ width: scorePercent + '%' }"
              ></div>
            </div>
            <div class="text-muted small mt-1">阈值: {{ cfConfig.activate_threshold || 50 }}</div>
          </div>
        </div>
      </div>

      <!-- Peak Score -->
      <div class="col-md-3 mb-3">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-body">
            <div class="text-muted small mb-1">历史峰值</div>
            <div class="h3 mb-0 text-warning">{{ status.peak || 0 }}</div>
            <div class="text-muted small mt-1" v-if="status.last_attack_at">
              最近攻击: {{ formatTime(status.last_attack_at) }}
            </div>
            <div class="text-muted small mt-1" v-else>暂无攻击记录</div>
          </div>
        </div>
      </div>

      <!-- CF Enabled -->
      <div class="col-md-3 mb-3">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-body">
            <div class="text-muted small mb-1">自动联动</div>
            <div class="h5 mb-0" :class="cfConfig.enabled ? 'text-success' : 'text-muted'">
              {{ cfConfig.enabled ? '已启用' : '已禁用' }}
            </div>
            <div class="text-muted small mt-1">
              {{ cfConfig.zone_ids && cfConfig.zone_ids.length ? cfConfig.zone_ids.length + ' 个 Zone' : '未配置 Zone' }}
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Manual Controls -->
    <div class="card border-0 shadow-sm mb-4">
      <div class="card-body">
        <h6 class="card-title mb-3">手动控制</h6>
        <div class="d-flex gap-2 align-items-center">
          <button
            class="btn btn-danger"
            :disabled="shieldActive || !cfConfig.enabled || ctrlLoading"
            @click="enableShield"
          >
            <i class="bi bi-shield-fill-exclamation mr-1"></i>
            {{ ctrlLoading && ctrlAction === 'enable' ? '启用中...' : '启用五秒盾' }}
          </button>
          <button
            class="btn btn-success"
            :disabled="!shieldActive || !cfConfig.enabled || ctrlLoading"
            @click="disableShield"
          >
            <i class="bi bi-shield-check mr-1"></i>
            {{ ctrlLoading && ctrlAction === 'disable' ? '禁用中...' : '关闭五秒盾' }}
          </button>
          <span class="text-muted small ml-2" v-if="!cfConfig.enabled">
            请先在配置中启用并保存 API Token
          </span>
          <span class="text-muted small ml-2" v-else-if="shieldActive">
            五秒盾激活中 — 点击"关闭"可手动解除
          </span>
          <span class="text-muted small ml-2" v-else>
            五秒盾待机中 — 可手动启用或等待自动触发
          </span>
        </div>
        <div v-if="ctrlError" class="alert alert-danger mt-3 mb-0 py-2">{{ ctrlError }}</div>
        <div v-if="ctrlSuccess" class="alert alert-success mt-3 mb-0 py-2">{{ ctrlSuccess }}</div>
      </div>
    </div>

    <!-- Activation History -->
    <div class="card border-0 shadow-sm">
      <div class="card-body">
        <div class="d-flex justify-content-between align-items-center mb-3">
          <h6 class="card-title mb-0">激活历史</h6>
          <button class="btn btn-sm btn-outline-danger" @click="clearHistory" :disabled="historyLoading">
            <i class="bi bi-trash mr-1"></i>清空历史
          </button>
        </div>
        <div v-if="history.length === 0" class="text-muted text-center py-4">暂无激活记录</div>
        <div v-else class="table-responsive">
          <table class="table table-sm table-hover mb-0">
            <thead>
              <tr>
                <th>类型</th>
                <th>时间</th>
                <th>原因</th>
                <th>错误</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(item, idx) in history" :key="idx">
                <td>
                  <span class="badge" :class="item.type === 'activate' ? 'badge-danger' : 'badge-success'">
                    {{ item.type === 'activate' ? '🔴 激活' : '🟢 关闭' }}
                  </span>
                </td>
                <td class="text-nowrap">{{ formatTime(item.at) }}</td>
                <td>
                  <small class="text-muted">{{ item.reason || '-' }}</small>
                </td>
                <td>
                  <small v-if="item.errors && item.errors.length" class="text-danger">
                    {{ item.errors.length }} 个错误
                  </small>
                  <small v-else class="text-muted">-</small>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="text-muted small mt-2" v-if="historyTotal > history.length">
          显示最近 {{ history.length }} / {{ historyTotal }} 条记录
        </div>
      </div>
    </div>

    <!-- Config Modal -->
    <div v-if="showConfigModal" class="modal-backdrop" @click.self="showConfigModal = false">
      <div class="card shadow-lg" style="width:560px; max-height:90vh; overflow-y:auto;">
        <div class="card-body">
          <div class="d-flex justify-content-between align-items-center mb-3">
            <h6 class="mb-0">Cloudflare 五秒盾配置</h6>
            <button class="btn btn-sm btn-outline-secondary" @click="showConfigModal = false">✕</button>
          </div>

          <div class="form-group">
            <label class="font-weight-bold">API Token <span class="text-muted small font-weight-normal">(Cloudflare Zone：编辑权限)</span></label>
            <div class="input-group">
              <input
                :type="showToken ? 'text' : 'password'"
                class="form-control"
                v-model="editConfig.api_token"
                placeholder="留空保持不变"
                autocomplete="off"
              />
              <div class="input-group-append">
                <button class="btn btn-outline-secondary" type="button" @click="showToken = !showToken">
                  <i :class="showToken ? 'bi bi-eye-slash' : 'bi bi-eye'"></i>
                </button>
              </div>
            </div>
            <small class="text-muted">
              <span v-if="cfConfig.api_token_masked">当前: {{ cfConfig.api_token_masked }}</span>
              <span v-else>尚未配置</span>
            </small>
          </div>

          <div class="form-row align-items-end">
            <div class="form-group col-md-6">
              <label class="font-weight-bold">认证类型</label>
              <select class="form-control" v-model="editConfig.auth_type">
                <option value="token">API Token (Bearer)</option>
                <option value="global_key">Global API Key</option>
              </select>
              <small class="text-muted">Global API Key 需要填写 X-Auth-Email 和 X-Auth-Key。</small>
            </div>
            <div class="form-group col-md-6" v-if="editConfig.auth_type === 'global_key'">
              <label class="font-weight-bold">Auth Email</label>
              <input
                type="email"
                class="form-control"
                v-model.trim="editConfig.auth_email"
                autocomplete="off"
                placeholder="输入与 Global Key 配套的邮箱"
              />
              <small class="text-muted">用来生成 `X-Auth-Email` 头，Global Key 必须填写。</small>
            </div>
          </div>

          <div class="form-group">
            <label class="font-weight-bold">Zone ID 列表</label>
            <div class="d-flex gap-2 mb-2">
              <button class="btn btn-sm btn-outline-primary" @click="fetchZones" :disabled="zonesLoading">
                <i class="bi bi-cloud-download mr-1"></i>
                {{ zonesLoading ? '获取中...' : '从 CF 账号获取' }}
              </button>
            </div>
            <div v-if="availableZones.length > 0" class="mb-2">
              <div
                v-for="z in availableZones"
                :key="z.id"
                class="form-check"
              >
                <input
                  type="checkbox"
                  class="form-check-input"
                  :id="'zone-' + z.id"
                  :value="z.id"
                  v-model="editConfig.zone_ids"
                />
                <label :for="'zone-' + z.id" class="form-check-label">
                  {{ z.name }} <small class="text-muted">({{ z.id }}) — {{ z.plan || z.status }}</small>
                </label>
              </div>
            </div>
            <textarea
              class="form-control"
              v-model="zoneIdsText"
              rows="3"
              placeholder="每行一个 Zone ID"
              @input="syncZoneIds"
            ></textarea>
            <small class="text-muted">每行一个 Zone ID，或使用上方按钮从 CF 账号选择</small>
          </div>

          <div class="form-row">
            <div class="form-group col-md-6">
              <label>激活阈值 <small class="text-muted">(攻击分值)</small></label>
              <input type="number" class="form-control" v-model.number="editConfig.activate_threshold" min="1" />
              <small class="text-muted">建议: 50</small>
            </div>
            <div class="form-group col-md-6">
              <label>解除阈值 <small class="text-muted">(攻击分值)</small></label>
              <input type="number" class="form-control" v-model.number="editConfig.deactivate_threshold" min="1" />
              <small class="text-muted">建议: 10</small>
            </div>
          </div>

          <div class="form-row">
            <div class="form-group col-md-6">
              <label>冷却时间 <small class="text-muted">(秒)</small></label>
              <input type="number" class="form-control" v-model.number="editConfig.cooldown_s" min="30" />
              <small class="text-muted">建议: 300（5分钟）</small>
            </div>
            <div class="form-group col-md-6">
              <label>恢复安全级别</label>
              <select class="form-control" v-model="editConfig.normal_security_level">
                <option value="essentially_off">essentially_off</option>
                <option value="low">low</option>
                <option value="medium">medium（推荐）</option>
                <option value="high">high</option>
              </select>
            </div>
          </div>

          <div class="form-group">
            <div class="custom-control custom-switch">
              <input type="checkbox" class="custom-control-input" id="cfEnabled" v-model="editConfig.enabled" />
              <label class="custom-control-label" for="cfEnabled">启用自动联动（达阈值自动触发）</label>
            </div>
          </div>

          <div class="d-flex justify-content-between align-items-center mt-3">
            <button class="btn btn-outline-secondary btn-sm" @click="testConnection" :disabled="testLoading">
              <i class="bi bi-plug mr-1"></i>
              {{ testLoading ? '测试中...' : '测试连接' }}
            </button>
            <span v-if="testResult" class="small" :class="testResult.connected ? 'text-success' : 'text-danger'">
              {{ testResult.connected
                ? '✅ 连接成功，找到 ' + testResult.zones_found + ' 个 Zone'
                : '❌ ' + testResult.error }}
            </span>
          </div>

          <div v-if="saveError" class="alert alert-danger mt-3 py-2">{{ saveError }}</div>

          <div class="d-flex justify-content-end gap-2 mt-3">
            <button class="btn btn-outline-secondary" @click="showConfigModal = false">取消</button>
            <button class="btn btn-primary" @click="saveConfig" :disabled="saveLoading">
              {{ saveLoading ? '保存中...' : '保存配置' }}
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios';

const api = axios.create({ baseURL: '/safeline-admin-api' });
api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token');
  if (t) cfg.headers.Authorization = 'Bearer ' + t;
  return cfg;
});

export default {
  name: 'CfShield',
  data() {
    return {
      status: { score: 0, peak: 0, last_attack_at: 0, state: { active: false } },
      cfConfig: {},
      history: [],
      historyTotal: 0,
      historyLoading: false,
      showConfigModal: false,
      editConfig: {
        api_token: '',
        auth_type: 'token',
        auth_email: '',
        zone_ids: [],
        enabled: false,
        activate_threshold: 50,
        deactivate_threshold: 10,
        cooldown_s: 300,
        normal_security_level: 'medium',
        timeout_ms: 10000,
      },
      zoneIdsText: '',
      availableZones: [],
      zonesLoading: false,
      showToken: false,
      saveLoading: false,
      saveError: '',
      testLoading: false,
      testResult: null,
      ctrlLoading: false,
      ctrlAction: '',
      ctrlError: '',
      ctrlSuccess: '',
      pollTimer: null,
    };
  },
  computed: {
    shieldActive() {
      return this.status.state && this.status.state.active === true;
    },
    scoreColor() {
      const s = this.status.score || 0;
      const t = this.cfConfig.activate_threshold || 50;
      if (s >= t) return 'text-danger';
      if (s >= t * 0.6) return 'text-warning';
      return 'text-success';
    },
    scoreBarClass() {
      const s = this.status.score || 0;
      const t = this.cfConfig.activate_threshold || 50;
      if (s >= t) return 'bg-danger';
      if (s >= t * 0.6) return 'bg-warning';
      return 'bg-success';
    },
    scorePercent() {
      const s = this.status.score || 0;
      const t = this.cfConfig.activate_threshold || 50;
      return Math.min(Math.round((s / t) * 100), 100);
    },
  },
  created() {
    this.loadAll();
    this.pollTimer = setInterval(() => this.loadStatus(), 10000);
  },
  beforeDestroy() {
    if (this.pollTimer) clearInterval(this.pollTimer);
  },
  methods: {
    async loadAll() {
      await Promise.all([this.loadStatus(), this.loadConfig(), this.loadHistory()]);
    },
    async loadStatus() {
      try {
        const r = await api.get('/cf/status');
        if (r.data.success) this.status = r.data.data;
      } catch (_) {}
    },
    async loadConfig() {
      try {
        const r = await api.get('/cf/config');
        if (r.data.success && r.data.data) {
          this.cfConfig = r.data.data;
          this.editConfig = {
            api_token: '',
            zone_ids: [...(r.data.data.zone_ids || [])],
            auth_type: r.data.data.auth_type || 'token',
            auth_email: r.data.data.auth_email || '',
            enabled: !!r.data.data.enabled,
            activate_threshold: r.data.data.activate_threshold || 50,
            deactivate_threshold: r.data.data.deactivate_threshold || 10,
            cooldown_s: r.data.data.cooldown_s || 300,
            normal_security_level: r.data.data.normal_security_level || 'medium',
            timeout_ms: r.data.data.timeout_ms || 10000,
          };
          this.zoneIdsText = (r.data.data.zone_ids || []).join('\n');
        }
      } catch (_) {}
    },
    async loadHistory() {
      this.historyLoading = true;
      try {
        const r = await api.get('/cf/history?limit=50');
        if (r.data.success) {
          this.history = r.data.data.items || [];
          this.historyTotal = r.data.data.total || 0;
        }
      } catch (_) {}
      this.historyLoading = false;
    },
    async saveConfig() {
      this.saveLoading = true;
      this.saveError = '';
      try {
        const payload = { ...this.editConfig };
        // Merge manually-typed zone IDs from textarea
        const textZones = this.zoneIdsText.split('\n').map(s => s.trim()).filter(Boolean);
        payload.zone_ids = textZones.length ? textZones : this.editConfig.zone_ids;
        payload.auth_email = payload.auth_type === 'global_key'
          ? (payload.auth_email || '').trim()
          : '';
        if (payload.auth_type === 'global_key' && !payload.auth_email) {
          this.saveError = 'Global API Key 模式需要填写 Auth Email';
          this.saveLoading = false;
          return;
        }
        const r = await api.put('/cf/config', payload);
        if (r.data.success) {
          this.cfConfig = r.data.data;
          this.showConfigModal = false;
          await this.loadStatus();
        } else {
          this.saveError = r.data.message || '保存失败';
        }
      } catch (e) {
        this.saveError = e.response?.data?.message || e.message || '保存失败';
      }
      this.saveLoading = false;
    },
    async fetchZones() {
      this.zonesLoading = true;
      this.testResult = null;
      try {
        const r = await api.get('/cf/zones');
        if (r.data.success) {
          this.availableZones = r.data.data || [];
        }
      } catch (e) {
        this.testResult = { connected: false, error: e.response?.data?.message || e.message };
      }
      this.zonesLoading = false;
    },
    async testConnection() {
      this.testLoading = true;
      this.testResult = null;
      try {
        const r = await api.post('/cf/test');
        this.testResult = r.data.data || r.data;
      } catch (e) {
        this.testResult = { connected: false, error: e.response?.data?.message || e.message };
      }
      this.testLoading = false;
    },
    async enableShield() {
      this.ctrlLoading = true;
      this.ctrlAction = 'enable';
      this.ctrlError = '';
      this.ctrlSuccess = '';
      try {
        const r = await api.post('/cf/shield/enable');
        if (r.data.success) {
          this.ctrlSuccess = '五秒盾已手动启用';
          await this.loadAll();
        } else {
          this.ctrlError = r.data.message || '启用失败';
        }
      } catch (e) {
        this.ctrlError = e.response?.data?.message || e.message || '启用失败';
      }
      this.ctrlLoading = false;
    },
    async disableShield() {
      this.ctrlLoading = true;
      this.ctrlAction = 'disable';
      this.ctrlError = '';
      this.ctrlSuccess = '';
      try {
        const r = await api.post('/cf/shield/disable');
        if (r.data.success) {
          this.ctrlSuccess = '五秒盾已手动关闭';
          await this.loadAll();
        } else {
          this.ctrlError = r.data.message || '关闭失败';
        }
      } catch (e) {
        this.ctrlError = e.response?.data?.message || e.message || '关闭失败';
      }
      this.ctrlLoading = false;
    },
    async clearHistory() {
      if (!confirm('确认清空激活历史和峰值记录？')) return;
      try {
        await api.delete('/cf/history');
        await this.loadHistory();
        await this.loadStatus();
      } catch (_) {}
    },
    syncZoneIds() {
      const lines = this.zoneIdsText.split('\n').map(s => s.trim()).filter(Boolean);
      this.editConfig.zone_ids = lines;
    },
    formatTime(ts) {
      if (!ts) return '-';
      const d = new Date(typeof ts === 'number' && ts < 1e12 ? ts * 1000 : ts);
      return d.toLocaleString('zh-CN');
    },
  },
};
</script>

<style scoped>
.modal-backdrop {
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1050;
}
.gap-2 {
  gap: 0.5rem;
}
</style>
