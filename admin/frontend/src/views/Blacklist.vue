<template>
  <div class="blacklist">
    <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
      <h1 class="h2">IP 黑名单</h1>
      <div class="btn-toolbar mb-2 mb-md-0">
        <button type="button" class="btn btn-sm btn-primary" @click="openAddModal">
          <i class="bi bi-plus-circle mr-1"></i> 添加 IP
        </button>
      </div>
    </div>

    <div class="row mb-4">
      <div class="col-md-12">
        <div class="alert alert-info" role="alert">
          <i class="bi bi-info-circle-fill mr-2"></i>
          IP 黑名单用于阻止已知的恶意 IP 地址访问您的站点。被添加到黑名单的 IP 将被直接拒绝访问，无需进一步验证。
        </div>
      </div>
    </div>

    <div class="row">
      <div class="col-md-12">
        <div class="card mb-4">
          <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="card-title mb-0">订阅威胁情报源</h5>
            <div>
              <button type="button" class="btn btn-sm btn-outline-secondary mr-2" @click="refreshBlacklistFeeds" :disabled="loadingFeeds">
                {{ loadingFeeds ? '刷新中...' : '立即刷新' }}
              </button>
              <button type="button" class="btn btn-sm btn-outline-primary" @click="saveBlacklistFeeds" :disabled="loadingFeeds">
                保存订阅配置
              </button>
            </div>
          </div>
          <div class="card-body">
            <div class="form-row">
              <div class="form-group col-md-3">
                <div class="form-check mt-4">
                  <input id="feed-enabled" v-model="feedConfig.enabled" type="checkbox" class="form-check-input">
                  <label class="form-check-label" for="feed-enabled">启用威胁情报订阅</label>
                </div>
              </div>
              <div class="form-group col-md-3">
                <label for="feed-refresh-interval">刷新间隔（秒）</label>
                <input id="feed-refresh-interval" v-model.number="feedConfig.refresh_interval" type="number" class="form-control" min="300" max="86400">
              </div>
              <div class="form-group col-md-3">
                <label for="feed-timeout">请求超时（毫秒）</label>
                <input id="feed-timeout" v-model.number="feedConfig.request_timeout_ms" type="number" class="form-control" min="1000" max="60000">
              </div>
              <div class="form-group col-md-3">
                <label for="feed-max-entries">单源最大条目数</label>
                <input id="feed-max-entries" v-model.number="feedConfig.max_entries_per_source" type="number" class="form-control" min="100" max="200000">
              </div>
            </div>

            <div class="d-flex justify-content-between align-items-center mb-2">
              <strong>源列表</strong>
              <button type="button" class="btn btn-sm btn-outline-success" @click="addFeedSource">新增源</button>
            </div>

            <div v-if="feedConfig.sources.length === 0" class="text-muted mb-3">暂无订阅源</div>
            <div v-else class="mb-3">
              <div class="border rounded p-3 mb-2" v-for="(source, index) in feedConfig.sources" :key="source.id || index">
                <div class="form-row">
                  <div class="form-group col-md-2">
                    <label>启用</label>
                    <div class="form-check mt-2">
                      <input :id="`feed-source-enabled-${index}`" v-model="source.enabled" type="checkbox" class="form-check-input">
                      <label class="form-check-label" :for="`feed-source-enabled-${index}`">启用</label>
                    </div>
                  </div>
                  <div class="form-group col-md-3">
                    <label>名称</label>
                    <input v-model.trim="source.name" type="text" class="form-control" placeholder="例如：blocklist.de all">
                  </div>
                  <div class="form-group col-md-2">
                    <label>ID</label>
                    <input v-model.trim="source.id" type="text" class="form-control" placeholder="feed-id">
                  </div>
                  <div class="form-group col-md-4">
                    <label>URL</label>
                    <input v-model.trim="source.url" type="url" class="form-control" placeholder="https://example.com/feed.txt">
                  </div>
                  <div class="form-group col-md-1 d-flex align-items-end">
                    <button type="button" class="btn btn-sm btn-outline-danger w-100" @click="removeFeedSource(index)">删除</button>
                  </div>
                </div>
              </div>
            </div>

            <div class="alert alert-secondary py-2 mb-0">
              <div><strong>上次刷新：</strong>{{ formatFeedTime(feedStatus.updated_at) }}</div>
              <div><strong>聚合 IP 数：</strong>{{ feedStatus.total_ips || 0 }}</div>
              <div><strong>聚合网段数：</strong>{{ feedStatus.total_ranges || 0 }}</div>
            </div>

            <div class="table-responsive mt-3" v-if="Array.isArray(feedStatus.sources) && feedStatus.sources.length > 0">
              <table class="table table-sm table-hover">
                <thead>
                  <tr>
                    <th>源</th>
                    <th>状态</th>
                    <th>条目数</th>
                    <th>上次抓取</th>
                    <th>信息</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="source in feedStatus.sources" :key="source.id">
                    <td>{{ source.name || source.id }}</td>
                    <td>
                      <span :class="source.success ? 'badge badge-success' : 'badge badge-secondary'">
                        {{ source.success ? '成功' : (source.message === 'disabled' ? '已禁用' : '失败') }}
                      </span>
                    </td>
                    <td>{{ source.entry_count || 0 }}</td>
                    <td>{{ formatFeedTime(source.fetched_at) }}</td>
                    <td class="text-monospace small">{{ source.message || '-' }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
      <div class="col-md-12">
        <div class="card mb-4">
          <div class="card-header d-flex flex-column flex-lg-row justify-content-between align-items-lg-center">
            <h5 class="card-title mb-3 mb-lg-0">IP 黑名单列表</h5>
            <div class="d-flex flex-column flex-lg-row align-items-lg-center" style="gap: 0.5rem;">
              <input
                v-model.trim="searchQuery"
                type="search"
                class="form-control form-control-sm"
                style="min-width: 240px;"
                placeholder="搜索 IP / 网段 / 类型 / 状态"
              >
              <div class="btn-group btn-group-sm">
                <button
                  v-for="option in statusFilters"
                  :key="option.value"
                  type="button"
                  class="btn"
                  :class="statusFilter === option.value ? 'btn-primary' : 'btn-outline-secondary'"
                  @click="statusFilter = option.value"
                >
                  {{ option.label }}
                </button>
              </div>
            </div>
          </div>
          <div class="card-body">
            <div v-if="loading" class="text-center py-5">
              <div class="spinner-border text-primary" role="status">
                <span class="sr-only">加载中...</span>
              </div>
              <p class="mt-2">加载 IP 黑名单...</p>
            </div>
            <div v-else-if="blacklist.length === 0" class="text-center py-5">
              <i class="bi bi-shield-check text-muted" style="font-size: 2rem;"></i>
              <p class="mt-2 text-muted">黑名单为空，没有被封禁的 IP。</p>
            </div>
            <div v-else-if="filteredBlacklist.length === 0" class="text-center py-5">
              <i class="bi bi-search text-muted" style="font-size: 2rem;"></i>
              <p class="mt-2 text-muted">没有匹配当前搜索条件的黑名单条目。</p>
            </div>
            <div v-else class="table-responsive">
              <table class="table table-hover">
                <thead>
                  <tr>
                    <th>IP / 网段</th>
                    <th>类型</th>
                    <th>来源</th>
                    <th>到期时间</th>
                    <th>状态</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="item in filteredBlacklist" :key="getEntryValue(item)">
                    <td>{{ getEntryValue(item) }}</td>
                    <td>{{ getEntryTypeText(item) }}</td>
                    <td>{{ getEntrySourceText(item) }}</td>
                    <td>
                      <span v-if="item.permanent">永久</span>
                      <span v-else-if="item.expires_in > 0">{{ formatExpiryTime(item.expires_in) }}</span>
                      <span v-else>已过期</span>
                    </td>
                    <td>
                      <span 
                        :class="getStatusBadgeClass(item)"
                      >
                        {{ getStatusText(item) }}
                      </span>
                    </td>
                    <td>
                      <button class="btn btn-sm btn-outline-danger" @click="confirmRemoveIp(item)">
                        <i class="bi bi-trash"></i> 移除
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 添加 IP 模态框 -->
    <div class="modal fade" id="addModal" tabindex="-1" aria-labelledby="addModalLabel" aria-hidden="true">
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="addModalLabel">添加 IP 到黑名单</h5>
            <button type="button" class="close" data-dismiss="modal" aria-label="Close">
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div class="modal-body">
            <form @submit.prevent="addIpToBlacklist">
              <div class="form-group">
                <label for="ipInput">IP 地址</label>
                <input 
                  type="text" 
                  class="form-control" 
                  id="ipInput" 
                  v-model="newIp.ip" 
                  placeholder="例如：192.168.1.1、2001:db8::1、10.0.0.0/24 或 10.0.0.1-10.0.0.9"
                  required
                >
                <small class="form-text text-muted">请输入要添加到黑名单的 IPv4、IPv6、CIDR 网段或 IPv4 范围</small>
              </div>
              
              <div class="form-group">
                <label>封禁时长</label>
                <template v-if="!isCurrentEntryCidr">
                  <div class="custom-control custom-radio">
                    <input type="radio" id="temporaryBan" name="banDuration" class="custom-control-input" value="temporary" v-model="newIp.banType">
                    <label class="custom-control-label" for="temporaryBan">临时封禁</label>
                  </div>
                  <div class="custom-control custom-radio">
                    <input type="radio" id="permanentBan" name="banDuration" class="custom-control-input" value="permanent" v-model="newIp.banType">
                    <label class="custom-control-label" for="permanentBan">永久封禁</label>
                  </div>
                </template>
                <small v-else class="form-text text-muted">网段或范围条目按永久封禁处理，并写入全局配置。</small>
              </div>
              
              <div class="form-group" v-if="!isCurrentEntryCidr && newIp.banType === 'temporary'">
                <label for="durationInput">封禁持续时间（小时）</label>
                <input 
                  type="number" 
                  class="form-control" 
                  id="durationInput" 
                  v-model="newIp.duration"
                  min="1"
                  required
                >
              </div>
              
              <div class="form-row mt-4">
                <div class="col-12 text-right">
                  <button type="button" class="btn btn-secondary mr-2" data-dismiss="modal">取消</button>
                  <button type="submit" class="btn btn-primary">添加</button>
                </div>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>

    <!-- 删除确认模态框 -->
    <div class="modal fade" id="removeModal" tabindex="-1" aria-labelledby="removeModalLabel" aria-hidden="true">
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="removeModalLabel">确认移除</h5>
            <button type="button" class="close" data-dismiss="modal" aria-label="Close">
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div class="modal-body">
            <p>您确定要将 <strong>{{ ipToRemove ? getEntryValue(ipToRemove) : '' }}</strong> 从黑名单中移除吗？</p>
            <p>移除后，该条目将不再被 WAF 拦截。</p>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-dismiss="modal">取消</button>
            <button type="button" class="btn btn-danger" @click="removeIpFromBlacklist">确认移除</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios';
import $ from 'jquery';
import { getApiErrorMessage, shouldHandleLocally } from '../utils/http';

export default {
  name: 'Blacklist',
  data() {
    return {
      blacklist: [],
      loading: true,
      loadingFeeds: false,
      ipToRemove: null,
      newIp: {
        ip: '',
        banType: 'temporary',
        duration: 24
      },
      feedConfig: {
        enabled: true,
        refresh_interval: 1800,
        request_timeout_ms: 10000,
        max_entries_per_source: 50000,
        sources: []
      },
      feedStatus: {
        updated_at: null,
        total_ips: 0,
        total_ranges: 0,
        sources: []
      },
      searchQuery: '',
      statusFilter: 'all',
      statusFilters: [
        { label: '全部', value: 'all' },
        { label: '临时', value: 'temporary' },
        { label: '永久', value: 'permanent' },
        { label: '已过期', value: 'expired' }
      ]
    };
  },
  computed: {
    isCurrentEntryCidr() {
      const entry = String(this.newIp.ip || '').trim();
      return entry.includes('/') || entry.includes('-');
    },
    filteredBlacklist() {
      const keyword = String(this.searchQuery || '').trim().toLowerCase();

      return this.blacklist.filter((item) => {
        if (this.statusFilter === 'temporary' && (item.permanent || !(item.expires_in > 0))) {
          return false;
        }
        if (this.statusFilter === 'permanent' && !item.permanent) {
          return false;
        }
        if (this.statusFilter === 'expired' && item.expires_in !== 0 && item.expires_in !== -2) {
          return false;
        }

        if (!keyword) {
          return true;
        }

        const haystack = [
          this.getEntryValue(item),
          this.getEntryTypeText(item),
          this.getEntrySourceText(item),
          this.getStatusText(item)
        ]
          .map((value) => String(value || '').toLowerCase())
          .join(' ');

        return haystack.includes(keyword);
      });
    }
  },
  created() {
    this.fetchBlacklist();
    this.fetchBlacklistFeeds();
  },
  methods: {
    isProbablyValidIp(value) {
      const raw = String(value || '').trim().replace(/^\[/, '').replace(/\]$/, '');
      if (!raw) {
        return false;
      }

      const ipv4Match = raw.match(/^(\d{1,3})(?:\.(\d{1,3})){3}$/);
      if (ipv4Match) {
        return raw.split('.').every((part) => {
          const num = Number(part);
          return Number.isInteger(num) && num >= 0 && num <= 255;
        });
      }

      return raw.includes(':') && /^[0-9a-f:.]+$/i.test(raw);
    },
    isProbablyValidBlacklistEntry(value) {
      const raw = String(value || '').trim();
      if (!raw) {
        return false;
      }

      if (raw.includes('-')) {
        const parts = raw.split('-');
        return parts.length === 2
          && this.isProbablyValidIp(parts[0].trim())
          && this.isProbablyValidIp(parts[1].trim())
          && !parts[0].includes(':')
          && !parts[1].includes(':');
      }

      if (!raw.includes('/')) {
        return this.isProbablyValidIp(raw);
      }

      const parts = raw.split('/');
      if (parts.length !== 2) {
        return false;
      }

      const ipPart = parts[0].trim();
      const prefix = Number(parts[1]);
      if (!Number.isInteger(prefix) || !this.isProbablyValidIp(ipPart)) {
        return false;
      }

      return ipPart.includes(':')
        ? prefix >= 0 && prefix <= 128
        : prefix >= 0 && prefix <= 32;
    },
    getEntryValue(item) {
      if (!item || typeof item !== 'object') {
        return '';
      }

      return item.entry || item.cidr || item.ip || '';
    },
    getEntryTypeText(item) {
      const entry = this.getEntryValue(item);
      if (!entry) {
        return '-';
      }

      if (item && item.type === 'range') {
        return '范围';
      }

      if (item && item.type === 'cidr') {
        return 'CIDR';
      }

      return entry.includes('/') ? 'CIDR' : 'IP';
    },
    getEntrySourceText(item) {
      if (!item || typeof item !== 'object') {
        return '-';
      }

      if (item.source === 'redis') {
        return '运行时';
      }

      if (item.source === 'config') {
        return '配置';
      }

      return item.source || '-';
    },
    async fetchBlacklist() {
      this.loading = true;
      try {
        const response = await axios.get('/blacklist');
        if (response.data.success) {
          this.blacklist = response.data.data;
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '获取黑名单失败，请稍后重试。'));
        }
      } finally {
        this.loading = false;
      }
    },
    async fetchBlacklistFeeds() {
      this.loadingFeeds = true;
      try {
        const response = await axios.get('/blacklist/feeds');
        if (response.data && response.data.success && response.data.data) {
          this.feedConfig = response.data.data.config || this.feedConfig;
          this.feedStatus = response.data.data.status || this.feedStatus;
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '获取订阅源失败，请稍后重试。'));
        }
      } finally {
        this.loadingFeeds = false;
      }
    },
    addFeedSource() {
      this.feedConfig.sources = [
        ...(Array.isArray(this.feedConfig.sources) ? this.feedConfig.sources : []),
        {
          id: `feed-${Date.now()}`,
          name: '',
          url: '',
          enabled: true,
          format: 'ip_list'
        }
      ];
    },
    removeFeedSource(index) {
      this.feedConfig.sources.splice(index, 1);
    },
    async saveBlacklistFeeds() {
      try {
        const response = await axios.put('/blacklist/feeds', this.feedConfig);
        if (response.data && response.data.success) {
          this.feedConfig = response.data.data.config || this.feedConfig;
          this.feedStatus = response.data.data.status || this.feedStatus;
          this.$toast.success('订阅源配置已保存并已发布。');
        } else {
          this.$toast.error((response.data && response.data.message) || '保存订阅源失败。');
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '保存订阅源失败，请稍后重试。'));
        }
      }
    },
    async refreshBlacklistFeeds() {
      this.loadingFeeds = true;
      try {
        const response = await axios.post('/blacklist/feeds/refresh');
        if (response.data && response.data.success) {
          this.feedStatus = response.data.data || this.feedStatus;
          await this.fetchBlacklist();
          this.$toast.success('订阅源已刷新。');
        } else {
          this.$toast.error((response.data && response.data.message) || '刷新订阅源失败。');
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '刷新订阅源失败，请稍后重试。'));
        }
      } finally {
        this.loadingFeeds = false;
      }
    },
    formatFeedTime(value) {
      if (!value) return '-';
      const date = new Date(Number(value));
      return Number.isNaN(date.getTime()) ? '-' : date.toLocaleString();
    },
    formatExpiryTime(seconds) {
      if (seconds <= 0) return '已过期';
      
      const days = Math.floor(seconds / 86400);
      const hours = Math.floor((seconds % 86400) / 3600);
      const minutes = Math.floor((seconds % 3600) / 60);
      
      if (days > 0) {
        return `${days}天${hours}小时后`;
      } else if (hours > 0) {
        return `${hours}小时${minutes}分钟后`;
      } else {
        return `${minutes}分钟后`;
      }
    },
    getStatusBadgeClass(item) {
      if (item.permanent) {
        return 'badge badge-danger';
      } else if (item.expires_in > 0) {
        return 'badge badge-warning';
      } else {
        return 'badge badge-secondary';
      }
    },
    getStatusText(item) {
      if (item.permanent) {
        return '永久封禁';
      } else if (item.expires_in > 0) {
        return '临时封禁';
      } else {
        return '已过期';
      }
    },
    openAddModal() {
      this.newIp = {
        ip: '',
        banType: 'temporary',
        duration: 24
      };
      $('#addModal').modal('show');
    },
    confirmRemoveIp(ip) {
      this.ipToRemove = ip;
      $('#removeModal').modal('show');
    },
    async addIpToBlacklist() {
      const entry = String(this.newIp.ip || '').trim();
      if (!this.isProbablyValidBlacklistEntry(entry)) {
        this.$toast.error('请输入有效的 IPv4、IPv6、CIDR 网段或 IPv4 范围。');
        return;
      }

      if (this.newIp.banType === 'temporary' && Number(this.newIp.duration) < 1) {
        this.$toast.error('临时封禁时长必须至少为 1 小时。');
        return;
      }
      
      try {
        const isConfigBackedEntry = entry.includes('/') || entry.includes('-');
        const payload = {
          entry,
          duration: isConfigBackedEntry || this.newIp.banType === 'permanent' ? -1 : this.newIp.duration * 3600
        };
        
        const response = await axios.post('/blacklist', payload);
        
        if (response.data.success) {
          await this.fetchBlacklist();
          $('#addModal').modal('hide');
          this.$toast.success('黑名单条目已添加。');
        } else {
          this.$toast.error((response.data && response.data.message) || '添加黑名单失败。');
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '添加黑名单失败，请稍后重试。'));
        }
      }
    },
    async removeIpFromBlacklist() {
      if (!this.ipToRemove) return;
      
      try {
        const entry = this.getEntryValue(this.ipToRemove);
        const response = await axios.delete('/blacklist', {
          params: {
            entry
          }
        });
        
        if (response.data.success) {
          this.blacklist = this.blacklist.filter(item => this.getEntryValue(item) !== entry);
          $('#removeModal').modal('hide');
          this.$toast.success(`${entry} 已从黑名单移除。`);
          this.ipToRemove = null;
        } else {
          this.$toast.error((response.data && response.data.message) || '移除黑名单失败。');
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '移除黑名单失败，请稍后重试。'));
        }
      }
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
</style>
