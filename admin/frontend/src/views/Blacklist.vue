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
          <div class="card-header">
            <h5 class="card-title mb-0">IP 黑名单列表</h5>
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
            <div v-else class="table-responsive">
              <table class="table table-hover">
                <thead>
                  <tr>
                    <th>IP / 网段</th>
                    <th>类型</th>
                    <th>到期时间</th>
                    <th>状态</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="item in blacklist" :key="getEntryValue(item)">
                    <td>{{ getEntryValue(item) }}</td>
                    <td>{{ getEntryTypeText(item) }}</td>
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
      ipToRemove: null,
      newIp: {
        ip: '',
        banType: 'temporary',
        duration: 24
      }
    };
  },
  computed: {
    isCurrentEntryCidr() {
      const entry = String(this.newIp.ip || '').trim();
      return entry.includes('/') || entry.includes('-');
    }
  },
  created() {
    this.fetchBlacklist();
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
          this.$toast.success('已加入 delta overlay，即将生效');
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
