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
                    <th>IP 地址</th>
                    <th>到期时间</th>
                    <th>状态</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="item in blacklist" :key="item.ip">
                    <td>{{ item.ip }}</td>
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
                  placeholder="例如：192.168.1.1"
                  required
                >
                <small class="form-text text-muted">请输入要添加到黑名单的 IP 地址</small>
              </div>
              
              <div class="form-group">
                <label>封禁时长</label>
                <div class="custom-control custom-radio">
                  <input type="radio" id="temporaryBan" name="banDuration" class="custom-control-input" value="temporary" v-model="newIp.banType">
                  <label class="custom-control-label" for="temporaryBan">临时封禁</label>
                </div>
                <div class="custom-control custom-radio">
                  <input type="radio" id="permanentBan" name="banDuration" class="custom-control-input" value="permanent" v-model="newIp.banType">
                  <label class="custom-control-label" for="permanentBan">永久封禁</label>
                </div>
              </div>
              
              <div class="form-group" v-if="newIp.banType === 'temporary'">
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
            <p>您确定要将 IP <strong>{{ ipToRemove ? ipToRemove.ip : '' }}</strong> 从黑名单中移除吗？</p>
            <p>移除后，此 IP 将能够再次访问您的站点。</p>
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
  created() {
    this.fetchBlacklist();
  },
  methods: {
    async fetchBlacklist() {
      this.loading = true;
      try {
        const response = await axios.get('/api/blacklist');
        if (response.data.success) {
          this.blacklist = response.data.data;
        }
      } catch (error) {
        console.error('Error fetching blacklist:', error);
        // Show error toast
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
      // 验证IP地址格式
      const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
      if (!ipRegex.test(this.newIp.ip)) {
        // Show error toast for invalid IP
        return;
      }
      
      try {
        const payload = {
          ip: this.newIp.ip,
          duration: this.newIp.banType === 'permanent' ? -1 : this.newIp.duration * 3600
        };
        
        const response = await axios.post('/api/blacklist', payload);
        
        if (response.data.success) {
          // Show success toast
          await this.fetchBlacklist();
          $('#addModal').modal('hide');
        }
      } catch (error) {
        console.error('Error adding IP to blacklist:', error);
        // Show error toast
      }
    },
    async removeIpFromBlacklist() {
      if (!this.ipToRemove) return;
      
      try {
        const response = await axios.delete(`/api/blacklist/${this.ipToRemove.ip}`);
        
        if (response.data.success) {
          // Show success toast
          this.blacklist = this.blacklist.filter(item => item.ip !== this.ipToRemove.ip);
          $('#removeModal').modal('hide');
        }
      } catch (error) {
        console.error('Error removing IP from blacklist:', error);
        // Show error toast
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
