<template>
  <div class="logs">
    <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
      <h1 class="h2">实时日志</h1>
      <div class="btn-toolbar mb-2 mb-md-0">
        <div class="btn-group mr-2">
          <button type="button" class="btn btn-sm btn-outline-secondary" @click="refreshLogs">
            <i class="bi bi-arrow-repeat mr-1"></i> 刷新
          </button>
          <button type="button" class="btn btn-sm btn-outline-secondary" @click="exportLogs">
            <i class="bi bi-download mr-1"></i> 导出
          </button>
        </div>
      </div>
    </div>

    <div class="row mb-4">
      <div class="col-md-12">
        <div class="card">
          <div class="card-header">
            <div class="d-flex justify-content-between align-items-center">
              <h5 class="card-title mb-0">请求日志列表</h5>
              <div class="form-inline">
                <div class="form-group mr-2">
                  <select class="form-control form-control-sm" v-model="filter.status">
                    <option value="all">所有状态</option>
                    <option value="blocked">已阻止</option>
                    <option value="passed">已通过</option>
                  </select>
                </div>
                <div class="form-group">
                  <input 
                    type="text" 
                    class="form-control form-control-sm" 
                    placeholder="搜索IP或URI" 
                    v-model="filter.search"
                  >
                </div>
              </div>
            </div>
          </div>
          <div class="card-body p-0">
            <div v-if="loading" class="text-center py-5">
              <div class="spinner-border text-primary" role="status">
                <span class="sr-only">加载中...</span>
              </div>
              <p class="mt-2">加载日志数据...</p>
            </div>
            <div v-else-if="filteredLogs.length === 0" class="text-center py-5">
              <i class="bi bi-file-earmark-text text-muted" style="font-size: 2rem;"></i>
              <p class="mt-2 text-muted">暂无日志数据或没有符合筛选条件的日志。</p>
            </div>
            <div v-else class="table-responsive">
              <table class="table table-hover table-striped">
                <thead>
                  <tr>
                    <th>时间</th>
                    <th>IP地址</th>
                    <th>方法</th>
                    <th>URI</th>
                    <th>状态</th>
                    <th>原因</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(log, index) in paginatedLogs" :key="index" :class="{'table-danger': log.is_blocked}">
                    <td>{{ formatDate(log.timestamp) }}</td>
                    <td>{{ log.client_ip }}</td>
                    <td>{{ log.method }}</td>
                    <td class="text-truncate" style="max-width: 200px;" :title="log.uri">{{ log.uri }}</td>
                    <td>
                      <span v-if="log.is_blocked" class="badge badge-danger">已阻止</span>
                      <span v-else class="badge badge-success">通过</span>
                    </td>
                    <td>{{ log.reason || '-' }}</td>
                    <td>
                      <div class="btn-group btn-group-sm">
                        <button 
                          class="btn btn-outline-secondary" 
                          @click="viewLogDetails(log)"
                          title="查看详情"
                        >
                          <i class="bi bi-eye"></i>
                        </button>
                        <button 
                          v-if="!isIpBlacklisted(log.client_ip)" 
                          class="btn btn-outline-danger" 
                          @click="blacklistIp(log.client_ip)"
                          title="加入黑名单"
                        >
                          <i class="bi bi-shield-slash"></i>
                        </button>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            
            <!-- 分页 -->
            <div class="d-flex justify-content-between align-items-center p-3 border-top">
              <div>
                显示 {{ startIndex + 1 }}-{{ endIndex }} 条，共 {{ filteredLogs.length }} 条
              </div>
              <nav aria-label="Page navigation">
                <ul class="pagination pagination-sm mb-0">
                  <li class="page-item" :class="{ disabled: currentPage === 1 }">
                    <a class="page-link" href="#" @click.prevent="goToPage(currentPage - 1)">上一页</a>
                  </li>
                  <li 
                    v-for="page in totalPages" 
                    :key="page" 
                    class="page-item"
                    :class="{ active: page === currentPage }"
                  >
                    <a class="page-link" href="#" @click.prevent="goToPage(page)">{{ page }}</a>
                  </li>
                  <li class="page-item" :class="{ disabled: currentPage === totalPages }">
                    <a class="page-link" href="#" @click.prevent="goToPage(currentPage + 1)">下一页</a>
                  </li>
                </ul>
              </nav>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 日志详情模态框 -->
    <div class="modal fade" id="logDetailModal" tabindex="-1" aria-labelledby="logDetailModalLabel" aria-hidden="true">
      <div class="modal-dialog modal-lg">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="logDetailModalLabel">日志详情</h5>
            <button type="button" class="close" data-dismiss="modal" aria-label="Close">
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div class="modal-body" v-if="selectedLog">
            <div class="row">
              <div class="col-md-6">
                <p><strong>时间：</strong> {{ formatDate(selectedLog.timestamp) }}</p>
                <p><strong>IP地址：</strong> {{ selectedLog.client_ip }}</p>
                <p><strong>方法：</strong> {{ selectedLog.method }}</p>
                <p><strong>URI：</strong> {{ selectedLog.uri }}</p>
              </div>
              <div class="col-md-6">
                <p>
                  <strong>状态：</strong> 
                  <span 
                    :class="selectedLog.is_blocked ? 'badge badge-danger' : 'badge badge-success'"
                  >
                    {{ selectedLog.is_blocked ? '已阻止' : '通过' }}
                  </span>
                </p>
                <p><strong>原因：</strong> {{ selectedLog.reason || '-' }}</p>
                <p><strong>User-Agent：</strong> {{ selectedLog.user_agent || '-' }}</p>
              </div>
            </div>
            
            <div v-if="selectedLog.request_headers || selectedLog.request_body" class="mt-3">
              <h6>请求数据</h6>
              <div class="card">
                <div class="card-body">
                  <div v-if="selectedLog.request_headers">
                    <h6>请求头</h6>
                    <pre class="bg-light p-2 rounded">{{ formatJSON(selectedLog.request_headers) }}</pre>
                  </div>
                  <div v-if="selectedLog.request_body">
                    <h6>请求体</h6>
                    <pre class="bg-light p-2 rounded">{{ formatJSON(selectedLog.request_body) }}</pre>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button 
              v-if="selectedLog && !isIpBlacklisted(selectedLog.client_ip)" 
              type="button" 
              class="btn btn-danger mr-auto" 
              @click="blacklistIp(selectedLog.client_ip)"
            >
              <i class="bi bi-shield-slash mr-1"></i> 加入黑名单
            </button>
            <button type="button" class="btn btn-secondary" data-dismiss="modal">关闭</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 黑名单确认模态框 -->
    <div class="modal fade" id="blacklistModal" tabindex="-1" aria-labelledby="blacklistModalLabel" aria-hidden="true">
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="blacklistModalLabel">添加 IP 到黑名单</h5>
            <button type="button" class="close" data-dismiss="modal" aria-label="Close">
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div class="modal-body">
            <p>确认将 IP <strong>{{ ipToBlacklist }}</strong> 添加到黑名单？</p>
            <div class="form-group">
              <label>封禁时长</label>
              <div class="custom-control custom-radio">
                <input type="radio" id="temporaryBan" name="banDuration" class="custom-control-input" value="temporary" v-model="blacklistDuration.type">
                <label class="custom-control-label" for="temporaryBan">临时封禁</label>
              </div>
              <div class="custom-control custom-radio">
                <input type="radio" id="permanentBan" name="banDuration" class="custom-control-input" value="permanent" v-model="blacklistDuration.type">
                <label class="custom-control-label" for="permanentBan">永久封禁</label>
              </div>
            </div>
            
            <div class="form-group" v-if="blacklistDuration.type === 'temporary'">
              <label for="durationInput">封禁持续时间（小时）</label>
              <input 
                type="number" 
                class="form-control" 
                id="durationInput" 
                v-model="blacklistDuration.hours"
                min="1"
                required
              >
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-dismiss="modal">取消</button>
            <button type="button" class="btn btn-danger" @click="confirmBlacklistIp">确认添加</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios';
import $ from 'jquery';
import moment from 'moment';

export default {
  name: 'Logs',
  data() {
    return {
      logs: [],
      loading: true,
      selectedLog: null,
      filter: {
        status: 'all',
        search: ''
      },
      currentPage: 1,
      pageSize: 15,
      blacklistedIps: [],
      ipToBlacklist: '',
      blacklistDuration: {
        type: 'temporary',
        hours: 24
      }
    };
  },
  computed: {
    filteredLogs() {
      return this.logs.filter(log => {
        // 状态筛选
        if (this.filter.status === 'blocked' && !log.is_blocked) return false;
        if (this.filter.status === 'passed' && log.is_blocked) return false;
        
        // 搜索筛选
        if (this.filter.search) {
          const searchTerm = this.filter.search.toLowerCase();
          return log.client_ip.includes(searchTerm) || 
                 (log.uri && log.uri.toLowerCase().includes(searchTerm));
        }
        
        return true;
      });
    },
    totalPages() {
      return Math.ceil(this.filteredLogs.length / this.pageSize);
    },
    startIndex() {
      return (this.currentPage - 1) * this.pageSize;
    },
    endIndex() {
      return Math.min(this.startIndex + this.pageSize, this.filteredLogs.length);
    },
    paginatedLogs() {
      return this.filteredLogs.slice(this.startIndex, this.endIndex);
    }
  },
  created() {
    this.fetchLogs();
    this.fetchBlacklist();
  },
  methods: {
    async fetchLogs() {
      this.loading = true;
      try {
        const response = await axios.get('/api/logs', { params: { limit: 500 } });
        if (response.data.success) {
          this.logs = response.data.data;
        }
      } catch (error) {
        console.error('Error fetching logs:', error);
      } finally {
        this.loading = false;
      }
    },
    async fetchBlacklist() {
      try {
        const response = await axios.get('/api/blacklist');
        if (response.data.success) {
          this.blacklistedIps = response.data.data.map(item => item.ip);
        }
      } catch (error) {
        console.error('Error fetching blacklist:', error);
      }
    },
    refreshLogs() {
      this.fetchLogs();
      this.fetchBlacklist();
    },
    exportLogs() {
      // 准备导出数据
      const exportData = this.filteredLogs.map(log => ({
        timestamp: this.formatDate(log.timestamp),
        client_ip: log.client_ip,
        method: log.method,
        uri: log.uri,
        status: log.is_blocked ? '已阻止' : '通过',
        reason: log.reason || '-',
        user_agent: log.user_agent || '-'
      }));
      
      // 转换为CSV
      const headers = ['时间', 'IP地址', '方法', 'URI', '状态', '原因', 'User-Agent'];
      const csvContent = [
        headers.join(','),
        ...exportData.map(row => Object.values(row).map(value => `"${value}"`).join(','))
      ].join('\n');
      
      // 创建下载链接
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.setAttribute('href', url);
      link.setAttribute('download', `safeline-logs-${moment().format('YYYY-MM-DD')}.csv`);
      link.style.visibility = 'hidden';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    },
    formatDate(timestamp) {
      return moment.unix(timestamp).format('YYYY-MM-DD HH:mm:ss');
    },
    formatJSON(data) {
      try {
        if (typeof data === 'string') {
          return JSON.stringify(JSON.parse(data), null, 2);
        }
        return JSON.stringify(data, null, 2);
      } catch (e) {
        return data;
      }
    },
    viewLogDetails(log) {
      this.selectedLog = log;
      $('#logDetailModal').modal('show');
    },
    isIpBlacklisted(ip) {
      return this.blacklistedIps.includes(ip);
    },
    blacklistIp(ip) {
      this.ipToBlacklist = ip;
      this.blacklistDuration = {
        type: 'temporary',
        hours: 24
      };
      $('#blacklistModal').modal('show');
    },
    async confirmBlacklistIp() {
      try {
        const payload = {
          ip: this.ipToBlacklist,
          duration: this.blacklistDuration.type === 'permanent' ? -1 : this.blacklistDuration.hours * 3600
        };
        
        const response = await axios.post('/api/blacklist', payload);
        
        if (response.data.success) {
          // 更新黑名单列表
          this.blacklistedIps.push(this.ipToBlacklist);
          
          // 关闭模态框
          $('#blacklistModal').modal('hide');
          
          // 如果日志详情模态框也打开，关闭它
          $('#logDetailModal').modal('hide');
          
          // 显示成功消息
          alert(`IP ${this.ipToBlacklist} 已成功添加到黑名单`);
        }
      } catch (error) {
        console.error('Error adding IP to blacklist:', error);
        alert('添加到黑名单失败');
      }
    },
    goToPage(page) {
      if (page >= 1 && page <= this.totalPages) {
        this.currentPage = page;
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
pre {
  max-height: 200px;
  overflow-y: auto;
}
</style>
