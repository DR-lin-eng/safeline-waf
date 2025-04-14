<template>
  <div class="dashboard">
    <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
      <h1 class="h2">仪表盘</h1>
      <div class="btn-toolbar mb-2 mb-md-0">
        <button type="button" class="btn btn-sm btn-outline-secondary" @click="refreshStats">
          <i class="bi bi-arrow-repeat"></i> 刷新数据
        </button>
      </div>
    </div>

    <div class="row mb-4">
      <div class="col-md-4">
        <div class="card text-white bg-primary mb-3">
          <div class="card-body">
            <div class="d-flex justify-content-between align-items-center">
              <div>
                <h6 class="card-title">总请求数</h6>
                <h3 class="card-text">{{ stats.total_requests.toLocaleString() }}</h3>
              </div>
              <div class="display-4">
                <i class="bi bi-graph-up"></i>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="card text-white bg-success mb-3">
          <div class="card-body">
            <div class="d-flex justify-content-between align-items-center">
              <div>
                <h6 class="card-title">通过请求数</h6>
                <h3 class="card-text">{{ (stats.total_requests - stats.blocked_requests).toLocaleString() }}</h3>
              </div>
              <div class="display-4">
                <i class="bi bi-check-circle"></i>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="card text-white bg-danger mb-3">
          <div class="card-body">
            <div class="d-flex justify-content-between align-items-center">
              <div>
                <h6 class="card-title">阻止请求数</h6>
                <h3 class="card-text">{{ stats.blocked_requests.toLocaleString() }}</h3>
              </div>
              <div class="display-4">
                <i class="bi bi-shield"></i>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="row mb-4">
      <div class="col-md-12">
        <div class="card mb-4">
          <div class="card-header">
            <h5 class="card-title mb-0">站点请求统计</h5>
          </div>
          <div class="card-body">
            <div v-if="Object.keys(stats.sites).length === 0" class="text-center py-4">
              <p class="text-muted">暂无站点数据</p>
            </div>
            <div v-else class="table-responsive">
              <table class="table table-hover">
                <thead>
                  <tr>
                    <th>站点</th>
                    <th class="text-right">请求数</th>
                    <th class="text-right">占比</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(count, domain) in stats.sites" :key="domain">
                    <td>{{ domain }}</td>
                    <td class="text-right">{{ count.toLocaleString() }}</td>
                    <td class="text-right">
                      {{ stats.total_requests > 0 ? ((count / stats.total_requests) * 100).toFixed(2) : 0 }}%
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="row">
      <div class="col-md-12">
        <div class="card">
          <div class="card-header">
            <h5 class="card-title mb-0">最近日志</h5>
          </div>
          <div class="card-body">
            <div v-if="logs.length === 0" class="text-center py-4">
              <p class="text-muted">暂无日志数据</p>
            </div>
            <div v-else class="table-responsive">
              <table class="table table-sm table-hover">
                <thead>
                  <tr>
                    <th>时间</th>
                    <th>IP地址</th>
                    <th>方法</th>
                    <th>URI</th>
                    <th>状态</th>
                    <th>原因</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(log, index) in logs.slice(0, 10)" :key="index" :class="{'table-danger': log.is_blocked}">
                    <td>{{ formatDate(log.timestamp) }}</td>
                    <td>{{ log.client_ip }}</td>
                    <td>{{ log.method }}</td>
                    <td class="text-truncate" style="max-width: 300px;">{{ log.uri }}</td>
                    <td>
                      <span v-if="log.is_blocked" class="badge badge-danger">已阻止</span>
                      <span v-else class="badge badge-success">通过</span>
                    </td>
                    <td>{{ log.reason || '-' }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div class="text-center mt-3">
              <router-link to="/logs" class="btn btn-sm btn-outline-primary">查看所有日志</router-link>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios';
import moment from 'moment';

export default {
  name: 'Dashboard',
  data() {
    return {
      stats: {
        total_requests: 0,
        blocked_requests: 0,
        sites: {}
      },
      logs: []
    };
  },
  created() {
    this.fetchData();
  },
  methods: {
    async fetchData() {
      try {
        const [statsResponse, logsResponse] = await Promise.all([
          axios.get('/api/stats'),
          axios.get('/api/logs?limit=10')
        ]);
        
        if (statsResponse.data.success) {
          this.stats = statsResponse.data.data;
        }
        
        if (logsResponse.data.success) {
          this.logs = logsResponse.data.data;
        }
      } catch (error) {
        console.error('Error fetching dashboard data:', error);
        this.$toast.error('获取仪表盘数据失败');
      }
    },
    refreshStats() {
      this.fetchData();
    },
    formatDate(timestamp) {
      return moment.unix(timestamp).format('YYYY-MM-DD HH:mm:ss');
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
.display-4 {
  font-size: 2.5rem;
  opacity: 0.8;
}
</style>
