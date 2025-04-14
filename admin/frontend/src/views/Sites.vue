<template>
  <div class="sites">
    <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
      <h1 class="h2">站点管理</h1>
      <div class="btn-toolbar mb-2 mb-md-0">
        <button type="button" class="btn btn-sm btn-primary" @click="openAddSiteModal">
          <i class="bi bi-plus-circle mr-1"></i> 添加站点
        </button>
      </div>
    </div>

    <div class="row mb-4">
      <div class="col-md-12">
        <div class="alert alert-info" role="alert">
          <i class="bi bi-info-circle-fill mr-2"></i>
          管理和配置受WAF保护的站点。对于每个站点，您可以单独配置防护功能和验证方式。
        </div>
      </div>
    </div>

    <div class="row">
      <div class="col-md-12">
        <div class="card mb-4">
          <div class="card-header">
            <h5 class="card-title mb-0">站点列表</h5>
          </div>
          <div class="card-body">
            <div v-if="loading" class="text-center py-5">
              <div class="spinner-border text-primary" role="status">
                <span class="sr-only">加载中...</span>
              </div>
              <p class="mt-2">加载站点列表...</p>
            </div>
            <div v-else-if="sites.length === 0" class="text-center py-5">
              <i class="bi bi-exclamation-circle text-muted" style="font-size: 2rem;"></i>
              <p class="mt-2 text-muted">暂无站点，请点击"添加站点"按钮添加一个站点。</p>
            </div>
            <div v-else class="table-responsive">
              <table class="table table-hover">
                <thead>
                  <tr>
                    <th>站点域名</th>
                    <th>后端服务器</th>
                    <th>状态</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="site in sites" :key="site.domain">
                    <td>{{ site.domain }}</td>
                    <td>{{ getSiteBackendServer(site) }}</td>
                    <td>
                      <span 
                        :class="site.enabled ? 'badge badge-success' : 'badge badge-danger'"
                      >
                        {{ site.enabled ? '已启用' : '已禁用' }}
                      </span>
                    </td>
                    <td>
                      <div class="btn-group btn-group-sm">
                        <button class="btn btn-outline-primary" @click="editSite(site)">
                          <i class="bi bi-pencil"></i> 编辑
                        </button>
                        <button class="btn btn-outline-danger" @click="confirmDeleteSite(site)">
                          <i class="bi bi-trash"></i> 删除
                        </button>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 添加/编辑站点模态框 -->
    <div class="modal fade" id="siteModal" tabindex="-1" aria-labelledby="siteModalLabel" aria-hidden="true">
      <div class="modal-dialog modal-lg">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="siteModalLabel">{{ isEditMode ? '编辑站点' : '添加站点' }}</h5>
            <button type="button" class="close" data-dismiss="modal" aria-label="Close">
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div class="modal-body">
            <form @submit.prevent="saveSite">
              <div class="form-row">
                <div class="form-group col-md-6">
                  <label for="domainInput">域名</label>
                  <input 
                    type="text" 
                    class="form-control" 
                    id="domainInput" 
                    v-model="currentSite.domain" 
                    :readonly="isEditMode"
                    required
                  >
                  <small class="form-text text-muted">站点的域名，例如：example.com</small>
                </div>
                <div class="form-group col-md-6">
                  <label for="backendServerInput">后端服务器</label>
                  <input 
                    type="text" 
                    class="form-control" 
                    id="backendServerInput" 
                    v-model="currentSite.backend_server" 
                    required
                  >
                  <small class="form-text text-muted">后端服务器地址，例如：http://192.168.1.10:8080</small>
                </div>
              </div>
              
              <div class="form-check mb-3">
                <input type="checkbox" class="form-check-input" id="enabledCheck" v-model="currentSite.enabled">
                <label class="form-check-label" for="enabledCheck">启用此站点</label>
              </div>
              
              <h5 class="mt-4">防护功能</h5>
              <hr>
              
              <div class="form-row">
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="browserDetectionCheck" v-model="currentSite.protection.browser_detection_enabled">
                    <label class="form-check-label" for="browserDetectionCheck">真实浏览器检测</label>
                  </div>
                </div>
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="environmentDetectionCheck" v-model="currentSite.protection.environment_detection_enabled">
                    <label class="form-check-label" for="environmentDetectionCheck">环境监测</label>
                  </div>
                </div>
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="ipBlacklistCheck" v-model="currentSite.protection.ip_blacklist_enabled">
                    <label class="form-check-label" for="ipBlacklistCheck">IP黑名单</label>
                  </div>
                </div>
              </div>
              
              <div class="form-row">
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="ddosProtectionCheck" v-model="currentSite.protection.ddos_protection_enabled">
                    <label class="form-check-label" for="ddosProtectionCheck">DDoS防护</label>
                  </div>
                </div>
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="antiCCCheck" v-model="currentSite.protection.anti_cc_enabled">
                    <label class="form-check-label" for="antiCCCheck">Anti-CC防护</label>
                  </div>
                </div>
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="randomAttackCheck" v-model="currentSite.protection.random_attack_protection_enabled">
                    <label class="form-check-label" for="randomAttackCheck">随机攻击防护</label>
                  </div>
                </div>
              </div>
              
              <div class="form-row">
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="jsEncryptionCheck" v-model="currentSite.protection.js_encryption_enabled">
                    <label class="form-check-label" for="jsEncryptionCheck">JS加密</label>
                  </div>
                </div>
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="preventF12Check" v-model="currentSite.protection.prevent_browser_f12">
                    <label class="form-check-label" for="preventF12Check">防止浏览器F12</label>
                  </div>
                </div>
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="honeypotCheck" v-model="currentSite.protection.honeypot_enabled">
                    <label class="form-check-label" for="honeypotCheck">蜜罐功能</label>
                  </div>
                </div>
              </div>
              
              <div class="form-row">
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="autoBlacklistCheck" v-model="currentSite.protection.auto_blacklist_enabled">
                    <label class="form-check-label" for="autoBlacklistCheck">自动添加IP黑名单</label>
                  </div>
                </div>
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="requestLoggingCheck" v-model="currentSite.protection.request_logging_enabled">
                    <label class="form-check-label" for="requestLoggingCheck">请求日志记录</label>
                  </div>
                </div>
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="trafficAnalysisCheck" v-model="currentSite.protection.traffic_analysis_enabled">
                    <label class="form-check-label" for="trafficAnalysisCheck">流量动态识别</label>
                  </div>
                </div>
              </div>
              
              <h5 class="mt-4">速率限制</h5>
              <hr>
              
              <div class="form-row">
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="globalRateLimitCheck" v-model="currentSite.protection.global_rate_limit_enabled">
                    <label class="form-check-label" for="globalRateLimitCheck">启用全局速率限制</label>
                  </div>
                </div>
                <div class="form-group col-md-4">
                  <label for="rateLimitCountInput">请求次数</label>
                  <input 
                    type="number" 
                    class="form-control" 
                    id="rateLimitCountInput" 
                    v-model="currentSite.protection.global_rate_limit_count" 
                    :disabled="!currentSite.protection.global_rate_limit_enabled"
                    min="1"
                  >
                </div>
                <div class="form-group col-md-4">
                  <label for="rateLimitWindowInput">时间窗口(秒)</label>
                  <input 
                    type="number" 
                    class="form-control" 
                    id="rateLimitWindowInput" 
                    v-model="currentSite.protection.global_rate_limit_window" 
                    :disabled="!currentSite.protection.global_rate_limit_enabled"
                    min="1"
                  >
                </div>
              </div>
              
              <h5 class="mt-4">验证方式</h5>
              <hr>
              
              <div class="form-row">
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="captchaCheck" v-model="currentSite.verification_methods.captcha_enabled">
                    <label class="form-check-label" for="captchaCheck">验证码</label>
                  </div>
                </div>
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="sliderCaptchaCheck" v-model="currentSite.verification_methods.slider_captcha_enabled">
                    <label class="form-check-label" for="sliderCaptchaCheck">滑块验证</label>
                  </div>
                </div>
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="powCheck" v-model="currentSite.verification_methods.pow_enabled">
                    <label class="form-check-label" for="powCheck">工作量证明(POW)</label>
                  </div>
                </div>
              </div>
              
              <div class="form-row" v-if="currentSite.verification_methods.pow_enabled">
                <div class="form-group col-md-6">
                  <label for="powBaseDifficultyInput">POW基础难度(1-10)</label>
                  <input 
                    type="number" 
                    class="form-control" 
                    id="powBaseDifficultyInput" 
                    v-model="currentSite.verification_methods.pow_base_difficulty" 
                    min="1" 
                    max="10"
                  >
                </div>
                <div class="form-group col-md-6">
                  <label for="powMaxDifficultyInput">POW最大难度(1-15)</label>
                  <input 
                    type="number" 
                    class="form-control" 
                    id="powMaxDifficultyInput" 
                    v-model="currentSite.verification_methods.pow_max_difficulty" 
                    min="1" 
                    max="15"
                  >
                </div>
              </div>
              
              <h6>验证方式关联</h6>
              <div class="form-row">
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="ipAddressCheck" v-model="currentSite.verification_methods.verification_methods.ip_address">
                    <label class="form-check-label" for="ipAddressCheck">IP地址</label>
                  </div>
                </div>
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="userAgentCheck" v-model="currentSite.verification_methods.verification_methods.user_agent">
                    <label class="form-check-label" for="userAgentCheck">User-Agent</label>
                  </div>
                </div>
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="cookieCheck" v-model="currentSite.verification_methods.verification_methods.cookie">
                    <label class="form-check-label" for="cookieCheck">Cookie</label>
                  </div>
                </div>
              </div>
              
              <div class="form-row mt-4">
                <div class="col-12 text-right">
                  <button type="button" class="btn btn-secondary mr-2" data-dismiss="modal">取消</button>
                  <button type="submit" class="btn btn-primary">保存</button>
                </div>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>

    <!-- 删除确认模态框 -->
    <div class="modal fade" id="deleteModal" tabindex="-1" aria-labelledby="deleteModalLabel" aria-hidden="true">
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="deleteModalLabel">确认删除</h5>
            <button type="button" class="close" data-dismiss="modal" aria-label="Close">
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div class="modal-body">
            <p>您确定要删除 <strong>{{ siteToDelete ? siteToDelete.domain : '' }}</strong> 站点吗？</p>
            <p class="text-danger">此操作不可逆，删除后该站点的所有配置将被永久移除。</p>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-dismiss="modal">取消</button>
            <button type="button" class="btn btn-danger" @click="deleteSite">确认删除</button>
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
  name: 'Sites',
  data() {
    return {
      sites: [],
      loading: true,
      isEditMode: false,
      siteToDelete: null,
      currentSite: this.getEmptySite()
    };
  },
  created() {
    this.fetchSites();
  },
  methods: {
    getEmptySite() {
      return {
        domain: '',
        backend_server: 'http://localhost:8080',
        enabled: true,
        protection: {
          browser_detection_enabled: true,
          environment_detection_enabled: true,
          ip_blacklist_enabled: true,
          global_rate_limit_enabled: true,
          global_rate_limit_count: 60,
          global_rate_limit_window: 60,
          ddos_protection_enabled: true,
          random_attack_protection_enabled: true,
          anti_cc_enabled: true,
          automation_detection_enabled: true,
          traffic_analysis_enabled: true,
          request_sampling_enabled: true,
          sampling_rate: 0.01,
          anomaly_threshold: 5.0,
          js_encryption_enabled: true,
          prevent_browser_f12: true,
          honeypot_enabled: true,
          auto_blacklist_enabled: true,
          request_logging_enabled: true
        },
        verification_methods: {
          captcha_enabled: true,
          slider_captcha_enabled: true,
          pow_enabled: true,
          pow_base_difficulty: 4,
          pow_max_difficulty: 8,
          verification_methods: {
            ip_address: true,
            user_agent: true,
            cookie: true
          }
        }
      };
    },
    async fetchSites() {
      this.loading = true;
      try {
        const response = await axios.get('/api/sites');
        if (response.data.success) {
          this.sites = response.data.data;
        }
      } catch (error) {
        console.error('Error fetching sites:', error);
        // Show error toast
      } finally {
        this.loading = false;
      }
    },
    getSiteBackendServer(site) {
      if (site.filename) {
        // Site list from API doesn't include backend_server, need to fetch full details
        return '点击编辑查看详情';
      }
      return site.backend_server || 'N/A';
    },
    openAddSiteModal() {
      this.isEditMode = false;
      this.currentSite = this.getEmptySite();
      $('#siteModal').modal('show');
    },
    async editSite(site) {
      this.isEditMode = true;
      
      try {
        // Fetch full site details
        const response = await axios.get(`/api/sites/${site.domain}`);
        if (response.data.success) {
          this.currentSite = response.data.data;
          
          // Ensure all required properties exist
          if (!this.currentSite.protection) {
            this.currentSite.protection = this.getEmptySite().protection;
          }
          
          if (!this.currentSite.verification_methods) {
            this.currentSite.verification_methods = this.getEmptySite().verification_methods;
          }
          
          if (!this.currentSite.verification_methods.verification_methods) {
            this.currentSite.verification_methods.verification_methods = {
              ip_address: true,
              user_agent: true,
              cookie: true
            };
          }
          
          $('#siteModal').modal('show');
        }
      } catch (error) {
        console.error('Error fetching site details:', error);
        // Show error toast
      }
    },
    async saveSite() {
      try {
        const domain = this.currentSite.domain;
        
        // Validate domain
        if (!domain || !/^[a-zA-Z0-9][a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}$/.test(domain)) {
          // Show error toast for invalid domain
          return;
        }
        
        // Validate backend server
        if (!this.currentSite.backend_server || !this.currentSite.backend_server.startsWith('http')) {
          // Show error toast for invalid backend server
          return;
        }
        
        const response = await axios.put(`/api/sites/${domain}`, this.currentSite);
        
        if (response.data.success) {
          // Show success toast
          await this.fetchSites();
          $('#siteModal').modal('hide');
        }
      } catch (error) {
        console.error('Error saving site:', error);
        // Show error toast
      }
    },
    confirmDeleteSite(site) {
      this.siteToDelete = site;
      $('#deleteModal').modal('show');
    },
    async deleteSite() {
      if (!this.siteToDelete) return;
      
      try {
        const domain = this.siteToDelete.domain;
        const response = await axios.delete(`/api/sites/${domain}`);
        
        if (response.data.success) {
          // Show success toast
          this.sites = this.sites.filter(site => site.domain !== domain);
          $('#deleteModal').modal('hide');
        }
      } catch (error) {
        console.error('Error deleting site:', error);
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
