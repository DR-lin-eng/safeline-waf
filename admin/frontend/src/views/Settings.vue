<template>
  <div class="settings">
    <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
      <h1 class="h2">系统设置</h1>
      <div class="btn-toolbar mb-2 mb-md-0">
        <button type="button" class="btn btn-sm btn-primary" @click="saveSettings">
          <i class="bi bi-save mr-1"></i> 保存设置
        </button>
      </div>
    </div>

    <div class="row mb-4">
      <div class="col-md-12">
        <div class="alert alert-info" role="alert">
          <i class="bi bi-info-circle-fill mr-2"></i>
          这些设置将应用于所有站点的默认配置。您也可以在站点配置中单独覆盖这些设置。
        </div>
      </div>
    </div>

    <div v-if="loading" class="text-center py-5">
      <div class="spinner-border text-primary" role="status">
        <span class="sr-only">加载中...</span>
      </div>
      <p class="mt-2">加载设置...</p>
    </div>
    <div v-else>
      <div class="row">
        <div class="col-md-6">
          <div class="card mb-4">
            <div class="card-header">
              <h5 class="card-title mb-0">DDoS 防护设置</h5>
            </div>
            <div class="card-body">
              <div class="form-group">
                <label for="urlThreshold">URL 请求阈值</label>
                <input 
                  type="number" 
                  class="form-control" 
                  id="urlThreshold" 
                  v-model="config.ddos_protection.url_threshold"
                  min="1"
                >
                <small class="form-text text-muted">单个 URL 的请求阈值</small>
              </div>
              
              <div class="form-group">
                <label for="urlWindow">URL 时间窗口 (秒)</label>
                <input 
                  type="number" 
                  class="form-control" 
                  id="urlWindow" 
                  v-model="config.ddos_protection.url_window"
                  min="1"
                >
                <small class="form-text text-muted">统计 URL 请求的时间窗口</small>
              </div>
              
              <div class="form-group">
                <label for="ipThreshold">IP 请求阈值</label>
                <input 
                  type="number" 
                  class="form-control" 
                  id="ipThreshold" 
                  v-model="config.ddos_protection.ip_threshold"
                  min="1"
                >
                <small class="form-text text-muted">单个 IP 的总请求阈值</small>
              </div>
              
              <div class="form-group">
                <label for="ipWindow">IP 时间窗口 (秒)</label>
                <input 
                  type="number" 
                  class="form-control" 
                  id="ipWindow" 
                  v-model="config.ddos_protection.ip_window"
                  min="1"
                >
                <small class="form-text text-muted">统计 IP 请求的时间窗口</small>
              </div>
              
              <div class="form-check">
                <input type="checkbox" class="form-check-input" id="dynamicScaling" v-model="config.ddos_protection.dynamic_scaling">
                <label class="form-check-label" for="dynamicScaling">启用动态扩展</label>
                <small class="form-text text-muted">根据全局流量动态调整阈值</small>
              </div>
            </div>
          </div>

          <div class="card mb-4">
            <div class="card-header">
              <h5 class="card-title mb-0">慢速 DDoS 设置</h5>
            </div>
            <div class="card-body">
              <div class="form-group">
                <label for="connectionThreshold">连接阈值</label>
                <input 
                  type="number" 
                  class="form-control" 
                  id="connectionThreshold" 
                  v-model="config.slow_ddos.connection_threshold"
                  min="1"
                >
                <small class="form-text text-muted">单个 IP 的最大连接数</small>
              </div>
              
              <div class="form-group">
                <label for="slowWindow">时间窗口 (秒)</label>
                <input 
                  type="number" 
                  class="form-control" 
                  id="slowWindow" 
                  v-model="config.slow_ddos.window"
                  min="1"
                >
                <small class="form-text text-muted">统计连接的时间窗口</small>
              </div>
            </div>
          </div>
        </div>
        
        <div class="col-md-6">
          <div class="card mb-4">
            <div class="card-header">
              <h5 class="card-title mb-0">Anti-CC 设置</h5>
            </div>
            <div class="card-body">
              <div class="form-group">
                <label for="ccThreshold">CC 阈值</label>
                <input 
                  type="number" 
                  class="form-control" 
                  id="ccThreshold" 
                  v-model="config.anti_cc.cc_threshold"
                  min="1"
                >
                <small class="form-text text-muted">单个 URL 的 CC 请求阈值</small>
              </div>
              
              <div class="form-group">
                <label for="ccTimeWindow">时间窗口 (秒)</label>
                <input 
                  type="number" 
                  class="form-control" 
                  id="ccTimeWindow" 
                  v-model="config.anti_cc.cc_time_window"
                  min="1"
                >
                <small class="form-text text-muted">统计 CC 请求的时间窗口</small>
              </div>
              
              <div class="form-group">
                <label for="ccRequestCount">请求计数</label>
                <input 
                  type="number" 
                  class="form-control" 
                  id="ccRequestCount" 
                  v-model="config.anti_cc.cc_request_count"
                  min="1"
                >
                <small class="form-text text-muted">触发 CC 防护的请求数</small>
              </div>
            </div>
          </div>

          <div class="card mb-4">
            <div class="card-header">
              <h5 class="card-title mb-0">POW 工作量证明设置</h5>
            </div>
            <div class="card-body">
              <div class="form-group">
                <label for="powBaseDifficulty">基础难度 (1-10)</label>
                <input 
                  type="number" 
                  class="form-control" 
                  id="powBaseDifficulty" 
                  v-model="config.pow_config.base_difficulty"
                  min="1"
                  max="10"
                >
                <small class="form-text text-muted">POW 验证的基础难度</small>
              </div>
              
              <div class="form-group">
                <label for="powMaxDifficulty">最大难度 (1-15)</label>
                <input 
                  type="number" 
                  class="form-control" 
                  id="powMaxDifficulty" 
                  v-model="config.pow_config.max_difficulty"
                  min="1"
                  max="15"
                >
                <small class="form-text text-muted">POW 验证的最大难度</small>
              </div>
            </div>
          </div>

          <div class="card mb-4">
            <div class="card-header">
              <h5 class="card-title mb-0">行为分析设置</h5>
            </div>
            <div class="card-body">
              <div class="form-group">
                <label for="windowSize">窗口大小 (秒)</label>
                <input 
                  type="number" 
                  class="form-control" 
                  id="windowSize" 
                  v-model="config.behavior_analysis.window_size"
                  min="1"
                >
                <small class="form-text text-muted">行为分析的时间窗口</small>
              </div>
              
              <div class="form-group">
                <label for="minRequests">最小请求数</label>
                <input 
                  type="number" 
                  class="form-control" 
                  id="minRequests" 
                  v-model="config.behavior_analysis.min_requests"
                  min="1"
                >
                <small class="form-text text-muted">进行行为分析的最小请求数</small>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="row">
        <div class="col-md-12">
          <div class="card mb-4">
            <div class="card-header">
              <h5 class="card-title mb-0">蜜罐设置</h5>
            </div>
            <div class="card-body">
              <div class="form-check mb-3">
                <input type="checkbox" class="form-check-input" id="honeypotEnabled" v-model="config.honeypot_settings.enabled">
                <label class="form-check-label" for="honeypotEnabled">启用蜜罐功能</label>
              </div>
              
              <div class="form-group">
                <label>蜜罐陷阱链接</label>
                <div v-for="(trap, index) in config.honeypot_settings.traps" :key="index" class="input-group mb-2">
                  <input type="text" class="form-control" v-model="config.honeypot_settings.traps[index]">
                  <div class="input-group-append">
                    <button class="btn btn-outline-danger" type="button" @click="removeTrap(index)">
                      <i class="bi bi-trash"></i>
                    </button>
                  </div>
                </div>
                <button class="btn btn-sm btn-outline-primary" @click="addTrap">
                  <i class="bi bi-plus-circle"></i> 添加陷阱链接
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="row mb-4">
        <div class="col-md-12">
          <div class="card">
            <div class="card-header">
              <h5 class="card-title mb-0">高级设置</h5>
            </div>
            <div class="card-body">
              <div class="form-row">
                <div class="form-group col-md-6">
                  <label for="jsRenewInterval">JS 加密更新间隔 (秒)</label>
                  <input 
                    type="number" 
                    class="form-control" 
                    id="jsRenewInterval" 
                    v-model="config.js_encryption.renew_interval"
                    min="1"
                  >
                  <small class="form-text text-muted">JavaScript 加密代码的更新间隔</small>
                </div>
                
                <div class="form-group col-md-6">
                  <label for="jsVarLength">变量名长度</label>
                  <input 
                    type="number" 
                    class="form-control" 
                    id="jsVarLength" 
                    v-model="config.js_encryption.variable_name_length"
                    min="4"
                  >
                  <small class="form-text text-muted">加密 JS 中变量名的长度</small>
                </div>
              </div>
              
              <div class="form-row">
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="samplingEnabled" v-model="config.sampling.enabled">
                    <label class="form-check-label" for="samplingEnabled">启用请求抽样</label>
                  </div>
                </div>
                
                <div class="form-group col-md-4">
                  <label for="samplingRate">抽样率</label>
                  <input 
                    type="number" 
                    class="form-control" 
                    id="samplingRate" 
                    v-model="config.sampling.rate"
                    min="0.001"
                    max="1"
                    step="0.001"
                  >
                  <small class="form-text text-muted">请求抽样分析的比例(0-1)</small>
                </div>
                
                <div class="form-group col-md-4">
                  <label for="anomalyThreshold">异常阈值</label>
                  <input 
                    type="number" 
                    class="form-control" 
                    id="anomalyThreshold" 
                    v-model="config.sampling.anomaly_threshold"
                    min="1"
                    step="0.1"
                  >
                  <small class="form-text text-muted">异常检测的阈值</small>
                </div>
              </div>
              
              <div class="form-row mt-3">
                <div class="col-md-12">
                  <div class="form-group">
                    <label for="logLevel">日志级别</label>
                    <select class="form-control" id="logLevel" v-model="config.global.log_level">
                      <option value="debug">调试</option>
                      <option value="info">信息</option>
                      <option value="warn">警告</option>
                      <option value="error">错误</option>
                    </select>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 保存确认模态框 -->
    <div class="modal fade" id="saveModal" tabindex="-1" aria-labelledby="saveModalLabel" aria-hidden="true">
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="saveModalLabel">确认保存设置</h5>
            <button type="button" class="close" data-dismiss="modal" aria-label="Close">
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div class="modal-body">
            <p>您确定要保存这些设置吗？保存后将立即生效，可能需要重新加载所有站点的配置。</p>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-dismiss="modal">取消</button>
            <button type="button" class="btn btn-primary" @click="confirmSaveSettings">确认保存</button>
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
  name: 'Settings',
  data() {
    return {
      loading: true,
      config: {
        global: {
          log_level: 'info',
          default_action: 'allow'
        },
        ddos_protection: {
          url_threshold: 60,
          url_window: 60,
          ip_threshold: 300,
          ip_window: 60,
          dynamic_scaling: true
        },
        slow_ddos: {
          connection_threshold: 10,
          window: 60
        },
        anti_cc: {
          cc_threshold: 60,
          cc_time_window: 60,
          cc_request_count: 60
        },
        pow_config: {
          base_difficulty: 4,
          max_difficulty: 8
        },
        behavior_analysis: {
          window_size: 60,
          min_requests: 10
        },
        js_encryption: {
          renew_interval: 3600,
          variable_name_length: 8
        },
        honeypot_settings: {
          enabled: true,
          traps: [
            "/.well-known/safeline-trap",
            "/admin_access",
            "/wp-login.php",
            "/.git/"
          ]
        },
        sampling: {
          enabled: true,
          rate: 0.01,
          anomaly_threshold: 5.0
        }
      }
    };
  },
  created() {
    this.fetchSettings();
  },
  methods: {
    async fetchSettings() {
      this.loading = true;
      try {
        const response = await axios.get('/api/config');
        if (response.data.success) {
          // 合并配置，保留默认值的属性
          this.mergeConfig(response.data.data);
        }
      } catch (error) {
        console.error('Error fetching settings:', error);
        // Show error toast
      } finally {
        this.loading = false;
      }
    },
    mergeConfig(newConfig) {
      // 递归合并配置对象
      const merge = (target, source) => {
        for (const key in source) {
          if (source.hasOwnProperty(key)) {
            if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
              // 如果属性是对象，递归合并
              if (!target[key]) target[key] = {};
              merge(target[key], source[key]);
            } else {
              // 否则直接赋值
              target[key] = source[key];
            }
          }
        }
      };
      
      merge(this.config, newConfig);
    },
    addTrap() {
      this.config.honeypot_settings.traps.push("");
    },
    removeTrap(index) {
      this.config.honeypot_settings.traps.splice(index, 1);
    },
    saveSettings() {
      $('#saveModal').modal('show');
    },
    async confirmSaveSettings() {
      try {
        const response = await axios.put('/api/config', this.config);
        
        if (response.data.success) {
          // Show success toast
          alert('设置已成功保存');
          $('#saveModal').modal('hide');
        } else {
          alert('保存设置失败: ' + response.data.message);
        }
      } catch (error) {
        console.error('Error saving settings:', error);
        alert('保存设置时发生错误');
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
