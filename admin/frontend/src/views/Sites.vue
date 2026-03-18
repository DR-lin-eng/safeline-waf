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
              <div v-if="siteFormError" class="alert alert-danger" role="alert">
                {{ siteFormError }}
              </div>
              <div v-if="siteFormMessage" class="alert alert-success" role="alert">
                {{ siteFormMessage }}
              </div>
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
                <div class="form-group col-md-8">
                  <label for="backendServerInput">后端服务器</label>
                  <input 
                    type="text" 
                    class="form-control" 
                    id="backendServerInput" 
                    v-model="currentSite.backend_server" 
                    required
                  >
                  <small class="form-text text-muted">后端服务器地址，例如：http://192.168.1.10:8080 或 https://origin.example.com:443</small>
                </div>
                <div class="form-group col-md-4 d-flex align-items-end">
                  <div class="form-check mb-2">
                    <input type="checkbox" class="form-check-input" id="backendPortFollowCheck" v-model="currentSite.backend_port_follow">
                    <label class="form-check-label" for="backendPortFollowCheck">后端端口跟随(80/443)</label>
                  </div>
                </div>
              </div>
              
              <h5 class="mt-2">HTTPS / TLS</h5>
              <hr>

              <div class="form-check mb-2">
                <input type="checkbox" class="form-check-input" id="tlsEnabledCheck" v-model="currentSite.tls.enabled">
                <label class="form-check-label" for="tlsEnabledCheck">Enable HTTPS (443)</label>
              </div>

              <div class="form-row" v-if="currentSite.tls.enabled">
                <div class="form-group col-md-6">
                  <label for="tlsCertPathInput">Certificate Path (crt/pem)</label>
                  <input
                    type="text"
                    class="form-control"
                    id="tlsCertPathInput"
                    v-model="currentSite.tls.cert_path"
                    required
                  >
                </div>
                <div class="form-group col-md-6">
                  <label for="tlsKeyPathInput">Private Key Path (key)</label>
                  <input
                    type="text"
                    class="form-control"
                    id="tlsKeyPathInput"
                    v-model="currentSite.tls.key_path"
                    required
                  >
                </div>
              </div>

              <div class="form-row" v-if="currentSite.tls.enabled">
                <div class="form-group col-md-6">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="tlsRedirectCheck" v-model="currentSite.tls.redirect_http_to_https">
                    <label class="form-check-label" for="tlsRedirectCheck">Redirect HTTP to HTTPS</label>
                  </div>
                </div>
                <div class="form-group col-md-6">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="tlsHttp2Check" v-model="currentSite.tls.http2_enabled">
                    <label class="form-check-label" for="tlsHttp2Check">Enable HTTP/2</label>
                  </div>
                </div>
              </div>

              <small class="form-text text-muted mb-3" v-if="currentSite.tls.enabled">
                Put certificate files in <code>./config/certs/</code>, container path: <code>/usr/local/openresty/nginx/conf/config/certs/</code>
              </small>

              <div class="card mb-3" v-if="currentSite.tls.enabled">
                <div class="card-body py-3">
                  <label class="d-block mb-2">Certificate Upload Mode</label>
                  <div class="form-check form-check-inline">
                    <input class="form-check-input" type="radio" id="certUploadFileMode" value="file" v-model="certUploadMode">
                    <label class="form-check-label" for="certUploadFileMode">Upload Files</label>
                  </div>
                  <div class="form-check form-check-inline">
                    <input class="form-check-input" type="radio" id="certUploadTextMode" value="text" v-model="certUploadMode">
                    <label class="form-check-label" for="certUploadTextMode">Paste Content</label>
                  </div>

                  <div class="mt-3" v-if="certUploadMode === 'file'">
                    <div class="form-row">
                      <div class="form-group col-md-6">
                        <label for="uploadCertFileInput">Certificate File</label>
                        <input type="file" class="form-control-file" id="uploadCertFileInput" @change="onCertFileChange('cert', $event)">
                      </div>
                      <div class="form-group col-md-6">
                        <label for="uploadKeyFileInput">Key File</label>
                        <input type="file" class="form-control-file" id="uploadKeyFileInput" @change="onCertFileChange('key', $event)">
                      </div>
                    </div>
                    <div class="form-row">
                      <div class="form-group col-md-6">
                        <label for="uploadCertFilenameInput">Certificate Filename (Optional)</label>
                        <input type="text" class="form-control" id="uploadCertFilenameInput" v-model="certUpload.certFilename" placeholder="example.com.crt">
                      </div>
                      <div class="form-group col-md-6">
                        <label for="uploadKeyFilenameInput">Key Filename (Optional)</label>
                        <input type="text" class="form-control" id="uploadKeyFilenameInput" v-model="certUpload.keyFilename" placeholder="example.com.key">
                      </div>
                    </div>
                    <button type="button" class="btn btn-outline-primary btn-sm" :disabled="certUpload.uploading" @click="uploadCertificateFiles">
                      {{ certUpload.uploading ? 'Uploading...' : 'Upload Certificate Files' }}
                    </button>
                  </div>

                  <div class="mt-3" v-else>
                    <div class="form-row">
                      <div class="form-group col-md-6">
                        <label for="uploadCertContentInput">Certificate Content</label>
                        <textarea class="form-control" id="uploadCertContentInput" rows="6" v-model="certUpload.certContent" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
                      </div>
                      <div class="form-group col-md-6">
                        <label for="uploadKeyContentInput">Key Content</label>
                        <textarea class="form-control" id="uploadKeyContentInput" rows="6" v-model="certUpload.keyContent" placeholder="-----BEGIN PRIVATE KEY-----"></textarea>
                      </div>
                    </div>
                    <div class="form-row">
                      <div class="form-group col-md-6">
                        <label for="uploadTextCertFilenameInput">Certificate Filename (Optional)</label>
                        <input type="text" class="form-control" id="uploadTextCertFilenameInput" v-model="certUpload.certFilename" placeholder="example.com.crt">
                      </div>
                      <div class="form-group col-md-6">
                        <label for="uploadTextKeyFilenameInput">Key Filename (Optional)</label>
                        <input type="text" class="form-control" id="uploadTextKeyFilenameInput" v-model="certUpload.keyFilename" placeholder="example.com.key">
                      </div>
                    </div>
                    <button type="button" class="btn btn-outline-primary btn-sm" :disabled="certUpload.uploading" @click="uploadCertificateContent">
                      {{ certUpload.uploading ? 'Uploading...' : 'Upload Certificate Content' }}
                    </button>
                  </div>

                  <div class="alert alert-success py-2 mt-3 mb-0" v-if="certUpload.message">
                    {{ certUpload.message }}
                  </div>
                  <div class="alert alert-danger py-2 mt-3 mb-0" v-if="certUpload.error">
                    {{ certUpload.error }}
                  </div>
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

              <div class="form-row">
                <div class="form-group col-md-4">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="requestInspectionCheck" v-model="currentSite.protection.request_content_inspection_enabled">
                    <label class="form-check-label" for="requestInspectionCheck">请求内容检测</label>
                  </div>
                </div>
                <div class="form-group col-md-4">
                  <label for="requestBodyMaxBytesInput">请求体扫描上限 (Bytes)</label>
                  <input
                    type="number"
                    class="form-control"
                    id="requestBodyMaxBytesInput"
                    v-model="currentSite.protection.request_body_max_bytes"
                    :disabled="!currentSite.protection.request_content_inspection_enabled"
                    min="1024"
                    step="1024"
                  >
                </div>
                <div class="form-group col-md-4">
                  <label for="requestFieldMaxLenInput">单字段最大长度 (Bytes)</label>
                  <input
                    type="number"
                    class="form-control"
                    id="requestFieldMaxLenInput"
                    v-model="currentSite.protection.request_field_max_len"
                    :disabled="!currentSite.protection.request_content_inspection_enabled"
                    min="256"
                    step="256"
                  >
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

              <div class="form-row">
                <div class="form-group col-md-6">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="originProxyOnlyCheck" v-model="currentSite.protection.origin_proxy_only_enabled">
                    <label class="form-check-label" for="originProxyOnlyCheck">仅允许可信代理回源</label>
                  </div>
                  <small class="form-text text-muted">启用后，非可信代理直接访问源站将被丢弃。</small>
                </div>
                <div class="form-group col-md-6">
                  <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="sliderStepUpCheck" v-model="currentSite.verification_methods.slider_step_up_on_high_risk">
                    <label class="form-check-label" for="sliderStepUpCheck">高风险滑块自动升级</label>
                  </div>
                  <small class="form-text text-muted">高风险场景下，滑块通过后自动升级到更强验证。</small>
                </div>
              </div>

              <div class="form-row">
                <div class="form-group col-md-4">
                  <label for="sliderVerificationTtlInput">滑块放行 TTL (秒)</label>
                  <input
                    type="number"
                    class="form-control"
                    id="sliderVerificationTtlInput"
                    v-model="currentSite.verification_methods.slider_verification_ttl"
                    min="60"
                    max="3600"
                  >
                </div>
                <div class="form-group col-md-4">
                  <label for="captchaVerificationTtlInput">验证码放行 TTL (秒)</label>
                  <input
                    type="number"
                    class="form-control"
                    id="captchaVerificationTtlInput"
                    v-model="currentSite.verification_methods.captcha_verification_ttl"
                    min="60"
                    max="7200"
                  >
                </div>
                <div class="form-group col-md-4">
                  <label for="powVerificationTtlInput">POW 放行 TTL (秒)</label>
                  <input
                    type="number"
                    class="form-control"
                    id="powVerificationTtlInput"
                    v-model="currentSite.verification_methods.pow_verification_ttl"
                    min="60"
                    max="7200"
                  >
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
import { getApiErrorMessage, shouldHandleLocally } from '../utils/http';

export default {
  name: 'Sites',
  data() {
    return {
      sites: [],
      loading: true,
      isEditMode: false,
      siteToDelete: null,
      currentSite: this.getEmptySite(),
      siteFormMessage: '',
      siteFormError: '',
      certUploadMode: 'file',
      certUpload: {
        certFile: null,
        keyFile: null,
        certContent: '',
        keyContent: '',
        certFilename: '',
        keyFilename: '',
        uploading: false,
        message: '',
        error: ''
      }
    };
  },
  created() {
    this.fetchSites();
  },
  methods: {
    validateDomainInput(value) {
      const domain = String(value || '').trim().toLowerCase();
      return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(domain);
    },
    validateBackendServerInput(value) {
      const raw = String(value || '').trim();
      if (!raw) {
        return { valid: false, normalized: '', message: 'Backend server is required.' };
      }

      let parsed;
      try {
        parsed = new URL(raw);
      } catch (_) {
        return { valid: false, normalized: '', message: 'Backend server must be a valid URL.' };
      }

      const protocol = String(parsed.protocol || '').toLowerCase();
      if (protocol !== 'http:' && protocol !== 'https:') {
        return { valid: false, normalized: '', message: 'Backend server must use http:// or https://.' };
      }

      if (!parsed.hostname) {
        return { valid: false, normalized: '', message: 'Backend server hostname is required.' };
      }

      if (parsed.username || parsed.password) {
        return { valid: false, normalized: '', message: 'Backend server URL must not include credentials.' };
      }

      if (parsed.port) {
        const port = Number(parsed.port);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
          return { valid: false, normalized: '', message: 'Backend server port must be between 1 and 65535.' };
        }
      }

      return { valid: true, normalized: raw.replace(/\/$/, ''), message: '' };
    },
    getDefaultTlsConfig(domain = '') {
      const normalizedDomain = String(domain || '').toLowerCase();
      const hasDomain = /^[a-z0-9.-]+$/.test(normalizedDomain);
      const certName = hasDomain ? normalizedDomain : 'example.com';
      return {
        enabled: false,
        cert_path: `/usr/local/openresty/nginx/conf/config/certs/${certName}.crt`,
        key_path: `/usr/local/openresty/nginx/conf/config/certs/${certName}.key`,
        redirect_http_to_https: true,
        http2_enabled: true
      };
    },
    ensureTlsConfig() {
      const defaultTlsConfig = this.getDefaultTlsConfig(this.currentSite.domain);
      if (!this.currentSite.tls) {
        this.currentSite.tls = defaultTlsConfig;
        return;
      }

      this.currentSite.tls = {
        ...defaultTlsConfig,
        ...this.currentSite.tls
      };
    },
    ensureBackendPortFollow() {
      this.currentSite.backend_port_follow = this.currentSite.backend_port_follow === true;
    },
    resetSiteFormStatus() {
      this.siteFormMessage = '';
      this.siteFormError = '';
    },
    resetCertUploadState() {
      this.certUploadMode = 'file';
      this.certUpload = {
        certFile: null,
        keyFile: null,
        certContent: '',
        keyContent: '',
        certFilename: '',
        keyFilename: '',
        uploading: false,
        message: '',
        error: ''
      };
    },
    onCertFileChange(type, event) {
      if (type !== 'cert' && type !== 'key') {
        return;
      }
      const files = event && event.target && event.target.files ? event.target.files : [];
      this.certUpload[`${type}File`] = files.length > 0 ? files[0] : null;
    },
    getValidatedDomainForCertUpload() {
      const domain = String(this.currentSite.domain || '').toLowerCase().trim();
      if (!domain || !/^[a-z0-9][a-z0-9-_.]+\.[a-z]{2,}$/.test(domain)) {
        return '';
      }
      return domain;
    },
    applyCertificateUploadResult(data, fallbackMessage) {
      if (!data) {
        this.certUpload.message = fallbackMessage;
        return;
      }

      this.currentSite.tls.cert_path = data.cert_path;
      this.currentSite.tls.key_path = data.key_path;
      this.currentSite.tls.enabled = true;

      const validation = data.validation || {};
      const domain = validation.domain || this.currentSite.domain || 'current domain';
      const validTo = validation.valid_to ? String(validation.valid_to).slice(0, 10) : '';
      const daysLeft = typeof validation.days_remaining === 'number' ? validation.days_remaining : null;

      if (validTo && daysLeft !== null) {
        this.certUpload.message = `Certificate validated for ${domain}, expires on ${validTo} (${daysLeft} days left).`;
      } else {
        this.certUpload.message = fallbackMessage;
      }
    },
    async uploadCertificateFiles() {
      this.ensureTlsConfig();
      this.certUpload.error = '';
      this.certUpload.message = '';

      const domain = this.getValidatedDomainForCertUpload();
      if (!domain) {
        this.certUpload.error = 'Please enter a valid site domain before uploading certificates.';
        return;
      }

      if (!this.certUpload.certFile || !this.certUpload.keyFile) {
        this.certUpload.error = 'Please select both certificate and key files.';
        return;
      }

      const formData = new FormData();
      formData.append('cert_file', this.certUpload.certFile);
      formData.append('key_file', this.certUpload.keyFile);
      formData.append('domain', domain);
      if (this.certUpload.certFilename) {
        formData.append('cert_filename', this.certUpload.certFilename);
      }
      if (this.certUpload.keyFilename) {
        formData.append('key_filename', this.certUpload.keyFilename);
      }

      this.certUpload.uploading = true;
      try {
        const response = await axios.post('/certificates/upload', formData, {
          headers: { 'Content-Type': 'multipart/form-data' }
        });
        if (response.data && response.data.success) {
          this.applyCertificateUploadResult(response.data.data, 'Certificate files uploaded successfully.');
        } else {
          this.certUpload.error = (response.data && response.data.message) || 'Certificate upload failed.';
        }
      } catch (error) {
        this.certUpload.error = (error.response && error.response.data && error.response.data.message)
          || 'Certificate upload failed.';
      } finally {
        this.certUpload.uploading = false;
      }
    },
    async uploadCertificateContent() {
      this.ensureTlsConfig();
      this.certUpload.error = '';
      this.certUpload.message = '';

      const domain = this.getValidatedDomainForCertUpload();
      if (!domain) {
        this.certUpload.error = 'Please enter a valid site domain before uploading certificates.';
        return;
      }

      if (!this.certUpload.certContent.trim() || !this.certUpload.keyContent.trim()) {
        this.certUpload.error = 'Please paste both certificate and key content.';
        return;
      }

      this.certUpload.uploading = true;
      try {
        const response = await axios.post('/certificates/content', {
          domain,
          cert_content: this.certUpload.certContent,
          key_content: this.certUpload.keyContent,
          cert_filename: this.certUpload.certFilename,
          key_filename: this.certUpload.keyFilename
        });
        if (response.data && response.data.success) {
          this.applyCertificateUploadResult(response.data.data, 'Certificate content uploaded successfully.');
        } else {
          this.certUpload.error = (response.data && response.data.message) || 'Certificate content upload failed.';
        }
      } catch (error) {
        this.certUpload.error = (error.response && error.response.data && error.response.data.message)
          || 'Certificate content upload failed.';
      } finally {
        this.certUpload.uploading = false;
      }
    },
    getEmptySite() {
      return {
        domain: '',
        backend_server: 'http://localhost:8080',
        backend_port_follow: false,
        enabled: true,
        tls: this.getDefaultTlsConfig(''),
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
          request_logging_enabled: true,
          request_content_inspection_enabled: true,
          request_body_max_bytes: 32768,
          request_field_max_len: 4096,
          ddos_reverify_window: 120,
          origin_proxy_only_enabled: true
        },
        verification_methods: {
          captcha_enabled: true,
          slider_captcha_enabled: true,
          pow_enabled: true,
          pow_base_difficulty: 4,
          pow_max_difficulty: 8,
          slider_step_up_on_high_risk: true,
          slider_verification_ttl: 300,
          captcha_verification_ttl: 900,
          pow_verification_ttl: 1200,
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
        const response = await axios.get('/sites');
        if (response.data.success) {
          this.sites = response.data.data;
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '获取站点列表失败，请稍后重试。'));
        }
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
      this.resetSiteFormStatus();
      this.resetCertUploadState();
      $('#siteModal').modal('show');
    },
    async editSite(site) {
      this.isEditMode = true;
      
      try {
        // Fetch full site details
        const response = await axios.get(`/sites/${site.domain}`);
        if (response.data.success) {
          this.currentSite = response.data.data;
          const defaults = this.getEmptySite();
          
          // Ensure all required properties exist
          this.currentSite.protection = {
            ...defaults.protection,
            ...(this.currentSite.protection || {})
          };
          
          this.currentSite.verification_methods = {
            ...defaults.verification_methods,
            ...(this.currentSite.verification_methods || {})
          };

          this.currentSite.verification_methods.verification_methods = {
            ...defaults.verification_methods.verification_methods,
            ...(this.currentSite.verification_methods.verification_methods || {})
          };

          this.ensureBackendPortFollow();
          this.ensureTlsConfig();
          this.resetSiteFormStatus();
          this.resetCertUploadState();
          
          $('#siteModal').modal('show');
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '获取站点详情失败，请稍后重试。'));
        }
      }
    },
    async saveSite() {
      try {
        this.resetSiteFormStatus();
        const domain = String(this.currentSite.domain || '').trim().toLowerCase();
        
        // Validate domain
        if (!this.validateDomainInput(domain)) {
          this.siteFormError = 'Domain format is invalid.';
          return;
        }

        this.currentSite.domain = domain;
        
        // Validate backend server
        const backendValidation = this.validateBackendServerInput(this.currentSite.backend_server);
        if (!backendValidation.valid) {
          this.siteFormError = backendValidation.message;
          return;
        }
        this.currentSite.backend_server = backendValidation.normalized;

        this.ensureBackendPortFollow();
        this.ensureTlsConfig();
        if (this.currentSite.protection.request_content_inspection_enabled) {
          const requestBodyMaxBytes = Number(this.currentSite.protection.request_body_max_bytes);
          const requestFieldMaxLen = Number(this.currentSite.protection.request_field_max_len);

          if (!Number.isInteger(requestBodyMaxBytes) || requestBodyMaxBytes < 1024) {
            this.siteFormError = 'Request body scan limit must be at least 1024 bytes.';
            return;
          }

          if (!Number.isInteger(requestFieldMaxLen) || requestFieldMaxLen < 256) {
            this.siteFormError = 'Request field max length must be at least 256 bytes.';
            return;
          }

          if (requestFieldMaxLen > requestBodyMaxBytes) {
            this.siteFormError = 'Request field max length cannot exceed the request body scan limit.';
            return;
          }
        }

        const sliderVerificationTtl = Number(this.currentSite.verification_methods.slider_verification_ttl);
        const captchaVerificationTtl = Number(this.currentSite.verification_methods.captcha_verification_ttl);
        const powVerificationTtl = Number(this.currentSite.verification_methods.pow_verification_ttl);
        const ddosReverifyWindow = Number(this.currentSite.protection.ddos_reverify_window);

        if (!Number.isInteger(ddosReverifyWindow) || ddosReverifyWindow < 10) {
          this.siteFormError = 'DDoS reverify window must be at least 10 seconds.';
          return;
        }

        if (!Number.isInteger(sliderVerificationTtl) || sliderVerificationTtl < 60 || sliderVerificationTtl > 3600) {
          this.siteFormError = 'Slider verification TTL must be between 60 and 3600 seconds.';
          return;
        }

        if (!Number.isInteger(captchaVerificationTtl) || captchaVerificationTtl < 60 || captchaVerificationTtl > 7200) {
          this.siteFormError = 'Captcha verification TTL must be between 60 and 7200 seconds.';
          return;
        }

        if (!Number.isInteger(powVerificationTtl) || powVerificationTtl < 60 || powVerificationTtl > 7200) {
          this.siteFormError = 'POW verification TTL must be between 60 and 7200 seconds.';
          return;
        }

        this.currentSite.protection.ddos_reverify_window = ddosReverifyWindow;
        this.currentSite.verification_methods.slider_verification_ttl = sliderVerificationTtl;
        this.currentSite.verification_methods.captcha_verification_ttl = captchaVerificationTtl;
        this.currentSite.verification_methods.pow_verification_ttl = powVerificationTtl;

        if (this.currentSite.tls.enabled) {
          if (!this.currentSite.tls.cert_path || !this.currentSite.tls.key_path) {
            this.siteFormError = 'TLS is enabled but certificate path or key path is empty.';
            return;
          }

          if (!this.currentSite.tls.cert_path.startsWith('/') || !this.currentSite.tls.key_path.startsWith('/')) {
            this.siteFormError = 'TLS certificate and key paths must be absolute paths.';
            return;
          }
        }
        
        const response = await axios.put(`/sites/${domain}`, this.currentSite);
        
        if (response.data.success) {
          this.siteFormMessage = response.data.message || 'Site saved successfully.';
          await this.fetchSites();
          $('#siteModal').modal('hide');
          this.$toast.success(response.data.message || '站点已保存。');
        } else {
          this.siteFormError = response.data.message || 'Failed to save site.';
        }
      } catch (error) {
        const responseData = error.response && error.response.data ? error.response.data : null;
        const reloadMessage = responseData && responseData.reload && responseData.reload.message
          ? ` Reload detail: ${responseData.reload.message}`
          : '';
        this.siteFormError = (responseData && responseData.message)
          ? `${responseData.message}${reloadMessage}`
          : 'Failed to save site.';
        if (shouldHandleLocally(error)) {
          this.$toast.error(this.siteFormError);
        }
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
        const response = await axios.delete(`/sites/${domain}`);
        
        if (response.data.success) {
          this.sites = this.sites.filter(site => site.domain !== domain);
          $('#deleteModal').modal('hide');
          this.$toast.success(`站点 ${domain} 已删除。`);
          this.siteToDelete = null;
        } else {
          this.$toast.error((response.data && response.data.message) || '删除站点失败。');
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '删除站点失败，请稍后重试。'));
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
