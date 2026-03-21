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
          管理和配置受 WAF 保护的站点。新建站点时可先完成基础接入，再继续补充 HTTPS 与高级防护设置。
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
              <p class="mt-2 text-muted">暂无站点，请点击“添加站点”开始创建。</p>
            </div>
            <div v-else class="table-responsive">
              <table class="table table-hover align-middle">
                <thead>
                  <tr>
                    <th>站点域名</th>
                    <th>回源地址</th>
                    <th>TLS</th>
                    <th>状态</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="site in sites" :key="site.domain">
                    <td>
                      <div class="font-weight-bold">{{ site.domain }}</div>
                    </td>
                    <td>
                      <div>{{ getSiteBackendServer(site) }}</div>
                      <small class="text-muted">{{ getBackendPortFollowLabel(site) }}</small>
                    </td>
                    <td>
                      <span :class="site.tls_enabled ? 'badge badge-success' : 'badge badge-secondary'">
                        {{ site.tls_enabled ? '已启用 HTTPS' : '仅 HTTP' }}
                      </span>
                    </td>
                    <td>
                      <span :class="site.enabled ? 'badge badge-success' : 'badge badge-danger'">
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

    <div class="modal fade" id="siteModal" tabindex="-1" aria-labelledby="siteModalLabel" aria-hidden="true">
      <div class="modal-dialog modal-xl modal-dialog-scrollable">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="siteModalLabel">{{ isEditMode ? '编辑站点' : '新建站点' }}</h5>
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

              <template v-if="!isEditMode">
                <ul class="wizard-steps list-unstyled d-flex flex-wrap mb-4">
                  <li v-for="step in createSteps" :key="step.key" :class="['wizard-step', { active: createStep === step.key, completed: isCreateStepCompleted(step.order) }]">
                    <span class="wizard-step-index">{{ step.order }}</span>
                    <div>
                      <div class="font-weight-bold">{{ step.title }}</div>
                      <small class="text-muted">{{ step.description }}</small>
                    </div>
                  </li>
                </ul>

                <div v-if="createStep === 'basic'">
                  <SiteBasicForm
                    :site="currentSite"
                    :readonly-domain="false"
                    id-prefix="create-basic"
                  />
                  <div class="alert alert-light border mt-3 mb-0">
                    先完成域名与回源地址即可创建 HTTP 站点。若启用 HTTPS，可在下一步上传证书。
                  </div>
                </div>

                <div v-else-if="createStep === 'tls'">
                  <div v-if="currentSite.tls.enabled">
                    <SiteTlsForm
                      :site="currentSite"
                      :upload-mode="certUploadMode"
                      :upload-state="certUpload"
                      :can-upload="canUploadCertificate"
                      id-prefix="create-tls"
                      @update:upload-mode="certUploadMode = $event"
                      @file-change="onCertFileChange"
                      @upload-files="uploadCertificateFiles"
                      @upload-content="uploadCertificateContent"
                    />
                  </div>
                  <div v-else class="alert alert-light border mb-0">
                    当前未启用 HTTPS。你可以直接跳过此步骤，先创建 HTTP 站点，后续再进入编辑模式补充 TLS 配置。
                  </div>
                </div>

                <div v-else-if="createStep === 'protection'">
                  <div class="alert alert-info">
                    默认防护参数已经填充，可直接使用。若你只是先完成接入，可以保持默认值并直接创建站点。
                  </div>
                  <SiteProtectionForm
                    :site="currentSite"
                    :sections="formSections"
                    :compact="true"
                    id-prefix="create-protection"
                    @toggle-section="toggleFormSection"
                  />
                </div>
              </template>

              <template v-else>
                <div class="mb-3">
                  <SiteBasicForm
                    :site="currentSite"
                    :readonly-domain="true"
                    id-prefix="edit-basic"
                  />
                </div>

                <div class="card mb-3">
                  <div class="card-header d-flex justify-content-between align-items-center">
                    <div>
                      <strong>HTTPS / TLS</strong>
                      <div class="small text-muted">证书上传、路径与 TLS 选项。</div>
                    </div>
                    <button type="button" class="btn btn-link btn-sm p-0" @click="toggleFormSection('tls')">
                      {{ formSections.tls ? '收起' : '展开' }}
                    </button>
                  </div>
                  <div class="card-body" v-if="formSections.tls">
                    <div v-if="currentSite.tls.enabled">
                      <SiteTlsForm
                        :site="currentSite"
                        :upload-mode="certUploadMode"
                        :upload-state="certUpload"
                        :can-upload="canUploadCertificate"
                        id-prefix="edit-tls"
                        @update:upload-mode="certUploadMode = $event"
                        @file-change="onCertFileChange"
                        @upload-files="uploadCertificateFiles"
                        @upload-content="uploadCertificateContent"
                      />
                    </div>
                    <div v-else class="text-muted">当前未启用 HTTPS，勾选“启用 HTTPS (443)”后即可配置证书。</div>
                  </div>
                </div>

                <SiteProtectionForm
                  :site="currentSite"
                  :sections="formSections"
                  :compact="false"
                  id-prefix="edit-protection"
                  @toggle-section="toggleFormSection"
                />
              </template>

              <div class="form-row mt-4">
                <div class="col-12 d-flex justify-content-between align-items-center flex-wrap">
                  <div class="text-muted mb-2 mb-md-0" v-if="!isEditMode">
                    {{ getCreateStepHint() }}
                  </div>
                  <div class="ml-auto">
                    <button type="button" class="btn btn-secondary mr-2" data-dismiss="modal">取消</button>
                    <template v-if="!isEditMode">
                      <button v-if="createStep !== 'basic'" type="button" class="btn btn-outline-secondary mr-2" @click="goToPreviousCreateStep">上一步</button>
                      <button v-if="createStep !== 'protection'" type="button" class="btn btn-primary" @click="goToNextCreateStep">下一步</button>
                      <button v-else type="submit" class="btn btn-primary">创建站点</button>
                    </template>
                    <button v-else type="submit" class="btn btn-primary">保存并发布</button>
                  </div>
                </div>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>

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
import SiteBasicForm from '../components/sites/SiteBasicForm.vue';
import SiteTlsForm from '../components/sites/SiteTlsForm.vue';
import SiteProtectionForm from '../components/sites/SiteProtectionForm.vue';

export default {
  name: 'Sites',
  components: {
    SiteBasicForm,
    SiteTlsForm,
    SiteProtectionForm
  },
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
      createStep: 'basic',
      createSteps: [
        { key: 'basic', order: 1, title: '基础信息', description: '域名、回源地址、HTTP/HTTPS' },
        { key: 'tls', order: 2, title: 'HTTPS', description: '证书上传与 TLS 参数' },
        { key: 'protection', order: 3, title: '高级配置', description: '防护、限速与验证方式' }
      ],
      formSections: {
        tls: true,
        protection: false,
        rateLimit: false,
        verification: false
      },
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
      },
      globalDefaults: {
        anti_bypass: {
          origin_proxy_only_default: false,
          slider_step_up_on_high_risk: true,
          slider_verification_ttl: 300,
          captcha_verification_ttl: 900,
          pow_verification_ttl: 1200
        },
        honeypot_settings: {
          enabled: true,
          traps: [
            '/.well-known/safeline-trap',
            '/admin_access',
            '/wp-login.php',
            '/.git/'
          ]
        },
        sampling: {
          enabled: true,
          rate: 0.01,
          anomaly_threshold: 5.0
        },
        adaptive_protection: {
          hard_drop_on_overload: true,
          verified_scrubbing_rps: 20
        },
        owasp_crs: {
          enabled: true,
          paranoia_level: 1,
          inbound_threshold: 5,
          max_matches: 8
        }
      }
    };
  },
  computed: {
    canUploadCertificate() {
      return Boolean(this.getValidatedDomainForCertUpload());
    }
  },
  created() {
    this.fetchSites();
    this.fetchGlobalDefaults();
  },
  methods: {
    validateDomainInput(value) {
      const domain = String(value || '').trim().toLowerCase();
      return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(domain);
    },
    validateBackendServerInput(value) {
      const raw = String(value || '').trim();
      if (!raw) {
        return { valid: false, normalized: '', message: '请填写后端服务器地址。' };
      }

      let parsed;
      try {
        parsed = new URL(raw);
      } catch (_) {
        return { valid: false, normalized: '', message: '后端服务器必须是合法的 URL。' };
      }

      const protocol = String(parsed.protocol || '').toLowerCase();
      if (protocol !== 'http:' && protocol !== 'https:') {
        return { valid: false, normalized: '', message: '后端服务器必须以 http:// 或 https:// 开头。' };
      }

      if (!parsed.hostname) {
        return { valid: false, normalized: '', message: '后端服务器缺少主机名。' };
      }

      if (parsed.username || parsed.password) {
        return { valid: false, normalized: '', message: '后端服务器 URL 中不能包含用户名或密码。' };
      }

      if ((parsed.pathname && parsed.pathname !== '/') || parsed.search || parsed.hash) {
        return { valid: false, normalized: '', message: '后端服务器只能填写协议、主机和端口，不能包含路径、查询参数或片段。' };
      }

      if (parsed.port) {
        const port = Number(parsed.port);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
          return { valid: false, normalized: '', message: '后端服务器端口必须介于 1 到 65535 之间。' };
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
    resetFormSections() {
      this.formSections = {
        tls: true,
        protection: this.isEditMode,
        rateLimit: false,
        verification: false
      };
    },
    async fetchGlobalDefaults() {
      try {
        const response = await axios.get('/config');
        if (response.data && response.data.success) {
          const rootConfig = response.data.data || {};
          const antiBypass = response.data.data && response.data.data.anti_bypass
            ? response.data.data.anti_bypass
            : {};
          const honeypotSettings = rootConfig.honeypot_settings && typeof rootConfig.honeypot_settings === 'object'
            ? rootConfig.honeypot_settings
            : {};
          const sampling = rootConfig.sampling && typeof rootConfig.sampling === 'object'
            ? rootConfig.sampling
            : {};
          const adaptiveProtection = rootConfig.adaptive_protection && typeof rootConfig.adaptive_protection === 'object'
            ? rootConfig.adaptive_protection
            : {};
          const owaspCrs = rootConfig.owasp_crs && typeof rootConfig.owasp_crs === 'object'
            ? rootConfig.owasp_crs
            : {};
          this.globalDefaults.anti_bypass = {
            ...this.globalDefaults.anti_bypass,
            ...antiBypass
          };
          this.globalDefaults.honeypot_settings = {
            ...this.globalDefaults.honeypot_settings,
            ...honeypotSettings
          };
          this.globalDefaults.sampling = {
            ...this.globalDefaults.sampling,
            ...sampling
          };
          this.globalDefaults.adaptive_protection = {
            ...this.globalDefaults.adaptive_protection,
            ...adaptiveProtection
          };
          this.globalDefaults.owasp_crs = {
            ...this.globalDefaults.owasp_crs,
            ...owaspCrs
          };
        }
      } catch (_error) {
        // Keep frontend defaults when global config is temporarily unavailable.
      }
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
      if (!this.validateDomainInput(domain)) {
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
      const domain = validation.domain || this.currentSite.domain || '当前域名';
      const validTo = validation.valid_to ? String(validation.valid_to).slice(0, 10) : '';
      const daysLeft = typeof validation.days_remaining === 'number' ? validation.days_remaining : null;

      if (validTo && daysLeft !== null) {
        this.certUpload.message = `证书已校验通过：${domain}，到期时间 ${validTo}，剩余 ${daysLeft} 天。`;
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
        this.certUpload.error = '请先填写合法域名，再上传证书。';
        return;
      }

      if (!this.certUpload.certFile || !this.certUpload.keyFile) {
        this.certUpload.error = '请同时选择证书文件和私钥文件。';
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
          this.applyCertificateUploadResult(response.data.data, '证书文件上传成功，路径已自动回填。');
        } else {
          this.certUpload.error = (response.data && response.data.message) || '证书上传失败。';
        }
      } catch (error) {
        this.certUpload.error = getApiErrorMessage(error, '证书上传失败。');
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
        this.certUpload.error = '请先填写合法域名，再上传证书。';
        return;
      }

      if (!this.certUpload.certContent.trim() || !this.certUpload.keyContent.trim()) {
        this.certUpload.error = '请同时粘贴证书内容和私钥内容。';
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
          this.applyCertificateUploadResult(response.data.data, '证书内容上传成功，路径已自动回填。');
        } else {
          this.certUpload.error = (response.data && response.data.message) || '证书内容上传失败。';
        }
      } catch (error) {
        this.certUpload.error = getApiErrorMessage(error, '证书内容上传失败。');
      } finally {
        this.certUpload.uploading = false;
      }
    },
    getEmptySite() {
      const antiBypassDefaults = (this.globalDefaults && this.globalDefaults.anti_bypass) || {};
      const honeypotDefaults = (this.globalDefaults && this.globalDefaults.honeypot_settings) || {};
      const samplingDefaults = (this.globalDefaults && this.globalDefaults.sampling) || {};
      const adaptiveDefaults = (this.globalDefaults && this.globalDefaults.adaptive_protection) || {};
      const owaspDefaults = (this.globalDefaults && this.globalDefaults.owasp_crs) || {};
      const defaultSamplingRate = Number(samplingDefaults.rate);
      const defaultAnomalyThreshold = Number(samplingDefaults.anomaly_threshold);
      const defaultVerifiedScrubbingRps = Number(adaptiveDefaults.verified_scrubbing_rps);
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
          credential_stuffing_detection_enabled: true,
          scraping_detection_enabled: true,
          inventory_hoarding_detection_enabled: true,
          ddos_protection_enabled: true,
          slow_ddos_protection_enabled: true,
          random_attack_protection_enabled: true,
          anti_cc_enabled: true,
          automation_detection_enabled: true,
          traffic_analysis_enabled: true,
          request_sampling_enabled: samplingDefaults.enabled !== false,
          sampling_rate: Number.isFinite(defaultSamplingRate) ? defaultSamplingRate : 0.01,
          log_sample_rate: Number.isFinite(defaultSamplingRate) ? defaultSamplingRate : 0.01,
          anomaly_threshold: Number.isFinite(defaultAnomalyThreshold) ? defaultAnomalyThreshold : 5.0,
          js_encryption_enabled: false,
          prevent_browser_f12: false,
          honeypot_enabled: honeypotDefaults.enabled !== false,
          auto_blacklist_enabled: true,
          auto_blacklist_score_threshold: 20,
          auto_blacklist_duration: 900,
          request_logging_enabled: true,
          llm_audit_enabled: true,
          ml_bot_classification_enabled: false,
          ml_bot_challenge_threshold: 0.75,
          ml_bot_ban_threshold: 0.92,
          ml_bot_autoban_enabled: false,
          owasp_crs_enabled: owaspDefaults.enabled !== false,
          owasp_paranoia_level: Number(owaspDefaults.paranoia_level || 1),
          owasp_inbound_threshold: Number(owaspDefaults.inbound_threshold || 5),
          owasp_max_matches: Number(owaspDefaults.max_matches || 8),
          request_content_inspection_enabled: true,
          request_body_max_bytes: 32768,
          request_field_max_len: 4096,
          request_body_max_depth: 32,
          graphql_max_depth: 12,
          max_uri_length: 8192,
          max_header_count: 96,
          max_forwarded_hops: 16,
          ddos_reverify_window: 120,
          stats_sample_rate: 0.01,
          global_hard_drop_enabled: adaptiveDefaults.hard_drop_on_overload === true,
          verified_scrubbing_rps: Number.isFinite(defaultVerifiedScrubbingRps) ? defaultVerifiedScrubbingRps : 20,
          origin_proxy_only_enabled: antiBypassDefaults.origin_proxy_only_default === true,
          challenge_whitelist_paths: []
        },
        verification_methods: {
          captcha_enabled: true,
          slider_captcha_enabled: true,
          pow_enabled: true,
          pow_base_difficulty: 4,
          pow_max_difficulty: 8,
          slider_step_up_on_high_risk: antiBypassDefaults.slider_step_up_on_high_risk !== false,
          slider_verification_ttl: Number(antiBypassDefaults.slider_verification_ttl || 300),
          captcha_verification_ttl: Number(antiBypassDefaults.captcha_verification_ttl || 900),
          pow_verification_ttl: Number(antiBypassDefaults.pow_verification_ttl || 1200),
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
      return site.backend_server || '未配置';
    },
    getBackendPortFollowLabel(site) {
      return site.backend_port_follow
        ? '端口跟随入口端口（只切换 80/443，不切换 http/https）'
        : '固定使用回源地址中的端口';
    },
    async openAddSiteModal() {
      await this.fetchGlobalDefaults();
      this.isEditMode = false;
      this.createStep = 'basic';
      this.currentSite = this.getEmptySite();
      this.resetSiteFormStatus();
      this.resetCertUploadState();
      this.resetFormSections();
      $('#siteModal').modal('show');
    },
    async editSite(site) {
      this.isEditMode = true;

      try {
        const response = await axios.get(`/sites/${site.domain}`);
        if (response.data.success) {
          this.currentSite = response.data.data;
          const defaults = this.getEmptySite();

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
          this.currentSite.verification_methods.verification_methods.cookie = true;

          this.ensureBackendPortFollow();
          this.ensureTlsConfig();
          this.resetSiteFormStatus();
          this.resetCertUploadState();
          this.resetFormSections();

          $('#siteModal').modal('show');
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '获取站点详情失败，请稍后重试。'));
        }
      }
    },
    toggleFormSection(section) {
      this.formSections = {
        ...this.formSections,
        [section]: !this.formSections[section]
      };
    },
    isCreateStepCompleted(order) {
      return this.createSteps.findIndex(step => step.key === this.createStep) + 1 > order;
    },
    getCreateStepHint() {
      if (this.createStep === 'basic') {
        return '先填写基础接入信息。';
      }
      if (this.createStep === 'tls') {
        return this.currentSite.tls.enabled ? '可上传证书，也可以稍后再配置。' : '当前未启用 HTTPS，可直接跳过。';
      }
      return '保持默认高级配置即可创建，后续仍可继续编辑。';
    },
    validateBasicStep() {
      this.resetSiteFormStatus();
      const domain = String(this.currentSite.domain || '').trim().toLowerCase();
      if (!this.validateDomainInput(domain)) {
        this.siteFormError = '域名格式不正确，请输入合法域名。';
        return false;
      }
      this.currentSite.domain = domain;

      const backendValidation = this.validateBackendServerInput(this.currentSite.backend_server);
      if (!backendValidation.valid) {
        this.siteFormError = backendValidation.message;
        return false;
      }
      this.currentSite.backend_server = backendValidation.normalized;
      this.ensureBackendPortFollow();
      this.ensureTlsConfig();
      return true;
    },
    goToNextCreateStep() {
      if (this.createStep === 'basic' && !this.validateBasicStep()) {
        return;
      }
      if (this.createStep === 'basic') {
        this.createStep = 'tls';
        return;
      }
      if (this.createStep === 'tls') {
        this.createStep = 'protection';
      }
    },
    goToPreviousCreateStep() {
      if (this.createStep === 'protection') {
        this.createStep = 'tls';
        return;
      }
      if (this.createStep === 'tls') {
        this.createStep = 'basic';
      }
    },
    validateAdvancedSettings() {
      const statsSampleRate = Number(this.currentSite.protection.stats_sample_rate);
      const autoBlacklistScoreThreshold = Number(this.currentSite.protection.auto_blacklist_score_threshold);
      const autoBlacklistDuration = Number(this.currentSite.protection.auto_blacklist_duration);
      const requestBodyMaxDepth = Number(this.currentSite.protection.request_body_max_depth);
      const graphqlMaxDepth = Number(this.currentSite.protection.graphql_max_depth);
      const maxUriLength = Number(this.currentSite.protection.max_uri_length);
      const maxHeaderCount = Number(this.currentSite.protection.max_header_count);
      const maxForwardedHops = Number(this.currentSite.protection.max_forwarded_hops);
      const verifiedScrubbingRps = Number(this.currentSite.protection.verified_scrubbing_rps);
      const mlBotChallengeThreshold = Number(this.currentSite.protection.ml_bot_challenge_threshold);
      const mlBotBanThreshold = Number(this.currentSite.protection.ml_bot_ban_threshold);
      const owaspParanoiaLevel = Number(this.currentSite.protection.owasp_paranoia_level);
      const owaspInboundThreshold = Number(this.currentSite.protection.owasp_inbound_threshold);
      const owaspMaxMatches = Number(this.currentSite.protection.owasp_max_matches);

      if (this.currentSite.protection.request_content_inspection_enabled) {
        const requestBodyMaxBytes = Number(this.currentSite.protection.request_body_max_bytes);
        const requestFieldMaxLen = Number(this.currentSite.protection.request_field_max_len);

        if (!Number.isInteger(requestBodyMaxBytes) || requestBodyMaxBytes < 1024) {
          this.siteFormError = '请求体扫描上限不能小于 1024 字节。';
          return false;
        }

        if (!Number.isInteger(requestFieldMaxLen) || requestFieldMaxLen < 256) {
          this.siteFormError = '单字段最大长度不能小于 256 字节。';
          return false;
        }

        if (requestFieldMaxLen > requestBodyMaxBytes) {
          this.siteFormError = '单字段最大长度不能超过请求体扫描上限。';
          return false;
        }

        if (!Number.isInteger(requestBodyMaxDepth) || requestBodyMaxDepth < 1 || requestBodyMaxDepth > 128) {
          this.siteFormError = '请求体结构深度必须介于 1 到 128 之间。';
          return false;
        }

        if (!Number.isInteger(graphqlMaxDepth) || graphqlMaxDepth < 1 || graphqlMaxDepth > 64) {
          this.siteFormError = 'GraphQL 深度限制必须介于 1 到 64 之间。';
          return false;
        }
      }

      const sliderVerificationTtl = Number(this.currentSite.verification_methods.slider_verification_ttl);
      const captchaVerificationTtl = Number(this.currentSite.verification_methods.captcha_verification_ttl);
      const powVerificationTtl = Number(this.currentSite.verification_methods.pow_verification_ttl);
      const ddosReverifyWindow = Number(this.currentSite.protection.ddos_reverify_window);
      const logSampleRate = Number(this.currentSite.protection.log_sample_rate);

      if (!Number.isInteger(ddosReverifyWindow) || ddosReverifyWindow < 10) {
        this.siteFormError = 'DDoS 复验窗口不能小于 10 秒。';
        return false;
      }

      if (!Number.isInteger(sliderVerificationTtl) || sliderVerificationTtl < 60 || sliderVerificationTtl > 3600) {
        this.siteFormError = '滑块放行 TTL 必须介于 60 到 3600 秒之间。';
        return false;
      }

      if (!Number.isInteger(captchaVerificationTtl) || captchaVerificationTtl < 60 || captchaVerificationTtl > 7200) {
        this.siteFormError = '验证码放行 TTL 必须介于 60 到 7200 秒之间。';
        return false;
      }

      if (!Number.isInteger(powVerificationTtl) || powVerificationTtl < 60 || powVerificationTtl > 7200) {
        this.siteFormError = 'POW 放行 TTL 必须介于 60 到 7200 秒之间。';
        return false;
      }

      if (!Number.isFinite(logSampleRate) || logSampleRate < 0 || logSampleRate > 1) {
        this.siteFormError = '放行请求采样率必须介于 0 到 1 之间。';
        return false;
      }

      if (!Number.isFinite(statsSampleRate) || statsSampleRate < 0 || statsSampleRate > 1) {
        this.siteFormError = '统计采样率必须介于 0 到 1 之间。';
        return false;
      }

      if (!Number.isInteger(autoBlacklistScoreThreshold) || autoBlacklistScoreThreshold < 1 || autoBlacklistScoreThreshold > 200) {
        this.siteFormError = '自动黑名单触发分数必须介于 1 到 200 之间。';
        return false;
      }

      if (!Number.isInteger(autoBlacklistDuration) || autoBlacklistDuration < 60 || autoBlacklistDuration > 604800) {
        this.siteFormError = '自动黑名单时长必须介于 60 到 604800 秒之间。';
        return false;
      }

      if (!Number.isInteger(maxUriLength) || maxUriLength < 256 || maxUriLength > 32768) {
        this.siteFormError = 'URI 最大长度必须介于 256 到 32768 之间。';
        return false;
      }

      if (!Number.isInteger(maxHeaderCount) || maxHeaderCount < 32 || maxHeaderCount > 256) {
        this.siteFormError = 'Header 数量限制必须介于 32 到 256 之间。';
        return false;
      }

      if (!Number.isInteger(maxForwardedHops) || maxForwardedHops < 4 || maxForwardedHops > 64) {
        this.siteFormError = 'Forwarded/XFF 跳数限制必须介于 4 到 64 之间。';
        return false;
      }

      if (!Number.isInteger(verifiedScrubbingRps) || verifiedScrubbingRps < 1 || verifiedScrubbingRps > 1000) {
        this.siteFormError = '已验证用户清洗速率必须介于 1 到 1000 之间。';
        return false;
      }

      if (this.currentSite.protection.ml_bot_classification_enabled) {
        if (!Number.isFinite(mlBotChallengeThreshold) || mlBotChallengeThreshold < 0.5 || mlBotChallengeThreshold > 1) {
          this.siteFormError = 'ML 审查阈值必须介于 0.5 到 1 之间。';
          return false;
        }

        if (!Number.isFinite(mlBotBanThreshold) || mlBotBanThreshold < 0.5 || mlBotBanThreshold > 1) {
          this.siteFormError = 'ML 封禁建议阈值必须介于 0.5 到 1 之间。';
          return false;
        }

        if (mlBotBanThreshold < mlBotChallengeThreshold) {
          this.siteFormError = 'ML 封禁建议阈值不能低于 ML 审查阈值。';
          return false;
        }
      }

      if (this.currentSite.protection.request_content_inspection_enabled && this.currentSite.protection.owasp_crs_enabled) {
        if (!Number.isInteger(owaspParanoiaLevel) || owaspParanoiaLevel < 1 || owaspParanoiaLevel > 4) {
          this.siteFormError = 'OWASP Paranoia Level 必须介于 1 到 4 之间。';
          return false;
        }

        if (!Number.isInteger(owaspInboundThreshold) || owaspInboundThreshold < 1 || owaspInboundThreshold > 100) {
          this.siteFormError = 'OWASP 入站阈值必须介于 1 到 100 之间。';
          return false;
        }

        if (!Number.isInteger(owaspMaxMatches) || owaspMaxMatches < 1 || owaspMaxMatches > 32) {
          this.siteFormError = 'OWASP 最大命中数必须介于 1 到 32 之间。';
          return false;
        }
      }

      this.currentSite.protection.ddos_reverify_window = ddosReverifyWindow;
      this.currentSite.protection.log_sample_rate = logSampleRate;
      this.currentSite.protection.stats_sample_rate = statsSampleRate;
      this.currentSite.protection.auto_blacklist_score_threshold = autoBlacklistScoreThreshold;
      this.currentSite.protection.auto_blacklist_duration = autoBlacklistDuration;
      this.currentSite.protection.request_body_max_depth = requestBodyMaxDepth;
      this.currentSite.protection.graphql_max_depth = graphqlMaxDepth;
      this.currentSite.protection.max_uri_length = maxUriLength;
      this.currentSite.protection.max_header_count = maxHeaderCount;
      this.currentSite.protection.max_forwarded_hops = maxForwardedHops;
      this.currentSite.protection.verified_scrubbing_rps = verifiedScrubbingRps;
      this.currentSite.protection.ml_bot_challenge_threshold = mlBotChallengeThreshold;
      this.currentSite.protection.ml_bot_ban_threshold = mlBotBanThreshold;
      this.currentSite.protection.owasp_paranoia_level = owaspParanoiaLevel;
      this.currentSite.protection.owasp_inbound_threshold = owaspInboundThreshold;
      this.currentSite.protection.owasp_max_matches = owaspMaxMatches;
      this.currentSite.verification_methods.slider_verification_ttl = sliderVerificationTtl;
      this.currentSite.verification_methods.captcha_verification_ttl = captchaVerificationTtl;
      this.currentSite.verification_methods.pow_verification_ttl = powVerificationTtl;

      if (this.currentSite.tls.enabled) {
        if (!this.currentSite.tls.cert_path || !this.currentSite.tls.key_path) {
          this.siteFormError = '已启用 HTTPS，但证书路径或私钥路径为空。';
          return false;
        }

        if (!this.currentSite.tls.cert_path.startsWith('/') || !this.currentSite.tls.key_path.startsWith('/')) {
          this.siteFormError = '证书路径和私钥路径必须为绝对路径。';
          return false;
        }
      }

      return true;
    },
    async saveSite() {
      try {
        this.resetSiteFormStatus();

        if (!this.validateBasicStep()) {
          return;
        }

        if (!this.validateAdvancedSettings()) {
          return;
        }

        const domain = this.currentSite.domain;
        const response = await axios.put(`/sites/${domain}`, this.currentSite);

        if (response.data.success) {
          const successMessage = this.isEditMode
            ? (response.data.message || '站点配置已保存并已发布。')
            : '站点已创建，可继续进入编辑模式完善高级配置。';
          this.siteFormMessage = successMessage;
          await this.fetchSites();
          $('#siteModal').modal('hide');
          this.$toast.success(successMessage);
        } else {
          this.siteFormError = response.data.message || '保存站点失败。';
        }
      } catch (error) {
        const responseData = error.response && error.response.data ? error.response.data : null;
        const reloadDetail = responseData && responseData.reload
          ? (
            responseData.reload.nginx_error
            || responseData.reload.config_error
            || (responseData.reload.nginx_detail
              && responseData.reload.nginx_detail.syntax_test
              && responseData.reload.nginx_detail.syntax_test.output)
            || responseData.reload.message
          )
          : '';
        const reloadMessage = reloadDetail
          ? ` 重新加载详情：${reloadDetail}`
          : '';
        this.siteFormError = (responseData && responseData.message)
          ? `${responseData.message}${reloadMessage}`
          : getApiErrorMessage(error, '保存站点失败。');
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

.wizard-steps {
  gap: 0.75rem;
}

.wizard-step {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem 1rem;
  border: 1px solid #dee2e6;
  border-radius: 0.75rem;
  background: #f8f9fa;
  flex: 1 1 220px;
}

.wizard-step.active {
  border-color: #007bff;
  background: rgba(0, 123, 255, 0.08);
}

.wizard-step.completed {
  border-color: #28a745;
}

.wizard-step-index {
  width: 2rem;
  height: 2rem;
  border-radius: 999px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: #dee2e6;
  font-weight: 700;
}

.wizard-step.active .wizard-step-index {
  background: #007bff;
  color: #fff;
}

.wizard-step.completed .wizard-step-index {
  background: #28a745;
  color: #fff;
}
</style>
