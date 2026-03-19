<template>
  <div>
    <div class="card mb-3">
      <div class="card-header d-flex justify-content-between align-items-center">
        <div>
          <strong>{{ protectionTitle }}</strong>
          <div class="small text-muted">{{ protectionDescription }}</div>
        </div>
        <button type="button" class="btn btn-link btn-sm p-0" @click="$emit('toggle-section', 'protection')">
          {{ sections.protection ? '收起' : '展开' }}
        </button>
      </div>
      <div class="card-body" v-if="sections.protection">
        <div class="form-row">
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('browser-detection')" v-model="site.protection.browser_detection_enabled" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('browser-detection')">真实浏览器检测</label></div></div>
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('environment-detection')" v-model="site.protection.environment_detection_enabled" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('environment-detection')">环境监测</label></div></div>
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('ip-blacklist')" v-model="site.protection.ip_blacklist_enabled" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('ip-blacklist')">IP 黑名单</label></div></div>
        </div>
        <div class="form-row">
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('ddos')" v-model="site.protection.ddos_protection_enabled" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('ddos')">DDoS 防护</label></div></div>
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('anti-cc')" v-model="site.protection.anti_cc_enabled" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('anti-cc')">Anti-CC 防护</label></div></div>
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('random-attack')" v-model="site.protection.random_attack_protection_enabled" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('random-attack')">随机攻击防护</label></div></div>
        </div>
        <div class="form-row">
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('js-encryption')" v-model="site.protection.js_encryption_enabled" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('js-encryption')">JS 加密</label></div></div>
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('prevent-f12')" v-model="site.protection.prevent_browser_f12" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('prevent-f12')">防止浏览器 F12</label></div></div>
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('honeypot')" v-model="site.protection.honeypot_enabled" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('honeypot')">蜜罐功能</label></div></div>
        </div>
        <div class="form-row">
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('auto-blacklist')" v-model="site.protection.auto_blacklist_enabled" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('auto-blacklist')">自动添加 IP 黑名单</label></div></div>
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('request-logging')" v-model="site.protection.request_logging_enabled" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('request-logging')">请求日志记录</label></div></div>
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('traffic-analysis')" v-model="site.protection.traffic_analysis_enabled" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('traffic-analysis')">流量动态识别</label></div></div>
        </div>
        <div class="form-row">
          <div class="form-group col-md-4">
            <label :for="id('log-sample-rate')">放行请求采样率</label>
            <input :id="id('log-sample-rate')" v-model.number="site.protection.log_sample_rate" :disabled="!site.protection.request_logging_enabled" type="number" class="form-control" min="0" max="1" step="0.01">
            <small class="form-text text-muted">0 表示仅记录拦截请求，0.01 表示约 1% 的放行请求会进入实时日志。</small>
          </div>
        </div>
        <div class="form-row">
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('request-inspection')" v-model="site.protection.request_content_inspection_enabled" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('request-inspection')">请求内容检测</label></div></div>
          <div class="form-group col-md-4">
            <label :for="id('request-body-max')">请求体扫描上限 (Bytes)</label>
            <input :id="id('request-body-max')" v-model="site.protection.request_body_max_bytes" :disabled="!site.protection.request_content_inspection_enabled" type="number" class="form-control" min="1024" step="1024">
          </div>
          <div class="form-group col-md-4">
            <label :for="id('request-field-max')">单字段最大长度 (Bytes)</label>
            <input :id="id('request-field-max')" v-model="site.protection.request_field_max_len" :disabled="!site.protection.request_content_inspection_enabled" type="number" class="form-control" min="256" step="256">
          </div>
        </div>
      </div>
    </div>

    <div class="card mb-3">
      <div class="card-header d-flex justify-content-between align-items-center">
        <div>
          <strong>速率限制</strong>
          <div class="small text-muted">默认值已经可用，可按业务流量调整。</div>
        </div>
        <button type="button" class="btn btn-link btn-sm p-0" @click="$emit('toggle-section', 'rateLimit')">
          {{ sections.rateLimit ? '收起' : '展开' }}
        </button>
      </div>
      <div class="card-body" v-if="sections.rateLimit">
        <div class="form-row">
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('global-rate-limit')" v-model="site.protection.global_rate_limit_enabled" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('global-rate-limit')">启用全局速率限制</label></div></div>
          <div class="form-group col-md-4"><label :for="id('rate-limit-count')">请求次数</label><input :id="id('rate-limit-count')" v-model="site.protection.global_rate_limit_count" :disabled="!site.protection.global_rate_limit_enabled" type="number" class="form-control" min="1"></div>
          <div class="form-group col-md-4"><label :for="id('rate-limit-window')">时间窗口（秒）</label><input :id="id('rate-limit-window')" v-model="site.protection.global_rate_limit_window" :disabled="!site.protection.global_rate_limit_enabled" type="number" class="form-control" min="1"></div>
        </div>
        <div class="form-row">
          <div class="form-group col-md-4"><label :for="id('ddos-reverify-window')">DDoS 复验窗口（秒）</label><input :id="id('ddos-reverify-window')" v-model="site.protection.ddos_reverify_window" type="number" class="form-control" min="10"></div>
          <div class="form-group col-md-8"><div class="form-check mt-4"><input :id="id('origin-proxy-only')" v-model="site.protection.origin_proxy_only_enabled" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('origin-proxy-only')">仅允许可信代理回源</label><small class="form-text text-muted">启用后，非可信代理直接访问源站将被丢弃。</small></div></div>
        </div>
      </div>
    </div>

    <div class="card mb-3">
      <div class="card-header d-flex justify-content-between align-items-center">
        <div>
          <strong>验证方式</strong>
          <div class="small text-muted">可保留默认值，创建完成后再细调。</div>
        </div>
        <button type="button" class="btn btn-link btn-sm p-0" @click="$emit('toggle-section', 'verification')">
          {{ sections.verification ? '收起' : '展开' }}
        </button>
      </div>
      <div class="card-body" v-if="sections.verification">
        <div class="form-row">
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('captcha')" v-model="site.verification_methods.captcha_enabled" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('captcha')">验证码</label></div></div>
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('slider-captcha')" v-model="site.verification_methods.slider_captcha_enabled" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('slider-captcha')">滑块验证</label></div></div>
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('pow')" v-model="site.verification_methods.pow_enabled" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('pow')">工作量证明 (POW)</label></div></div>
        </div>
        <div class="form-row">
          <div class="form-group col-md-6"><div class="form-check"><input :id="id('slider-step-up')" v-model="site.verification_methods.slider_step_up_on_high_risk" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('slider-step-up')">高风险滑块自动升级</label><small class="form-text text-muted">高风险场景下，滑块通过后自动升级到更强验证。</small></div></div>
        </div>
        <div class="form-row">
          <div class="form-group col-md-4"><label :for="id('slider-ttl')">滑块放行 TTL (秒)</label><input :id="id('slider-ttl')" v-model="site.verification_methods.slider_verification_ttl" type="number" class="form-control" min="60" max="3600"></div>
          <div class="form-group col-md-4"><label :for="id('captcha-ttl')">验证码放行 TTL (秒)</label><input :id="id('captcha-ttl')" v-model="site.verification_methods.captcha_verification_ttl" type="number" class="form-control" min="60" max="7200"></div>
          <div class="form-group col-md-4"><label :for="id('pow-ttl')">POW 放行 TTL (秒)</label><input :id="id('pow-ttl')" v-model="site.verification_methods.pow_verification_ttl" type="number" class="form-control" min="60" max="7200"></div>
        </div>
        <div class="form-row" v-if="site.verification_methods.pow_enabled">
          <div class="form-group col-md-6"><label :for="id('pow-base-difficulty')">POW 基础难度 (1-10)</label><input :id="id('pow-base-difficulty')" v-model="site.verification_methods.pow_base_difficulty" type="number" class="form-control" min="1" max="10"></div>
          <div class="form-group col-md-6"><label :for="id('pow-max-difficulty')">POW 最大难度 (1-15)</label><input :id="id('pow-max-difficulty')" v-model="site.verification_methods.pow_max_difficulty" type="number" class="form-control" min="1" max="15"></div>
        </div>
        <h6>验证关联维度</h6>
        <div class="form-row">
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('verify-ip')" v-model="site.verification_methods.verification_methods.ip_address" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('verify-ip')">IP 地址</label></div></div>
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('verify-ua')" v-model="site.verification_methods.verification_methods.user_agent" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('verify-ua')">User-Agent</label></div></div>
          <div class="form-group col-md-4"><div class="form-check"><input :id="id('verify-cookie')" v-model="site.verification_methods.verification_methods.cookie" type="checkbox" class="form-check-input"><label class="form-check-label" :for="id('verify-cookie')">Cookie</label></div></div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'SiteProtectionForm',
  props: {
    site: {
      type: Object,
      required: true
    },
    sections: {
      type: Object,
      required: true
    },
    compact: {
      type: Boolean,
      default: false
    },
    idPrefix: {
      type: String,
      default: 'site-protection'
    }
  },
  computed: {
    protectionTitle() {
      return this.compact ? '高级防护配置' : '防护功能';
    },
    protectionDescription() {
      return this.compact
        ? '默认防护已启用，可直接跳过，创建完成后再细调。'
        : '编辑模式下可按需调整所有防护开关。';
    }
  },
  methods: {
    id(suffix) {
      return `${this.idPrefix}-${suffix}`;
    }
  }
};
</script>
