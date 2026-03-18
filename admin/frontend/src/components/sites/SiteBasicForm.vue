<template>
  <div>
    <div class="form-row">
      <div class="form-group col-md-6">
        <label :for="domainInputId">域名</label>
        <input
          :id="domainInputId"
          v-model="site.domain"
          :readonly="readonlyDomain"
          type="text"
          class="form-control"
          required
        >
        <small class="form-text text-muted">站点域名，例如：example.com</small>
      </div>
      <div class="form-group col-md-8">
        <label :for="backendInputId">后端服务器</label>
        <input
          :id="backendInputId"
          v-model="site.backend_server"
          type="text"
          class="form-control"
          required
        >
        <small class="form-text text-muted">回源地址，例如：http://192.168.1.10:8080 或 https://origin.example.com:443</small>
      </div>
      <div class="form-group col-md-4 d-flex align-items-end">
        <div class="form-check mb-2">
          <input :id="portFollowInputId" v-model="site.backend_port_follow" type="checkbox" class="form-check-input">
          <label class="form-check-label" :for="portFollowInputId">后端端口跟随访问协议</label>
          <small class="form-text text-muted">启用后，HTTP 请求回源到 80，HTTPS 请求回源到 443，而不是固定使用回源地址中的端口。</small>
        </div>
      </div>
    </div>

    <div class="form-check mb-3">
      <input :id="enabledInputId" v-model="site.enabled" type="checkbox" class="form-check-input">
      <label class="form-check-label" :for="enabledInputId">启用此站点</label>
    </div>

    <div class="form-check mb-2">
      <input :id="tlsEnabledInputId" v-model="site.tls.enabled" type="checkbox" class="form-check-input">
      <label class="form-check-label" :for="tlsEnabledInputId">启用 HTTPS (443)</label>
    </div>
    <small class="form-text text-muted">创建 HTTP 站点时可先关闭，稍后再补充证书与 HTTPS 配置。</small>
  </div>
</template>

<script>
export default {
  name: 'SiteBasicForm',
  props: {
    site: {
      type: Object,
      required: true
    },
    readonlyDomain: {
      type: Boolean,
      default: false
    },
    idPrefix: {
      type: String,
      default: 'site-basic'
    }
  },
  computed: {
    domainInputId() {
      return `${this.idPrefix}-domain`;
    },
    backendInputId() {
      return `${this.idPrefix}-backend`;
    },
    portFollowInputId() {
      return `${this.idPrefix}-port-follow`;
    },
    enabledInputId() {
      return `${this.idPrefix}-enabled`;
    },
    tlsEnabledInputId() {
      return `${this.idPrefix}-tls-enabled`;
    }
  }
};
</script>
