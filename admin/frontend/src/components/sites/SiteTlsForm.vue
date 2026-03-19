<template>
  <div>
    <div class="form-row">
      <div class="form-group col-md-6">
        <label :for="tlsCertPathInputId">证书路径</label>
        <input
          :id="tlsCertPathInputId"
          v-model="site.tls.cert_path"
          type="text"
          class="form-control"
          required
        >
      </div>
      <div class="form-group col-md-6">
        <label :for="tlsKeyPathInputId">私钥路径</label>
        <input
          :id="tlsKeyPathInputId"
          v-model="site.tls.key_path"
          type="text"
          class="form-control"
          required
        >
      </div>
    </div>

    <div class="form-row">
      <div class="form-group col-md-6">
        <div class="form-check">
          <input :id="tlsRedirectInputId" v-model="site.tls.redirect_http_to_https" type="checkbox" class="form-check-input">
          <label class="form-check-label" :for="tlsRedirectInputId">将 HTTP 自动跳转到 HTTPS</label>
        </div>
      </div>
      <div class="form-group col-md-6">
        <div class="form-check">
          <input :id="tlsHttp2InputId" v-model="site.tls.http2_enabled" type="checkbox" class="form-check-input">
          <label class="form-check-label" :for="tlsHttp2InputId">启用 HTTP/2</label>
        </div>
      </div>
    </div>

    <small class="form-text text-muted mb-3">
      证书文件默认存放于 <code>./config/certs/</code>，容器内路径为 <code>/usr/local/openresty/nginx/conf/config/certs/</code>。
      如未上传证书但开启 HTTPS，系统会按当前域名自动生成自签名证书。
    </small>

    <div class="alert alert-info py-2" v-if="!canUpload">
      请先填写合法域名，再上传证书。也可以直接开启 HTTPS 而不上传证书，系统会自动生成自签名证书。
    </div>

    <div class="card mb-3">
      <div class="card-body py-3">
        <label class="d-block mb-2">证书上传方式</label>
        <div class="form-check form-check-inline">
          <input :id="fileModeInputId" :checked="uploadMode === 'file'" class="form-check-input" type="radio" value="file" @change="$emit('update:upload-mode', 'file')">
          <label class="form-check-label" :for="fileModeInputId">上传文件</label>
        </div>
        <div class="form-check form-check-inline">
          <input :id="textModeInputId" :checked="uploadMode === 'text'" class="form-check-input" type="radio" value="text" @change="$emit('update:upload-mode', 'text')">
          <label class="form-check-label" :for="textModeInputId">粘贴内容</label>
        </div>

        <div class="mt-3" v-if="uploadMode === 'file'">
          <div class="form-row">
            <div class="form-group col-md-6">
              <label :for="uploadCertFileInputId">证书文件</label>
              <input :id="uploadCertFileInputId" type="file" class="form-control-file" :disabled="!canUpload || uploadState.uploading" @change="$emit('file-change', 'cert', $event)">
            </div>
            <div class="form-group col-md-6">
              <label :for="uploadKeyFileInputId">私钥文件</label>
              <input :id="uploadKeyFileInputId" type="file" class="form-control-file" :disabled="!canUpload || uploadState.uploading" @change="$emit('file-change', 'key', $event)">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group col-md-6">
              <label :for="uploadCertFilenameInputId">证书文件名（可选）</label>
              <input :id="uploadCertFilenameInputId" v-model="uploadState.certFilename" type="text" class="form-control" placeholder="example.com.crt" :disabled="uploadState.uploading">
            </div>
            <div class="form-group col-md-6">
              <label :for="uploadKeyFilenameInputId">私钥文件名（可选）</label>
              <input :id="uploadKeyFilenameInputId" v-model="uploadState.keyFilename" type="text" class="form-control" placeholder="example.com.key" :disabled="uploadState.uploading">
            </div>
          </div>
          <button type="button" class="btn btn-outline-primary btn-sm" :disabled="!canUpload || uploadState.uploading" @click="$emit('upload-files')">
            {{ uploadState.uploading ? '上传中...' : '上传证书文件' }}
          </button>
        </div>

        <div class="mt-3" v-else>
          <div class="form-row">
            <div class="form-group col-md-6">
              <label :for="uploadCertContentInputId">证书内容</label>
              <textarea :id="uploadCertContentInputId" v-model="uploadState.certContent" rows="6" class="form-control" placeholder="-----BEGIN CERTIFICATE-----" :disabled="!canUpload || uploadState.uploading"></textarea>
            </div>
            <div class="form-group col-md-6">
              <label :for="uploadKeyContentInputId">私钥内容</label>
              <textarea :id="uploadKeyContentInputId" v-model="uploadState.keyContent" rows="6" class="form-control" placeholder="-----BEGIN PRIVATE KEY-----" :disabled="!canUpload || uploadState.uploading"></textarea>
            </div>
          </div>
          <div class="form-row">
            <div class="form-group col-md-6">
              <label :for="uploadTextCertFilenameInputId">证书文件名（可选）</label>
              <input :id="uploadTextCertFilenameInputId" v-model="uploadState.certFilename" type="text" class="form-control" placeholder="example.com.crt" :disabled="uploadState.uploading">
            </div>
            <div class="form-group col-md-6">
              <label :for="uploadTextKeyFilenameInputId">私钥文件名（可选）</label>
              <input :id="uploadTextKeyFilenameInputId" v-model="uploadState.keyFilename" type="text" class="form-control" placeholder="example.com.key" :disabled="uploadState.uploading">
            </div>
          </div>
          <button type="button" class="btn btn-outline-primary btn-sm" :disabled="!canUpload || uploadState.uploading" @click="$emit('upload-content')">
            {{ uploadState.uploading ? '上传中...' : '上传证书内容' }}
          </button>
        </div>

        <div class="alert alert-success py-2 mt-3 mb-0" v-if="uploadState.message">
          {{ uploadState.message }}
        </div>
        <div class="alert alert-danger py-2 mt-3 mb-0" v-if="uploadState.error">
          {{ uploadState.error }}
        </div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'SiteTlsForm',
  props: {
    site: {
      type: Object,
      required: true
    },
    uploadMode: {
      type: String,
      required: true
    },
    uploadState: {
      type: Object,
      required: true
    },
    canUpload: {
      type: Boolean,
      default: false
    },
    idPrefix: {
      type: String,
      default: 'site-tls'
    }
  },
  computed: {
    tlsCertPathInputId() { return `${this.idPrefix}-cert-path`; },
    tlsKeyPathInputId() { return `${this.idPrefix}-key-path`; },
    tlsRedirectInputId() { return `${this.idPrefix}-redirect`; },
    tlsHttp2InputId() { return `${this.idPrefix}-http2`; },
    fileModeInputId() { return `${this.idPrefix}-mode-file`; },
    textModeInputId() { return `${this.idPrefix}-mode-text`; },
    uploadCertFileInputId() { return `${this.idPrefix}-cert-file`; },
    uploadKeyFileInputId() { return `${this.idPrefix}-key-file`; },
    uploadCertFilenameInputId() { return `${this.idPrefix}-cert-filename`; },
    uploadKeyFilenameInputId() { return `${this.idPrefix}-key-filename`; },
    uploadCertContentInputId() { return `${this.idPrefix}-cert-content`; },
    uploadKeyContentInputId() { return `${this.idPrefix}-key-content`; },
    uploadTextCertFilenameInputId() { return `${this.idPrefix}-text-cert-filename`; },
    uploadTextKeyFilenameInputId() { return `${this.idPrefix}-text-key-filename`; }
  }
};
</script>
