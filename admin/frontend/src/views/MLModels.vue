<template>
  <div class="ml-models">
    <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
      <h1 class="h2"><i class="bi bi-box-seam mr-2"></i>ML 模型管理</h1>
      <button class="btn btn-sm btn-primary" @click="showUploadModal = true">
        <i class="bi bi-upload mr-1"></i> 上传模型
      </button>
    </div>

    <div v-if="loading" class="text-center py-5">
      <div class="spinner-border text-primary" role="status"></div>
    </div>

    <template v-else>
      <!-- 模型列表 -->
      <div class="card">
        <div class="card-header"><i class="bi bi-list-ul mr-2"></i>模型版本列表</div>
        <div class="card-body p-0">
          <div v-if="models.length" class="table-responsive">
            <table class="table table-hover mb-0">
              <thead class="thead-light">
                <tr>
                  <th>版本</th>
                  <th>算法</th>
                  <th>特征数</th>
                  <th>阈值</th>
                  <th>准确率</th>
                  <th>上传时间</th>
                  <th>状态</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="m in models" :key="m.version">
                  <td><code>{{ m.version }}</code></td>
                  <td>{{ m.algorithm }}</td>
                  <td>{{ m.feature_count }}</td>
                  <td>{{ m.threshold }}</td>
                  <td>
                    <span v-if="m.accuracy > 0">{{ (m.accuracy * 100).toFixed(1) }}%</span>
                    <span v-else class="text-muted">-</span>
                  </td>
                  <td>{{ formatTime(m.uploaded_at) }}</td>
                  <td>
                    <span v-if="m.active" class="badge badge-success">
                      <i class="bi bi-check-circle-fill mr-1"></i>激活中
                    </span>
                    <span v-else class="badge badge-secondary">待机</span>
                  </td>
                  <td>
                    <button v-if="!m.active" class="btn btn-xs btn-outline-success mr-1"
                      @click="activateModel(m.version)" title="激活">
                      <i class="bi bi-play-fill"></i> 激活
                    </button>
                    <button v-if="!m.active" class="btn btn-xs btn-outline-danger"
                      @click="confirmDelete(m.version)" title="删除">
                      <i class="bi bi-trash"></i>
                    </button>
                    <span v-if="m.active" class="text-muted small">
                      <button class="btn btn-xs btn-outline-secondary" @click="doRollback"
                        :disabled="!hasPrevious">
                        <i class="bi bi-arrow-counterclockwise"></i> 回滚
                      </button>
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <p v-else class="text-muted text-center py-4">暂无模型，请上传模型文件。</p>
        </div>
      </div>
    </template>

    <!-- 上传模态框 -->
    <div v-if="showUploadModal" class="modal-overlay" @click.self="showUploadModal = false">
      <div class="modal-dialog modal-dialog-centered" style="max-width:500px; margin:auto;">
        <div class="modal-content shadow">
          <div class="modal-header">
            <h5 class="modal-title"><i class="bi bi-upload mr-2"></i>上传 ML 模型</h5>
            <button type="button" class="close" @click="showUploadModal = false">&times;</button>
          </div>
          <div class="modal-body">
            <div class="form-group">
              <label>模型文件（JSON）<span class="text-danger">*</span></label>
              <input type="file" class="form-control-file" accept=".json,application/json"
                @change="onFileChange" />
              <small class="text-muted">格式：{weights[], intercept, threshold, scaler_mean[], scaler_std[]}</small>
            </div>
            <div class="form-group">
              <label>版本号</label>
              <input type="text" class="form-control form-control-sm" v-model="upload.version"
                placeholder="留空自动生成，如 v20260317-ab12" />
            </div>
            <div class="form-row">
              <div class="form-group col-md-6">
                <label>准确率（可选）</label>
                <input type="number" class="form-control form-control-sm" v-model.number="upload.accuracy"
                  placeholder="0.95" min="0" max="1" step="0.001" />
              </div>
              <div class="form-group col-md-6">
                <label>F1 分数（可选）</label>
                <input type="number" class="form-control form-control-sm" v-model.number="upload.f1_score"
                  placeholder="0.94" min="0" max="1" step="0.001" />
              </div>
            </div>
            <div class="form-group">
              <label>描述（可选）</label>
              <input type="text" class="form-control form-control-sm" v-model="upload.description"
                placeholder="模型说明..." />
            </div>
          </div>
          <div class="modal-footer">
            <button class="btn btn-secondary btn-sm" @click="showUploadModal = false">取消</button>
            <button class="btn btn-primary btn-sm" @click="doUpload" :disabled="uploading || !upload.file">
              <span v-if="uploading" class="spinner-border spinner-border-sm mr-1"></span>
              上传
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- 删除确认 -->
    <div v-if="deleteTarget" class="modal-overlay" @click.self="deleteTarget = null">
      <div class="modal-dialog modal-dialog-centered" style="max-width:400px; margin:auto;">
        <div class="modal-content shadow">
          <div class="modal-header bg-danger text-white">
            <h5 class="modal-title"><i class="bi bi-exclamation-triangle-fill mr-2"></i>确认删除</h5>
          </div>
          <div class="modal-body">
            确定要删除模型 <code>{{ deleteTarget }}</code> 吗？此操作不可恢复。
          </div>
          <div class="modal-footer">
            <button class="btn btn-secondary btn-sm" @click="deleteTarget = null">取消</button>
            <button class="btn btn-danger btn-sm" @click="doDelete">确认删除</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios'
import toast from '../toast'

export default {
  name: 'MLModels',
  data() {
    return {
      loading: true,
      uploading: false,
      showUploadModal: false,
      deleteTarget: null,
      models: [],
      hasPrevious: false,
      upload: { file: null, version: '', accuracy: '', f1_score: '', description: '' },
    }
  },
  mounted() {
    this.loadModels()
  },
  methods: {
    async loadModels() {
      this.loading = true
      try {
        const [modelsRes, statusRes] = await Promise.all([
          axios.get('/ml/models'),
          axios.get('/ml/status'),
        ])
        this.models = modelsRes.data.data || []
        this.hasPrevious = !!(statusRes.data.data && statusRes.data.data.previous_version)
      } catch (err) {
        toast.error('加载模型列表失败: ' + (err.response?.data?.message || err.message))
      } finally {
        this.loading = false
      }
    },
    onFileChange(e) {
      this.upload.file = e.target.files[0] || null
    },
    async doUpload() {
      if (!this.upload.file) return
      this.uploading = true
      const fd = new FormData()
      fd.append('model', this.upload.file)
      if (this.upload.version)     fd.append('version',     this.upload.version)
      if (this.upload.accuracy)    fd.append('accuracy',    this.upload.accuracy)
      if (this.upload.f1_score)    fd.append('f1_score',    this.upload.f1_score)
      if (this.upload.description) fd.append('description', this.upload.description)
      try {
        const res = await axios.post('/ml/models/upload', fd, {
          headers: { 'Content-Type': 'multipart/form-data' }
        })
        toast.success('模型上传成功: ' + res.data.data.version)
        this.showUploadModal = false
        this.upload = { file: null, version: '', accuracy: '', f1_score: '', description: '' }
        await this.loadModels()
      } catch (err) {
        toast.error('上传失败: ' + (err.response?.data?.message || err.message))
      } finally {
        this.uploading = false
      }
    },
    async activateModel(version) {
      try {
        await axios.put(`/ml/models/${version}/activate`)
        toast.success(`模型 ${version} 已激活并广播到所有节点`)
        await this.loadModels()
      } catch (err) {
        toast.error('激活失败: ' + (err.response?.data?.message || err.message))
      }
    },
    async doRollback() {
      try {
        const res = await axios.post('/ml/models/rollback')
        toast.success('已回滚到: ' + res.data.data.active_version)
        await this.loadModels()
      } catch (err) {
        toast.error('回滚失败: ' + (err.response?.data?.message || err.message))
      }
    },
    confirmDelete(version) {
      this.deleteTarget = version
    },
    async doDelete() {
      const version = this.deleteTarget
      this.deleteTarget = null
      try {
        await axios.delete(`/ml/models/${version}`)
        toast.success(`模型 ${version} 已删除`)
        await this.loadModels()
      } catch (err) {
        toast.error('删除失败: ' + (err.response?.data?.message || err.message))
      }
    },
    formatTime(ts) {
      if (!ts) return '-'
      return new Date(ts).toLocaleString()
    },
  },
}
</script>

<style scoped>
.modal-overlay {
  position: fixed; top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0,0,0,0.5); z-index: 1050;
  display: flex; align-items: center; justify-content: center;
}
.btn-xs { padding: 0.15rem 0.4rem; font-size: 0.75rem; }
</style>
