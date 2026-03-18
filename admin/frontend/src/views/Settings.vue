<template>
  <div class="settings">
    <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
      <h1 class="h2">系统设置</h1>
      <div class="btn-toolbar mb-2 mb-md-0">
        <button type="button" class="btn btn-sm btn-primary" @click="saveSettings">
          <i class="bi bi-save mr-1"></i> 保存设置
        </button>
        <button
          type="button"
          class="btn btn-sm btn-outline-success ml-2"
          @click="publishSnapshot"
          :disabled="snapshotPublishing"
        >
          <i class="bi bi-upload mr-1"></i> 发布配置
        </button>
      </div>
    </div>

    <div class="row mb-3">
      <div class="col-md-12">
        <div class="alert alert-light d-flex justify-content-between align-items-center" role="alert">
          <div>
            当前版本: <code>{{ snapshotStatus.active_version || '-' }}</code>
            <span class="mx-2">|</span>
            发布时间: {{ formatPublishedAt(snapshotStatus.published_at) }}
          </div>
          <button
            type="button"
            class="btn btn-sm btn-outline-secondary"
            @click="fetchSnapshotStatus"
            :disabled="snapshotLoading"
          >
            <i class="bi bi-arrow-clockwise mr-1"></i> 刷新
          </button>
        </div>
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
              <h5 class="card-title mb-0">Anti-Bypass 默认策略</h5>
            </div>
            <div class="card-body">
              <div class="form-check mb-3">
                <input type="checkbox" class="form-check-input" id="originProxyOnlyDefault" v-model="config.anti_bypass.origin_proxy_only_default">
                <label class="form-check-label" for="originProxyOnlyDefault">新站点默认仅允许可信代理回源</label>
              </div>

              <div class="form-check mb-3">
                <input type="checkbox" class="form-check-input" id="sliderStepUpDefault" v-model="config.anti_bypass.slider_step_up_on_high_risk">
                <label class="form-check-label" for="sliderStepUpDefault">高风险场景默认启用滑块升级</label>
              </div>

              <div class="form-row">
                <div class="form-group col-md-4">
                  <label for="sliderVerificationTtlDefault">滑块放行 TTL (秒)</label>
                  <input
                    type="number"
                    class="form-control"
                    id="sliderVerificationTtlDefault"
                    v-model="config.anti_bypass.slider_verification_ttl"
                    min="60"
                    max="3600"
                  >
                </div>
                <div class="form-group col-md-4">
                  <label for="captchaVerificationTtlDefault">验证码放行 TTL (秒)</label>
                  <input
                    type="number"
                    class="form-control"
                    id="captchaVerificationTtlDefault"
                    v-model="config.anti_bypass.captcha_verification_ttl"
                    min="60"
                    max="7200"
                  >
                </div>
                <div class="form-group col-md-4">
                  <label for="powVerificationTtlDefault">POW 放行 TTL (秒)</label>
                  <input
                    type="number"
                    class="form-control"
                    id="powVerificationTtlDefault"
                    v-model="config.anti_bypass.pow_verification_ttl"
                    min="60"
                    max="7200"
                  >
                </div>
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

              <div class="form-row">
                <div class="col-md-12">
                  <div class="form-group mb-0">
                    <label for="trustedBotsInput">可信爬虫 UA 关键字</label>
                    <textarea
                      id="trustedBotsInput"
                      class="form-control"
                      rows="6"
                      v-model="trustedBotsText"
                      placeholder="googlebot&#10;bingbot&#10;slurp"
                    ></textarea>
                    <small class="form-text text-muted">
                      每行一个关键字，匹配时不区分大小写。留空表示不额外放行任何爬虫 UA。
                    </small>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="row mb-4">
        <div class="col-md-12">
          <div class="card">
            <div class="card-header">
              <h5 class="card-title mb-0">多核心自适应</h5>
            </div>
            <div class="card-body">
              <div class="form-row">
                <div class="form-group col-md-3">
                  <div class="form-check mt-4">
                    <input type="checkbox" class="form-check-input" id="adaptiveEnabled" v-model="config.adaptive_protection.enabled">
                    <label class="form-check-label" for="adaptiveEnabled">启用自适应</label>
                  </div>
                </div>
                <div class="form-group col-md-3">
                  <label for="cpuCoresPer10kRps">每万RPS所需核数</label>
                  <input type="number" class="form-control" id="cpuCoresPer10kRps" v-model="config.adaptive_protection.cpu_cores_per_10k_rps" min="1" step="0.5">
                </div>
                <div class="form-group col-md-3">
                  <label for="verifiedScrubbingRps">已验证清洗限速(RPS)</label>
                  <input type="number" class="form-control" id="verifiedScrubbingRps" v-model="config.adaptive_protection.verified_scrubbing_rps" min="1">
                </div>
                <div class="form-group col-md-3">
                  <label for="globalHardReverifyWindow">硬压复验窗口(秒)</label>
                  <input type="number" class="form-control" id="globalHardReverifyWindow" v-model="config.adaptive_protection.global_hard_reverify_window" min="10">
                </div>
              </div>
              <div class="form-row">
                <div class="form-group col-md-4">
                  <label for="workerConnectionsPerCore">每核建议连接数</label>
                  <input type="number" class="form-control" id="workerConnectionsPerCore" v-model="config.adaptive_protection.worker_connections_per_core" min="1024">
                </div>
                <div class="form-group col-md-4">
                  <label for="workerRlimitPerCore">每核建议FD上限</label>
                  <input type="number" class="form-control" id="workerRlimitPerCore" v-model="config.adaptive_protection.worker_rlimit_nofile_per_core" min="1024">
                </div>
                <div class="form-group col-md-4">
                  <label for="sharedDictScalePerCore">共享内存倍率/核</label>
                  <input type="number" class="form-control" id="sharedDictScalePerCore" v-model="config.adaptive_protection.shared_dict_scale_per_core" min="0.1" step="0.1">
                </div>
              </div>
              <div class="form-check">
                <input type="checkbox" class="form-check-input" id="hardDropOnOverload" v-model="config.adaptive_protection.hard_drop_on_overload">
                <label class="form-check-label" for="hardDropOnOverload">极限过载时直接硬丢弃</label>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="row mb-4">
        <div class="col-md-12">
          <div class="card">
            <div class="card-header">
              <h5 class="card-title mb-0">集群主副设置</h5>
            </div>
            <div class="card-body">
              <div class="form-row">
                <div class="form-group col-md-3">
                  <div class="form-check mt-4">
                    <input type="checkbox" class="form-check-input" id="clusterEnabled" v-model="config.cluster.enabled">
                    <label class="form-check-label" for="clusterEnabled">启用集群</label>
                  </div>
                </div>
                <div class="form-group col-md-3">
                  <label for="clusterNodeId">当前节点ID</label>
                  <input type="text" class="form-control" id="clusterNodeId" v-model="config.cluster.node_id">
                </div>
                <div class="form-group col-md-3">
                  <label for="clusterNodeRole">节点角色</label>
                  <select class="form-control" id="clusterNodeRole" v-model="config.cluster.node_role">
                    <option value="primary">主节点</option>
                    <option value="secondary">从节点</option>
                  </select>
                </div>
                <div class="form-group col-md-3">
                  <label for="clusterPrimaryApi">主节点API地址</label>
                  <input type="text" class="form-control" id="clusterPrimaryApi" v-model="config.cluster.primary_api_url" placeholder="http://10.0.0.10:3000">
                </div>
              </div>

              <div class="form-row">
                <div class="form-group col-md-3">
                  <div class="form-check mt-4">
                    <input type="checkbox" class="form-check-input" id="clusterSyncEnabled" v-model="config.cluster.sync.enabled">
                    <label class="form-check-label" for="clusterSyncEnabled">启用自动同步</label>
                  </div>
                </div>
                <div class="form-group col-md-3">
                  <label for="clusterConfigInterval">配置同步间隔(秒)</label>
                  <input type="number" class="form-control" id="clusterConfigInterval" v-model="config.cluster.sync.config_interval" min="5">
                </div>
                <div class="form-group col-md-3">
                  <label for="clusterBlacklistInterval">黑名单同步间隔(秒)</label>
                  <input type="number" class="form-control" id="clusterBlacklistInterval" v-model="config.cluster.sync.blacklist_interval" min="3">
                </div>
                <div class="form-group col-md-3">
                  <label for="clusterSyncTimeout">同步超时(ms)</label>
                  <input type="number" class="form-control" id="clusterSyncTimeout" v-model="config.cluster.sync.request_timeout_ms" min="300">
                </div>
              </div>

              <div class="form-row">
                <div class="form-group col-md-4">
                  <label for="clusterFanoutConcurrency">并发扇出数</label>
                  <input type="number" class="form-control" id="clusterFanoutConcurrency" v-model="config.cluster.sync.fanout_concurrency" min="1">
                  <small class="form-text text-muted">主节点并发同步从节点数量（十几个节点建议 4-8）</small>
                </div>
                <div class="form-group col-md-4">
                  <label for="clusterRetryCount">失败重试次数</label>
                  <input type="number" class="form-control" id="clusterRetryCount" v-model="config.cluster.sync.retry_count" min="0" max="10">
                </div>
                <div class="form-group col-md-4">
                  <label for="clusterRetryBackoff">重试退避(ms)</label>
                  <input type="number" class="form-control" id="clusterRetryBackoff" v-model="config.cluster.sync.retry_backoff_ms" min="50">
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
import { getApiErrorMessage, shouldHandleLocally } from '../utils/http';

const DEFAULT_TRUSTED_BOTS = [
  'googlebot',
  'bingbot',
  'yandexbot',
  'duckduckbot',
  'baiduspider',
  'applebot',
  'slurp',
  'facebookexternalhit',
  'twitterbot',
  'linkedinbot',
  'whatsapp',
  'telegrambot',
  'discordbot',
  'semrushbot',
  'ahrefsbot',
  'mj12bot',
  'dotbot',
  'rogerbot'
];

export default {
  name: 'Settings',
  data() {
    return {
      loading: true,
      snapshotLoading: false,
      snapshotPublishing: false,
      snapshotStatus: {
        active_version: null,
        published_at: null
      },
      trustedBotsText: DEFAULT_TRUSTED_BOTS.join('\n'),
      config: {
        global: {
          log_level: 'info',
          default_action: 'allow'
        },
        trusted_bots: DEFAULT_TRUSTED_BOTS.slice(),
        ddos_protection: {
          url_threshold: 60,
          url_window: 60,
          ip_threshold: 300,
          ip_window: 60,
          dynamic_scaling: true
        },
        adaptive_protection: {
          enabled: true,
          cpu_cores_per_10k_rps: 2,
          global_hard_reverify_window: 45,
          verified_scrubbing_rps: 20,
          hard_drop_on_overload: true,
          worker_connections_per_core: 8192,
          worker_rlimit_nofile_per_core: 65535,
          shared_dict_scale_per_core: 1.0
        },
        anti_bypass: {
          origin_proxy_only_default: true,
          slider_step_up_on_high_risk: true,
          slider_verification_ttl: 300,
          captcha_verification_ttl: 900,
          pow_verification_ttl: 1200
        },
        cluster: {
          enabled: false,
          node_id: 'node-1',
          node_role: 'primary',
          primary_api_url: '',
          nodes: [
            {
              id: 'node-1',
              name: '主节点',
              api_url: 'http://admin-backend:3000',
              role: 'primary',
              enabled: true,
              sync: true
            }
          ],
          sync: {
            enabled: true,
            config_interval: 30,
            blacklist_interval: 10,
            max_skew_seconds: 60,
            request_timeout_ms: 2000,
            fanout_concurrency: 6,
            retry_count: 2,
            retry_backoff_ms: 250
          }
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
    this.fetchSnapshotStatus();
  },
  methods: {
    async fetchSettings() {
      this.loading = true;
      try {
        const response = await axios.get('/config');
        if (response.data.success) {
          // 合并配置，保留默认值的属性
          this.mergeConfig(response.data.data);
        } else {
          this.$toast.error((response.data && response.data.message) || '加载系统设置失败。');
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '加载系统设置失败，请稍后重试。'));
        }
      } finally {
        this.loading = false;
      }
    },
    formatPublishedAt(value) {
      if (!value) {
        return '-';
      }

      const date = new Date(value);
      return Number.isFinite(date.getTime()) ? date.toLocaleString() : String(value);
    },
    async fetchSnapshotStatus() {
      this.snapshotLoading = true;
      try {
        const response = await axios.get('/snapshot/status');
        const payload = response && response.data ? response.data : null;
        if (payload && payload.code === 0) {
          this.snapshotStatus = payload.data || { active_version: null, published_at: null };
        } else {
          this.$toast.error((payload && payload.message) || '获取快照状态失败。');
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '获取快照状态失败，请稍后重试。'));
        }
      } finally {
        this.snapshotLoading = false;
      }
    },
    async publishSnapshot() {
      this.snapshotPublishing = true;
      try {
        const response = await axios.post('/snapshot/publish');
        const payload = response && response.data ? response.data : null;
        if (payload && payload.code === 0) {
          this.$toast.success('发布成功');
          await this.fetchSnapshotStatus();
        } else {
          this.$toast.error((payload && payload.message) || '发布失败。');
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '发布失败，请稍后重试。'));
        }
      } finally {
        this.snapshotPublishing = false;
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
      this.syncTrustedBotsText();
    },
    addTrap() {
      this.config.honeypot_settings.traps.push("");
    },
    removeTrap(index) {
      this.config.honeypot_settings.traps.splice(index, 1);
    },
    syncTrustedBotsText() {
      const bots = Array.isArray(this.config.trusted_bots) ? this.config.trusted_bots : [];
      this.trustedBotsText = bots.join('\n');
    },
    normalizeTrustedBots() {
      const trustedBots = String(this.trustedBotsText || '')
        .split(/\r?\n|,/)
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean)
        .filter((item, index, list) => list.indexOf(item) === index);

      this.config.trusted_bots = trustedBots;
      this.trustedBotsText = trustedBots.join('\n');
    },
    saveSettings() {
      $('#saveModal').modal('show');
    },
    async confirmSaveSettings() {
      try {
        this.normalizeTrustedBots();
        this.config.honeypot_settings.traps = this.config.honeypot_settings.traps
          .map((trap) => String(trap || '').trim())
          .filter(Boolean);

        const response = await axios.put('/config', this.config);
        
        if (response.data.success) {
          this.$toast.success(response.data.message || '设置已成功保存。');
          $('#saveModal').modal('hide');
          this.fetchSnapshotStatus();
        } else {
          this.$toast.error((response.data && response.data.message) || '保存设置失败。');
        }
      } catch (error) {
        if (shouldHandleLocally(error)) {
          this.$toast.error(getApiErrorMessage(error, '保存设置时发生错误，请稍后重试。'));
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
