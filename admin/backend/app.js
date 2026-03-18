const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const axios = require('axios');
const Redis = require('ioredis');
const morgan = require('morgan');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const os = require('os');
const net = require('net');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const snapshotCompiler = require('./snapshot_compiler');
const snapshotPublisher = require('./snapshot_publisher');
const ClusterManager = require('./cluster');
const HeartbeatWorker = require('./heartbeat-worker');
const {
  CfShieldWorker,
  readAttackTelemetry
} = require('./cf_worker');

function isStrongSecret(secret) {
  const value = String(secret || '');
  if (value.length < 32) {
    return false;
  }

  if (/^(change[-_ ]?me|default|secret|password|admin|test|123456)/i.test(value)) {
    return false;
  }

  const checks = [
    /[a-z]/.test(value),
    /[A-Z]/.test(value),
    /\d/.test(value),
    /[^A-Za-z0-9]/.test(value)
  ];

  return checks.filter(Boolean).length >= 3;
}

function sendError(res, httpStatus, message, code = httpStatus) {
  const normalizedMessage = typeof message === 'string' && message.trim()
    ? message.trim()
    : 'Request failed';
  return res.status(httpStatus).json({ code, message: normalizedMessage, data: null });
}

// JWT 配置
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRY = process.env.JWT_EXPIRY || '8h';
if (!isStrongSecret(JWT_SECRET)) {
  console.error('[FATAL] JWT_SECRET is not set or is too weak. Use at least 32 chars with mixed character classes.');
  process.exit(1);
}

// 管理员凭据（从环境变量读取）
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
// 密码哈希：用 node -e "require('bcryptjs').hash('yourpassword',12).then(console.log)" 生成
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
if (!ADMIN_PASSWORD_HASH) {
  console.error('[FATAL] ADMIN_PASSWORD_HASH is not set. Set a bcrypt password hash in environment variables.');
  process.exit(1);
}

// Redis client with password auth
const redis = new Redis({
  host: process.env.REDIS_HOST || 'redis',
  port: parseInt(process.env.REDIS_PORT || '6379', 10),
  password: process.env.REDIS_PASSWORD || undefined,
  enableReadyCheck: true,
  maxRetriesPerRequest: 3,
  retryStrategy: (times) => Math.min(times * 100, 3000)
});

redis.on('error', (err) => console.error('[Redis] Connection error:', err.message));

// Long-lived inter-node cluster token (uses same JWT_SECRET — valid for 365 days)
const CLUSTER_TOKEN = jwt.sign({ username: '_cluster', role: 'cluster' }, JWT_SECRET, { expiresIn: '365d' });

// Initialize cluster manager
const clusterManager = new ClusterManager();
const heartbeatWorker = new HeartbeatWorker(clusterManager);

// 鍒涘缓Express搴旂敤
const app = express();
const PORT = process.env.PORT || 3000;

// Normalize all error responses to: { code, message, data: null }
app.use((req, res, next) => {
  const originalJson = res.json.bind(res);

  res.json = (payload) => {
    if (res.statusCode >= 400) {
      const message = payload && typeof payload === 'object' && typeof payload.message === 'string'
        ? payload.message.trim()
        : typeof payload === 'string'
          ? payload.trim()
          : 'Request failed';

      const code = payload && typeof payload === 'object' && Number.isFinite(payload.code)
        ? payload.code
        : res.statusCode;

      return originalJson({ code, message, data: null });
    }

    return originalJson(payload);
  };

  next();
});

// 涓棿浠?
app.use(helmet()); // 瀹夊叏HTTP澶?
app.use(compression()); // 鍘嬬缉鍝嶅簲
app.use(morgan('combined')); // 鏃ュ織
app.use(bodyParser.json({ limit: '1mb' }));
app.use(bodyParser.urlencoded({ extended: false, limit: '1mb' }));

// 璺ㄥ煙閰嶇疆
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:8080',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// 鍩虹闄愰€燂細淇濇姢鐧诲綍鎺ュ彛锛岄伩鍏嶆毚鍔涚牬瑙?婊ョ敤
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
});

// Health check endpoint (no auth required)
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: Date.now() });
});

// Login API - issues JWT token
app.post('/api/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return sendError(res, 400, 'Missing credentials');
  }
  // Constant-time username check to prevent timing attacks
  const usernameMatch = username === ADMIN_USERNAME;
  // Always run bcrypt to prevent timing-based username enumeration
  const valid = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
  if (!usernameMatch || !valid) {
    return sendError(res, 401, 'Invalid username or password');
  }
  const token = jwt.sign({ username, role: 'administrator' }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
  res.json({
    success: true,
    message: 'Login successful',
    token,
    user: { username, role: 'administrator' }
  });
});

// JWT authentication middleware
const authMiddleware = (req, res, next) => {
  if (req.method === 'OPTIONS') return next();
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return sendError(res, 401, 'Unauthorized');
  }
  const token = authHeader.slice(7);
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (_) {
    return sendError(res, 401, 'Invalid or expired token');
  }
};

// Cluster token authentication middleware (for inter-node communication)
const clusterAuthMiddleware = (req, res, next) => {
  if (req.method === 'OPTIONS') return next();
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return sendError(res, 401, 'Unauthorized');
  }
  const token = authHeader.slice(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'cluster') {
      return sendError(res, 403, 'Forbidden: cluster token required');
    }
    req.user = decoded;
    next();
  } catch (_) {
    return sendError(res, 401, 'Invalid or expired cluster token');
  }
};

// 淇濇姢API璺敱
app.use('/api', authMiddleware);

// 淇敼涓哄崟鐙殑API璺敱鍓嶇紑
const apiRouter = express.Router();
app.use('/api', apiRouter);

// 閰嶇疆鐩綍
const CONFIG_DIR = process.env.CONFIG_DIR || '/app/config';
const SITES_DIR = path.join(CONFIG_DIR, 'sites');
const CERTS_DIR = path.join(CONFIG_DIR, 'certs');
const DEFAULT_CONFIG_PATH = path.join(CONFIG_DIR, 'default_config.json');
const NGINX_CONF_DIR = process.env.NGINX_CONF_DIR || '/nginx/conf.d';
const NGINX_CERT_DIR = process.env.NGINX_CERT_DIR || '/usr/local/openresty/nginx/conf/config/certs';

async function compileAndPublishSnapshot() {
  const bundle = await snapshotCompiler.compile(redis, CONFIG_DIR);
  await snapshotPublisher.publish(redis, bundle.version);
  return bundle;
}

const certUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 2 * 1024 * 1024
  }
});

function isObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function deepMerge(target, source) {
  if (!isObject(target) || !isObject(source)) {
    return target;
  }

  Object.keys(source).forEach((key) => {
    const sourceValue = source[key];
    if (isObject(sourceValue)) {
      if (!isObject(target[key])) {
        target[key] = {};
      }
      deepMerge(target[key], sourceValue);
    } else {
      target[key] = sourceValue;
    }
  });

  return target;
}

function normalizeNodeRole(value) {
  const role = String(value || '').toLowerCase();
  if (role === 'primary' || role === 'secondary') {
    return role;
  }
  return 'secondary';
}

function normalizeNodeId(value) {
  const id = String(value || '').trim();
  if (!id) {
    return `node-${Date.now()}`;
  }
  return id.replace(/[^a-zA-Z0-9._-]/g, '-').slice(0, 64);
}

function sanitizeUrl(url) {
  if (!url) {
    return '';
  }

  const raw = String(url).trim();
  if (!raw) {
    return '';
  }

  try {
    const parsed = new URL(raw);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return '';
    }
    parsed.hash = '';
    return parsed.toString().replace(/\/$/, '');
  } catch (_) {
    return '';
  }
}

function normalizeBackendPortFollow(value) {
  return value === true;
}

function buildBackendProxyConfig(backendServer, backendPortFollow) {
  let parsed;
  try {
    parsed = new URL(backendServer);
  } catch (_) {
    throw new Error('Invalid backend_server url');
  }

  const protocol = parsed.protocol.replace(':', '').toLowerCase();
  if (!['http', 'https'].includes(protocol)) {
    throw new Error('backend_server protocol must be http or https');
  }

  if (parsed.username || parsed.password) {
    throw new Error('backend_server must not include credentials');
  }

  const rawHostname = parsed.hostname;
  if (!rawHostname) {
    throw new Error('backend_server hostname is required');
  }

  const upstreamHost = rawHostname.includes(':') ? `[${rawHostname}]` : rawHostname;
  const explicitPort = parsed.port
    ? parseInt(parsed.port, 10)
    : (protocol === 'https' ? 443 : 80);

  if (!Number.isInteger(explicitPort) || explicitPort < 1 || explicitPort > 65535) {
    throw new Error('backend_server port must be between 1 and 65535');
  }

  const pathname = parsed.pathname && parsed.pathname !== '/' ? parsed.pathname : '';
  const search = parsed.search || '';
  const uriSuffix = `${pathname}${search}`;
  const portFollow = normalizeBackendPortFollow(backendPortFollow);

  return {
    protocol,
    serverName: rawHostname,
    usesHttps: protocol === 'https',
    portFollow,
    fixedProxyPass: `${protocol}://${upstreamHost}:${explicitPort}${uriSuffix}`,
    followProxyPass: `${protocol}://${upstreamHost}:$server_port${uriSuffix}`
  };
}

function sanitizeNginxPath(filePath) {
  if (!filePath) {
    return '';
  }

  const raw = String(filePath).trim();
  if (!raw) {
    return '';
  }

  if (!raw.startsWith('/')) {
    return '';
  }

  if (raw.includes('..') || /\s/.test(raw)) {
    return '';
  }

  if (!/^\/[A-Za-z0-9._/\-]+$/.test(raw)) {
    return '';
  }

  return raw;
}

function getDefaultTlsPaths(domain) {
  const normalizedDomain = String(domain || '').toLowerCase() || 'example.com';
  return {
    cert_path: `${NGINX_CERT_DIR}/${normalizedDomain}.crt`,
    key_path: `${NGINX_CERT_DIR}/${normalizedDomain}.key`
  };
}

function normalizeSiteTlsConfig(siteConfig, domain) {
  const tlsInput = isObject(siteConfig && siteConfig.tls) ? siteConfig.tls : {};
  const defaults = getDefaultTlsPaths(domain);

  const certPath = sanitizeNginxPath(tlsInput.cert_path) || defaults.cert_path;
  const keyPath = sanitizeNginxPath(tlsInput.key_path) || defaults.key_path;

  return {
    enabled: tlsInput.enabled === true,
    cert_path: certPath,
    key_path: keyPath,
    redirect_http_to_https: tlsInput.redirect_http_to_https !== false,
    http2_enabled: tlsInput.http2_enabled !== false
  };
}

function toBooleanOrDefault(value, defaultValue) {
  return typeof value === 'boolean' ? value : defaultValue;
}

function normalizeInteger(value, defaultValue, minValue, maxValue) {
  const normalized = Number.parseInt(value, 10);
  if (!Number.isFinite(normalized)) {
    return defaultValue;
  }

  if (typeof minValue === 'number' && normalized < minValue) {
    return minValue;
  }

  if (typeof maxValue === 'number' && normalized > maxValue) {
    return maxValue;
  }

  return normalized;
}

function normalizeAntiBypassConfig(rawConfig) {
  const antiBypassInput = isObject(rawConfig && rawConfig.anti_bypass) ? rawConfig.anti_bypass : {};

  return {
    origin_proxy_only_default: toBooleanOrDefault(antiBypassInput.origin_proxy_only_default, true),
    slider_step_up_on_high_risk: toBooleanOrDefault(antiBypassInput.slider_step_up_on_high_risk, true),
    slider_verification_ttl: normalizeInteger(antiBypassInput.slider_verification_ttl, 300, 60, 3600),
    captcha_verification_ttl: normalizeInteger(antiBypassInput.captcha_verification_ttl, 900, 60, 7200),
    pow_verification_ttl: normalizeInteger(antiBypassInput.pow_verification_ttl, 1200, 60, 7200)
  };
}

function normalizeAttackReasonName(reason) {
  const raw = String(reason || '').trim();
  if (!raw) {
    return 'unknown';
  }

  return raw
    .replace(/^ddos_protection_/i, '')
    .replace(/^ddos_/i, '')
    .replace(/^slow_ddos_/i, 'slow_')
    .replace(/_/g, ' ')
    .trim() || 'unknown';
}

function isAttackReason(reason) {
  return /^(ddos_|ddos_protection_|slow_ddos_)/i.test(String(reason || ''));
}

function parseJsonLines(lines) {
  return (Array.isArray(lines) ? lines : []).map((line) => {
    try {
      return JSON.parse(line);
    } catch (_) {
      return null;
    }
  }).filter(Boolean);
}

function detectAttackFromLogs(logs) {
  return (Array.isArray(logs) ? logs : []).some((item) => item && isAttackReason(item.reason));
}

function buildAttackTargetSummary(topSites, topUris, topBlockReasons) {
  const site = Array.isArray(topSites) && topSites.length > 0 ? topSites[0] : null;
  const uri = Array.isArray(topUris) && topUris.length > 0 ? topUris[0] : null;
  const reason = Array.isArray(topBlockReasons) && topBlockReasons.length > 0 ? topBlockReasons[0] : null;

  const siteName = site && site.name ? site.name : '';
  const uriName = uri && uri.name ? uri.name : '';
  const reasonName = reason && reason.name ? reason.name : '';
  const reasonLabel = reasonName ? normalizeAttackReasonName(reasonName) : 'unknown';

  const labelParts = [];
  if (siteName) {
    labelParts.push(siteName);
  }
  if (uriName) {
    labelParts.push(uriName);
  }
  if (reasonLabel && reasonLabel !== 'unknown') {
    labelParts.push(reasonLabel);
  }

  return {
    site: siteName || null,
    site_score: site ? Number(site.score || 0) : 0,
    uri: uriName || null,
    uri_score: uri ? Number(uri.score || 0) : 0,
    reason: reasonName || null,
    reason_label: reasonLabel,
    reason_score: reason ? Number(reason.score || 0) : 0,
    label: labelParts.length > 0 ? labelParts.join(' · ') : '暂无攻击目标'
  };
}

function formatAttackSummaryLine(status) {
  const currentStatus = isObject(status) ? status : {};
  const target = isObject(currentStatus.target_summary) ? currentStatus.target_summary : {};
  const score = Number(currentStatus.score || 0);
  const shieldState = isObject(currentStatus.shield_state) ? currentStatus.shield_state : {};
  const suffix = shieldState.active ? '（CF Shield 已开启）' : '';

  if (currentStatus.active) {
    return `检测到攻击：${target.label || '暂无攻击目标'}，当前分数 ${score}${suffix}`;
  }

  return `攻击已缓解：${target.label || '暂无攻击目标'}，当前分数 ${score}${suffix}`;
}

function isSameAttackStatus(previousState, currentState) {
  const previous = isObject(previousState) ? previousState : {};
  const current = isObject(currentState) ? currentState : {};
  const previousTarget = isObject(previous.target_summary) ? previous.target_summary : {};
  const currentTarget = isObject(current.target_summary) ? current.target_summary : {};

  return Boolean(previous.active) === Boolean(current.active)
    && Number(previous.score || 0) === Number(current.score || 0)
    && Number(previous.peak || 0) === Number(current.peak || 0)
    && Number(previous.last_attack_at || 0) === Number(current.last_attack_at || 0)
    && Boolean(previous.shield_state && previous.shield_state.active) === Boolean(current.shield_state && current.shield_state.active)
    && String(previousTarget.label || '') === String(currentTarget.label || '');
}

function buildAttackNotifications(previousState, currentState) {
  const previous = isObject(previousState) ? previousState : null;
  const current = isObject(currentState) ? currentState : {};
  const notifications = [];
  const target = isObject(current.target_summary) ? current.target_summary : {};
  const stateChangedAt = Number(current.state_changed_at || current.last_attack_at || Date.now());

  if (!previous || !previous.active) {
    if (current.active) {
      notifications.push({
        key: `attack_started:${stateChangedAt}`,
        type: 'attack_started',
        level: 'error',
        message: formatAttackSummaryLine(current),
        at: stateChangedAt
      });
    }
    return notifications;
  }

  if (previous.active && !current.active) {
    notifications.push({
      key: `attack_recovered:${stateChangedAt}`,
      type: 'attack_recovered',
      level: 'success',
      message: formatAttackSummaryLine(current),
      at: stateChangedAt
    });
    return notifications;
  }

  const previousTarget = isObject(previous.target_summary) ? previous.target_summary : {};
  if (
    current.active
    && String(previousTarget.label || '') !== String(target.label || '')
    && String(target.label || '')
    && String(target.label || '') !== '暂无攻击目标'
  ) {
    notifications.push({
      key: `target_changed:${stateChangedAt}:${target.label}`,
      type: 'target_changed',
      level: 'warning',
      message: `攻击目标变化：${target.label}`,
      at: stateChangedAt
    });
  }

  return notifications;
}

function summarizeAttackStatus(options) {
  const telemetry = isObject(options && options.telemetry) ? options.telemetry : {};
  const shieldState = isObject(options && options.shieldState) ? options.shieldState : { active: false };
  const topSites = Array.isArray(options && options.topSites) ? options.topSites : [];
  const topUris = Array.isArray(options && options.topUris) ? options.topUris : [];
  const topBlockReasons = Array.isArray(options && options.topBlockReasons) ? options.topBlockReasons : [];
  const logs = Array.isArray(options && options.logs) ? options.logs : [];
  const historyItems = Array.isArray(options && options.historyItems) ? options.historyItems : [];
  const activateThreshold = Number(options && options.activateThreshold || 50);
  const now = Number(options && options.now || Date.now());
  const score = Number(telemetry.score || 0);
  const peak = Number(telemetry.peak || 0);
  const lastAttackAt = Number(telemetry.last_attack_at || 0);
  const activeByShield = Boolean(shieldState.active);
  const activeByScore = score >= activateThreshold;
  const activeByLogs = detectAttackFromLogs(logs);
  const activeByReasons = topBlockReasons.some((item) => item && isAttackReason(item.name));
  const activeByRecentAttack = lastAttackAt > 0 && (now - lastAttackAt) <= 5 * 60 * 1000;
  const active = activeByShield || activeByScore || activeByLogs || activeByReasons || activeByRecentAttack;
  const recentEvents = historyItems
    .map((item) => ({
      type: item && item.type ? item.type : 'unknown',
      at: Number(item && item.at || 0),
      reason: item && item.reason ? item.reason : '',
      score: Number(item && item.score || 0),
      errors: Array.isArray(item && item.errors) ? item.errors : []
    }))
    .filter((item) => item.at > 0)
    .sort((a, b) => b.at - a.at)
    .slice(0, 10);

  return {
    active,
    score,
    peak,
    last_attack_at: lastAttackAt,
    shield_state: shieldState,
    target_summary: buildAttackTargetSummary(topSites, topUris, topBlockReasons),
    recent_events: recentEvents,
    summary: active ? '正在被攻击' : '已恢复',
    state_changed_at: Number((active ? shieldState.activated_at : shieldState.deactivated_at) || lastAttackAt || now)
  };
}

function buildAttackStatusPayload(currentState, previousState) {
  const current = isObject(currentState) ? currentState : {};
  const previous = isObject(previousState) ? previousState : null;
  return {
    ...current,
    changed: previous ? !isSameAttackStatus(previous, current) : Boolean(current.active),
    notifications: buildAttackNotifications(previous, current)
  };
}

function normalizeSiteProtectionConfig(siteConfig, antiBypassConfig) {
  const protectionInput = isObject(siteConfig && siteConfig.protection) ? siteConfig.protection : {};

  return {
    ...protectionInput,
    ddos_reverify_window: normalizeInteger(protectionInput.ddos_reverify_window, 120, 10, 3600),
    origin_proxy_only_enabled: toBooleanOrDefault(
      protectionInput.origin_proxy_only_enabled,
      antiBypassConfig.origin_proxy_only_default
    )
  };
}

function normalizeSiteVerificationMethods(siteConfig, antiBypassConfig) {
  const verificationInput = isObject(siteConfig && siteConfig.verification_methods)
    ? siteConfig.verification_methods
    : {};
  const verificationBindings = isObject(verificationInput.verification_methods)
    ? verificationInput.verification_methods
    : {};

  return {
    ...verificationInput,
    captcha_enabled: toBooleanOrDefault(verificationInput.captcha_enabled, true),
    slider_captcha_enabled: toBooleanOrDefault(verificationInput.slider_captcha_enabled, true),
    pow_enabled: toBooleanOrDefault(verificationInput.pow_enabled, true),
    pow_base_difficulty: normalizeInteger(verificationInput.pow_base_difficulty, 4, 1, 10),
    pow_max_difficulty: normalizeInteger(verificationInput.pow_max_difficulty, 8, 1, 15),
    slider_step_up_on_high_risk: toBooleanOrDefault(
      verificationInput.slider_step_up_on_high_risk,
      antiBypassConfig.slider_step_up_on_high_risk
    ),
    slider_verification_ttl: normalizeInteger(
      verificationInput.slider_verification_ttl,
      antiBypassConfig.slider_verification_ttl,
      60,
      3600
    ),
    captcha_verification_ttl: normalizeInteger(
      verificationInput.captcha_verification_ttl,
      antiBypassConfig.captcha_verification_ttl,
      60,
      7200
    ),
    pow_verification_ttl: normalizeInteger(
      verificationInput.pow_verification_ttl,
      antiBypassConfig.pow_verification_ttl,
      60,
      7200
    ),
    verification_methods: {
      ip_address: toBooleanOrDefault(verificationBindings.ip_address, true),
      user_agent: toBooleanOrDefault(verificationBindings.user_agent, true),
      cookie: toBooleanOrDefault(verificationBindings.cookie, true)
    }
  };
}

function normalizeSiteConfig(rawConfig, fallbackDomain, antiBypassConfig = normalizeAntiBypassConfig(rawConfig)) {
  if (!isObject(rawConfig)) {
    throw new Error('Invalid site config payload');
  }

  const normalized = JSON.parse(JSON.stringify(rawConfig));
  const normalizedDomain = String(normalized.domain || fallbackDomain || '').toLowerCase().trim();
  const backendServer = sanitizeUrl(normalized.backend_server);
  const backendPortFollow = normalizeBackendPortFollow(normalized.backend_port_follow);

  if (!normalizedDomain || !/^[a-zA-Z0-9.-]{1,255}$/.test(normalizedDomain)) {
    throw new Error('Invalid site domain');
  }

  if (!backendServer) {
    throw new Error('Invalid backend_server url');
  }

  buildBackendProxyConfig(backendServer, backendPortFollow);

  normalized.domain = normalizedDomain;
  normalized.backend_server = backendServer;
  normalized.backend_port_follow = backendPortFollow;
  normalized.enabled = normalized.enabled !== false;
  normalized.tls = normalizeSiteTlsConfig(normalized, normalizedDomain);
  normalized.protection = normalizeSiteProtectionConfig(normalized, antiBypassConfig);
  normalized.verification_methods = normalizeSiteVerificationMethods(normalized, antiBypassConfig);

  return normalized;
}

function mapNginxCertPathToHostPath(nginxPath) {
  const normalizedPath = sanitizeNginxPath(nginxPath);
  if (!normalizedPath) {
    return '';
  }

  const prefix = `${NGINX_CERT_DIR}/`;
  if (!normalizedPath.startsWith(prefix)) {
    return '';
  }

  const relativePath = normalizedPath.slice(prefix.length);
  if (!relativePath || relativePath.includes('..') || relativePath.startsWith('/')) {
    return '';
  }

  return path.join(CERTS_DIR, relativePath);
}

async function validateSiteTlsFiles(siteConfig) {
  const normalizedSiteConfig = normalizeSiteConfig(siteConfig, siteConfig && siteConfig.domain);
  const tlsConfig = normalizeSiteTlsConfig(normalizedSiteConfig, normalizedSiteConfig.domain);

  if (!normalizedSiteConfig.enabled) {
    return;
  }

  if (!tlsConfig.enabled) {
    return;
  }

  const certHostPath = mapNginxCertPathToHostPath(tlsConfig.cert_path);
  const keyHostPath = mapNginxCertPathToHostPath(tlsConfig.key_path);

  if (!certHostPath || !keyHostPath) {
    throw new Error(`TLS certificate paths must be under ${NGINX_CERT_DIR}`);
  }

  try {
    await fs.access(certHostPath);
  } catch (_) {
    throw new Error(`TLS certificate file not found: ${tlsConfig.cert_path}`);
  }

  try {
    await fs.access(keyHostPath);
  } catch (_) {
    throw new Error(`TLS private key file not found: ${tlsConfig.key_path}`);
  }
}

function sanitizeFilename(filename) {
  const raw = String(filename || '').trim();
  const name = path.basename(raw).replace(/[^a-zA-Z0-9._-]/g, '_');
  return name;
}

function resolveCertFilenames(input, fallbackDomain) {
  const normalizedDomain = String(fallbackDomain || '').toLowerCase().trim();
  const baseName = /^[a-zA-Z0-9.-]{1,255}$/.test(normalizedDomain)
    ? normalizedDomain
    : `cert-${Date.now()}`;

  const certInput = sanitizeFilename(input.cert_filename || `${baseName}.crt`);
  const keyInput = sanitizeFilename(input.key_filename || `${baseName}.key`);

  const certFileName = certInput.match(/\.(crt|pem)$/i) ? certInput : `${certInput}.crt`;
  const keyFileName = keyInput.match(/\.(key|pem)$/i) ? keyInput : `${keyInput}.key`;

  return {
    cert_file_name: certFileName,
    key_file_name: keyFileName
  };
}

function ensurePemLikeContent(content, type) {
  const value = String(content || '').trim();
  if (!value) {
    throw new Error(`${type} content is required`);
  }

  if (!value.includes('-----BEGIN')) {
    throw new Error(`${type} content is invalid`);
  }

  return `${value}\n`;
}

function normalizeCertificateDomain(domainInput) {
  const domain = String(domainInput || '').toLowerCase().trim();
  if (!domain || !/^[a-z0-9][a-z0-9.-]{0,253}[a-z0-9]$/.test(domain) || !domain.includes('.')) {
    throw new Error('A valid domain is required for certificate validation');
  }
  return domain;
}

function extractPemBlocks(content, type) {
  const pattern = type === 'certificate'
    ? /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g
    : /-----BEGIN[\s\S]+?PRIVATE KEY-----[\s\S]+?-----END[\s\S]+?PRIVATE KEY-----/g;

  return String(content || '').match(pattern) || [];
}

function extractCertificateHostnames(x509) {
  const hostnames = new Set();
  const san = String(x509.subjectAltName || '');

  if (san) {
    san.split(',').forEach((item) => {
      const entry = item.trim();
      if (entry.toUpperCase().startsWith('DNS:')) {
        const value = entry.slice(4).trim().toLowerCase();
        if (value) {
          hostnames.add(value);
        }
      }
    });
  }

  if (hostnames.size === 0) {
    const subject = String(x509.subject || '');
    const cnMatch = subject.match(/CN\s*=\s*([^,\n/]+)/i);
    if (cnMatch && cnMatch[1]) {
      hostnames.add(cnMatch[1].trim().toLowerCase());
    }
  }

  return Array.from(hostnames);
}

function matchCertificateHostname(pattern, domain) {
  if (!pattern || !domain) {
    return false;
  }

  const normalizedPattern = pattern.toLowerCase();
  const normalizedDomain = domain.toLowerCase();

  if (normalizedPattern === normalizedDomain) {
    return true;
  }

  if (!normalizedPattern.startsWith('*.')) {
    return false;
  }

  const baseDomain = normalizedPattern.slice(2);
  if (!baseDomain || !normalizedDomain.endsWith(`.${baseDomain}`)) {
    return false;
  }

  const leftLabel = normalizedDomain.slice(0, normalizedDomain.length - baseDomain.length - 1);
  return !!leftLabel && !leftLabel.includes('.');
}

function validateCertificateBundle(certContent, keyContent, domain) {
  const normalizedDomain = normalizeCertificateDomain(domain);
  const normalizedCertContent = ensurePemLikeContent(certContent, 'Certificate');
  const normalizedKeyContent = ensurePemLikeContent(keyContent, 'Private key');

  const certBlocks = extractPemBlocks(normalizedCertContent, 'certificate');
  if (certBlocks.length === 0) {
    throw new Error('Certificate content must include a valid PEM certificate block');
  }

  let x509;
  try {
    x509 = new crypto.X509Certificate(certBlocks[0]);
  } catch (_) {
    throw new Error('Unable to parse certificate file');
  }

  const validFrom = new Date(x509.validFrom);
  const validTo = new Date(x509.validTo);
  const now = new Date();

  if (Number.isNaN(validFrom.getTime()) || Number.isNaN(validTo.getTime())) {
    throw new Error('Certificate validity time is invalid');
  }

  if (now < validFrom) {
    throw new Error(`Certificate is not valid before ${validFrom.toISOString()}`);
  }

  if (now > validTo) {
    throw new Error(`Certificate has expired at ${validTo.toISOString()}`);
  }

  const hostnames = extractCertificateHostnames(x509);
  const matched = hostnames.some((hostname) => matchCertificateHostname(hostname, normalizedDomain));
  if (!matched) {
    throw new Error(`Certificate SAN/CN does not match domain ${normalizedDomain}`);
  }

  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(normalizedKeyContent);
  } catch (_) {
    throw new Error('Unable to parse private key file');
  }

  let certPublicKeyDer;
  let keyPublicKeyDer;
  try {
    certPublicKeyDer = x509.publicKey.export({ type: 'spki', format: 'der' });
    keyPublicKeyDer = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  } catch (_) {
    throw new Error('Failed to verify certificate and private key pair');
  }

  if (!Buffer.from(certPublicKeyDer).equals(Buffer.from(keyPublicKeyDer))) {
    throw new Error('Certificate and private key do not match');
  }

  return {
    domain: normalizedDomain,
    subject: x509.subject,
    issuer: x509.issuer,
    valid_from: validFrom.toISOString(),
    valid_to: validTo.toISOString(),
    days_remaining: Math.max(0, Math.floor((validTo.getTime() - now.getTime()) / (24 * 60 * 60 * 1000))),
    hostnames
  };
}

function normalizeClusterConfig(config) {
  const cluster = isObject(config.cluster) ? config.cluster : {};
  const nodesInput = Array.isArray(cluster.nodes) ? cluster.nodes : [];
  const syncInput = isObject(cluster.sync) ? cluster.sync : {};

  const nodeRole = normalizeNodeRole(cluster.node_role || cluster.role || 'primary');
  const nodeId = normalizeNodeId(cluster.node_id || process.env.SAFELINE_NODE_ID || 'node-1');
  const enabled = cluster.enabled === true;

  const seen = new Set();
  const nodes = [];

  nodesInput.forEach((node, index) => {
    if (!isObject(node)) {
      return;
    }

    const id = normalizeNodeId(node.id || `node-${index + 1}`);
    if (seen.has(id)) {
      return;
    }
    seen.add(id);

    const role = normalizeNodeRole(node.role);
    const apiUrl = sanitizeUrl(node.api_url);
    const normalizedNode = {
      id,
      name: String(node.name || id),
      api_url: apiUrl,
      role,
      enabled: node.enabled !== false,
      sync: node.sync !== false
    };

    nodes.push(normalizedNode);
  });

  if (!seen.has(nodeId)) {
    nodes.unshift({
      id: nodeId,
      name: nodeRole === 'primary' ? 'Primary node' : 'Local node',
      api_url: sanitizeUrl(process.env.NODE_PUBLIC_API || ''),
      role: nodeRole,
      enabled: true,
      sync: true
    });
  }

  const primaryNode = nodes.find((n) => n.role === 'primary') || nodes[0];
  const primaryApi = sanitizeUrl(cluster.primary_api_url) || (primaryNode ? primaryNode.api_url : '');

  const sync = {
    enabled: syncInput.enabled !== false,
    config_interval: Math.max(5, parseInt(syncInput.config_interval || 30, 10)),
    blacklist_interval: Math.max(3, parseInt(syncInput.blacklist_interval || 10, 10)),
    max_skew_seconds: Math.max(10, parseInt(syncInput.max_skew_seconds || 60, 10)),
    request_timeout_ms: Math.max(300, parseInt(syncInput.request_timeout_ms || 2000, 10)),
    fanout_concurrency: Math.max(1, parseInt(syncInput.fanout_concurrency || 6, 10)),
    retry_count: Math.max(0, parseInt(syncInput.retry_count || 2, 10)),
    retry_backoff_ms: Math.max(50, parseInt(syncInput.retry_backoff_ms || 250, 10))
  };

  return {
    enabled,
    node_id: nodeId,
    node_role: nodeRole,
    primary_api_url: primaryApi,
    nodes,
    sync
  };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }

  if (isObject(value)) {
    const sorted = {};
    Object.keys(value).sort().forEach((key) => {
      sorted[key] = canonicalize(value[key]);
    });
    return sorted;
  }

  return value;
}

function getConfigVersionInfo(config) {
  const normalized = canonicalize(config || {});
  const content = JSON.stringify(normalized);
  const hash = crypto.createHash('sha256').update(content).digest('hex');

  return {
    hash,
    generated_at: Date.now()
  };
}

async function runWithConcurrency(items, concurrency, worker) {
  const queue = Array.isArray(items) ? items.slice() : [];
  const results = [];
  const size = Math.max(1, parseInt(concurrency || 1, 10));

  const runners = new Array(Math.min(size, queue.length || 1)).fill(null).map(async () => {
    while (queue.length > 0) {
      const item = queue.shift();
      if (!item) {
        continue;
      }

      const result = await worker(item);
      results.push(result);
    }
  });

  await Promise.all(runners);
  return results;
}

async function postWithRetry(url, body, requestOptions, retryCount, retryBackoffMs) {
  const maxRetry = Math.max(0, parseInt(retryCount || 0, 10));
  const backoff = Math.max(50, parseInt(retryBackoffMs || 250, 10));

  let lastError = null;
  for (let attempt = 0; attempt <= maxRetry; attempt += 1) {
    try {
      const response = await axios.post(url, body, requestOptions);
      return { response, attempts: attempt + 1 };
    } catch (error) {
      lastError = error;
      if (attempt < maxRetry) {
        await sleep(backoff * Math.pow(2, attempt));
      }
    }
  }

  throw { error: lastError, attempts: maxRetry + 1 };
}

function getRuntimeProfile(config) {
  const adaptive = isObject(config.adaptive_protection) ? config.adaptive_protection : {};
  const ddos = isObject(config.ddos_protection) ? config.ddos_protection : {};

  const cores = Math.max(1, os.cpus().length || 1);
  const enabled = adaptive.enabled !== false;
  const per10k = Math.max(1, parseFloat(adaptive.cpu_cores_per_10k_rps || 2));
  const estimatedCapacityRps = Math.floor((cores / per10k) * 10000);
  const workerConnections = Math.floor((parseInt(adaptive.worker_connections_per_core || 8192, 10) || 8192) * cores);
  const workerRlimit = Math.floor((parseInt(adaptive.worker_rlimit_nofile_per_core || 65535, 10) || 65535) * cores);
  const sharedScale = Math.max(0.1, parseFloat(adaptive.shared_dict_scale_per_core || 1.0) || 1.0);

  const softRatio = 1 + (cores - 1) * 0.6;
  const ddosSuggested = {
    url_threshold: Math.max(30, Math.floor((parseInt(ddos.url_threshold || 60, 10) || 60) * softRatio)),
    ip_threshold: Math.max(120, Math.floor((parseInt(ddos.ip_threshold || 300, 10) || 300) * softRatio)),
    global_threshold: Math.max(500, (parseInt(ddos.global_threshold || 3000, 10) || 3000) * cores),
    global_hard_threshold: Math.max(1000, (parseInt(ddos.global_hard_threshold || 8000, 10) || 8000) * cores)
  };

  return {
    adaptive_enabled: enabled,
    cpu_cores: cores,
    estimated_capacity_rps: estimatedCapacityRps,
    suggested_worker_connections: workerConnections,
    suggested_worker_rlimit_nofile: workerRlimit,
    suggested_shared_dict_scale: Number(sharedScale.toFixed(2)),
    suggested_ddos_thresholds: ddosSuggested
  };
}

function getCurrentNode(config) {
  const cluster = normalizeClusterConfig(config);
  const current = cluster.nodes.find((node) => node.id === cluster.node_id) || null;
  return {
    id: cluster.node_id,
    role: cluster.node_role,
    enabled: cluster.enabled,
    api_url: current ? current.api_url : '',
    cluster_size: cluster.nodes.length,
    primary_api_url: cluster.primary_api_url
  };
}

async function fetchNodeStatus(node, timeoutMs) {
  if (!node.enabled || !node.api_url) {
    return {
      id: node.id,
      name: node.name,
      role: node.role,
      enabled: node.enabled,
      sync: node.sync,
      healthy: false,
      message: node.enabled ? 'Missing API URL' : 'Node disabled'
    };
  }

  try {
    const response = await axios.get(`${node.api_url}/api/cluster/node`, {
      timeout: timeoutMs,
      headers: { Authorization: `Bearer ${CLUSTER_TOKEN}` }
    });

    const remote = response.data && response.data.data ? response.data.data : null;
    if (!remote) {
      return {
        id: node.id,
        name: node.name,
        role: node.role,
        enabled: node.enabled,
        sync: node.sync,
        healthy: false,
        message: '鑺傜偣杩斿洖鏃犳晥鏁版嵁'
      };
    }

    return {
      id: node.id,
      name: node.name,
      role: node.role,
      enabled: node.enabled,
      sync: node.sync,
      healthy: true,
      remote_id: remote.id,
      remote_role: remote.role,
      cluster_size: remote.cluster_size,
      primary_api_url: remote.primary_api_url,
      message: 'ok'
    };
  } catch (error) {
    return {
      id: node.id,
      name: node.name,
      role: node.role,
      enabled: node.enabled,
      sync: node.sync,
      healthy: false,
      message: error.message
    };
  }
}

async function replicateConfigToSecondaries(config, options = {}) {
  const cluster = normalizeClusterConfig(config);
  if (!cluster.enabled) {
    return [];
  }

  const current = getCurrentNode(config);
  if (current.role !== 'primary') {
    return [];
  }

  const timeoutMs = options.timeoutMs || cluster.sync.request_timeout_ms;
  const fanoutConcurrency = options.fanoutConcurrency || cluster.sync.fanout_concurrency;
  const retryCount = options.retryCount !== undefined ? options.retryCount : cluster.sync.retry_count;
  const retryBackoffMs = options.retryBackoffMs || cluster.sync.retry_backoff_ms;
  const requestAuth = { headers: { Authorization: `Bearer ${CLUSTER_TOKEN}` } };

  const version = getConfigVersionInfo(config);
  const payload = {
    config,
    version,
    source: {
      node_id: cluster.node_id,
      ts: Date.now()
    }
  };

  const targets = cluster.nodes.filter((node) => (
    node.enabled && node.sync && node.id !== cluster.node_id && node.role !== 'primary' && node.api_url
  ));

  return runWithConcurrency(targets, fanoutConcurrency, async (node) => {
    try {
      const requestOptions = {
        timeout: timeoutMs,
        ...requestAuth
      };
      const { response, attempts } = await postWithRetry(
        `${node.api_url}/api/cluster/sync/config`,
        payload,
        requestOptions,
        retryCount,
        retryBackoffMs
      );

      const ok = !!(response.data && response.data.success);
      return {
        id: node.id,
        api_url: node.api_url,
        success: ok,
        attempts,
        version: version.hash,
        message: ok ? '鍚屾鎴愬姛' : (response.data && response.data.message) || '鍚屾澶辫触'
      };
    } catch (failure) {
      const error = failure && failure.error ? failure.error : failure;
      const attempts = failure && failure.attempts ? failure.attempts : 1;
      return {
        id: node.id,
        api_url: node.api_url,
        success: false,
        attempts,
        version: version.hash,
        message: error && error.message ? error.message : '璇锋眰澶辫触'
      };
    }
  });
}

async function replicateBlacklistToSecondaries(config, payload, options = {}) {
  const cluster = normalizeClusterConfig(config);
  if (!cluster.enabled) {
    return [];
  }

  const current = getCurrentNode(config);
  if (current.role !== 'primary') {
    return [];
  }

  const timeoutMs = options.timeoutMs || cluster.sync.request_timeout_ms;
  const fanoutConcurrency = options.fanoutConcurrency || cluster.sync.fanout_concurrency;
  const retryCount = options.retryCount !== undefined ? options.retryCount : cluster.sync.retry_count;
  const retryBackoffMs = options.retryBackoffMs || cluster.sync.retry_backoff_ms;
  const requestAuth = { headers: { Authorization: `Bearer ${CLUSTER_TOKEN}` } };

  const requestBody = {
    ...payload,
    source: {
      node_id: cluster.node_id,
      ts: Date.now()
    }
  };

  const targets = cluster.nodes.filter((node) => (
    node.enabled && node.sync && node.id !== cluster.node_id && node.role !== 'primary' && node.api_url
  ));

  return runWithConcurrency(targets, fanoutConcurrency, async (node) => {
    try {
      const requestOptions = {
        timeout: timeoutMs,
        ...requestAuth
      };
      const { response, attempts } = await postWithRetry(
        `${node.api_url}/api/cluster/sync/blacklist`,
        requestBody,
        requestOptions,
        retryCount,
        retryBackoffMs
      );

      const ok = !!(response.data && response.data.success);
      return {
        id: node.id,
        api_url: node.api_url,
        success: ok,
        attempts,
        message: ok ? '鍚屾鎴愬姛' : (response.data && response.data.message) || '鍚屾澶辫触'
      };
    } catch (failure) {
      const error = failure && failure.error ? failure.error : failure;
      const attempts = failure && failure.attempts ? failure.attempts : 1;
      return {
        id: node.id,
        api_url: node.api_url,
        success: false,
        attempts,
        message: error && error.message ? error.message : '璇锋眰澶辫触'
      };
    }
  });
}

async function applyIncomingClusterConfig(incomingConfig, localConfig) {
  if (!isObject(incomingConfig)) {
    return { success: false, message: '閰嶇疆鏁版嵁鏃犳晥' };
  }

  const localCluster = normalizeClusterConfig(localConfig || {});
  const normalizedIncomingCluster = normalizeClusterConfig(incomingConfig);

  incomingConfig.cluster = {
    ...normalizedIncomingCluster,
    node_id: localCluster.node_id,
    node_role: localCluster.node_role,
    primary_api_url: localCluster.primary_api_url,
    nodes: localCluster.nodes,
    enabled: localCluster.enabled
  };

  const previousConfigRaw = await readTextFileIfExists(DEFAULT_CONFIG_PATH);
  const success = await writeConfigFile(DEFAULT_CONFIG_PATH, incomingConfig);
  if (!success) {
    return { success: false, message: '鍐欏叆鏈湴閰嶇疆澶辫触' };
  }

  try {
    await setupClusterSyncLoop();
  } catch (error) {
    try {
      await restoreTextFile(DEFAULT_CONFIG_PATH, previousConfigRaw);
    } catch (rollbackError) {
      console.error('[Cluster] rollback default_config.json failed:', rollbackError.message || rollbackError);
    }
    return { success: false, message: error.message || 'Failed to apply incoming config' };
  }

  return { success: true };
}

async function getNodeConfigVersion() {
  const config = await readConfigFile(DEFAULT_CONFIG_PATH);
  if (!config) {
    return null;
  }

  return getConfigVersionInfo(config);
}

async function shouldSkipIncomingConfigSync(payloadVersion) {
  if (!payloadVersion || !payloadVersion.hash) {
    return false;
  }

  const localVersion = await getNodeConfigVersion();
  if (!localVersion || !localVersion.hash) {
    return false;
  }

  return localVersion.hash === payloadVersion.hash;
}

async function syncConfigFromPrimary(config) {
  const cluster = normalizeClusterConfig(config);
  if (!cluster.enabled || cluster.node_role !== 'secondary' || !cluster.sync.enabled || !cluster.primary_api_url) {
    return { attempted: false };
  }

  try {
    const requestAuth = { headers: { Authorization: `Bearer ${CLUSTER_TOKEN}` } };

    const response = await axios.get(`${cluster.primary_api_url}/api/config`, {
      timeout: cluster.sync.request_timeout_ms,
      ...requestAuth
    });

    if (!(response.data && response.data.success && isObject(response.data.data))) {
      return { attempted: true, success: false, message: 'Invalid primary node config response' };
    }

    const applyResult = await applyIncomingClusterConfig(response.data.data, config);
    if (!applyResult.success) {
      return { attempted: true, success: false, message: applyResult.message };
    }

    return { attempted: true, success: true };
  } catch (error) {
    return { attempted: true, success: false, message: error.message };
  }
}

let clusterConfigSyncTimer = null;

async function setupClusterSyncLoop() {
  if (clusterConfigSyncTimer) {
    clearInterval(clusterConfigSyncTimer);
    clusterConfigSyncTimer = null;
  }

  const config = await readConfigFile(DEFAULT_CONFIG_PATH);
  if (!config) {
    return;
  }

  const cluster = normalizeClusterConfig(config);
  if (!cluster.enabled || cluster.node_role !== 'secondary' || !cluster.sync.enabled) {
    return;
  }

  const intervalMs = Math.max(5000, cluster.sync.config_interval * 1000);
  clusterConfigSyncTimer = setInterval(async () => {
    const latest = await readConfigFile(DEFAULT_CONFIG_PATH);
    if (!latest) {
      return;
    }

    const result = await syncConfigFromPrimary(latest);
    if (result.attempted && !result.success) {
      console.error('[cluster-sync] 浠庝富鑺傜偣鍚屾閰嶇疆澶辫触:', result.message);
    }
  }, intervalMs);

  console.log(`[cluster-sync] 宸插惎鐢ㄤ粠涓昏妭鐐归厤缃悓姝ワ紝闂撮殧 ${intervalMs}ms`);
}

// 纭繚閰嶇疆鐩綍瀛樺湪
async function ensureDirectories() {
  try {
    await fs.mkdir(SITES_DIR, { recursive: true });
    await fs.mkdir(CERTS_DIR, { recursive: true });
    await fs.mkdir(NGINX_CONF_DIR, { recursive: true });
    console.log('Configuration directories are ready');
  } catch (error) {
    console.error('鍒涘缓閰嶇疆鐩綍澶辫触:', error);
    process.exit(1);
  }
}

// 璇诲彇閰嶇疆鏂囦欢
async function readConfigFile(filePath) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return null;
    }
    console.error(`璇诲彇閰嶇疆鏂囦欢澶辫触 ${filePath}:`, error);
    return null;
  }
}

// 鍐欏叆閰嶇疆鏂囦欢
async function writeConfigFile(filePath, data) {
  try {
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf8');
    return true;
  } catch (error) {
    console.error(`鍐欏叆閰嶇疆鏂囦欢澶辫触 ${filePath}:`, error);
    return false;
  }
}

async function readTextFileIfExists(filePath) {
  try {
    return await fs.readFile(filePath, 'utf8');
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

async function restoreTextFile(filePath, content) {
  if (typeof content === 'string') {
    await fs.writeFile(filePath, content, 'utf8');
    return;
  }

  try {
    await fs.unlink(filePath);
  } catch (error) {
    if (!error || error.code !== 'ENOENT') {
      throw error;
    }
  }
}

async function updateDefaultConfigWithReload(mutateConfig) {
  const currentConfig = await readConfigFile(DEFAULT_CONFIG_PATH) || {};
  const previousConfigRaw = await readTextFileIfExists(DEFAULT_CONFIG_PATH);
  const nextConfig = JSON.parse(JSON.stringify(currentConfig));
  const mutationResult = await mutateConfig(nextConfig, currentConfig);

  if (mutationResult && mutationResult.changed === false) {
    return {
      success: true,
      changed: false,
      config: nextConfig,
      message: mutationResult.message || 'No configuration changes were required',
      replication: {
        total: 0,
        success: 0,
        failed: 0,
        details: []
      }
    };
  }

  nextConfig.cluster = normalizeClusterConfig(nextConfig);
  const written = await writeConfigFile(DEFAULT_CONFIG_PATH, nextConfig);
  if (!written) {
    return {
      success: false,
      status: 500,
      message: 'Failed to save configuration file'
    };
  }

  let snapshotBundle;
  try {
    snapshotBundle = await compileAndPublishSnapshot();
  } catch (publishError) {
    try {
      await restoreTextFile(DEFAULT_CONFIG_PATH, previousConfigRaw);
    } catch (rollbackError) {
      console.error('[Snapshot] rollback default_config.json failed:', rollbackError.message || rollbackError);
    }

    return {
      success: false,
      status: 500,
      message: publishError.message || 'Snapshot publish failed',
      replication: {
        total: 0,
        success: 0,
        failed: 0,
        details: []
      }
    };
  }

  let replicationDetails = [];
  try {
    replicationDetails = await replicateConfigToSecondaries(nextConfig);
  } catch (replicationError) {
    console.error('[Cluster] config replication failed:', replicationError.message || replicationError);
    replicationDetails = [];
  }

  const replication = {
    total: replicationDetails.length,
    success: replicationDetails.filter((item) => item.success).length,
    failed: replicationDetails.filter((item) => !item.success).length,
    details: replicationDetails
  };

  return {
    success: true,
    changed: true,
    config: nextConfig,
    message: (mutationResult && mutationResult.message) || 'Configuration updated and published',
    snapshot: {
      version: snapshotBundle.version,
      compiled_at: snapshotBundle.compiled_at
    },
    replication
  };
}

function clampInteger(value, min, max, fallback) {
  const parsed = parseInt(value, 10);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, parsed));
}

function safeJsonParse(value, fallback = null) {
  if (typeof value !== 'string' || value === '') {
    return fallback;
  }

  try {
    return JSON.parse(value);
  } catch (_) {
    return fallback;
  }
}

function normalizeInspectionItem(item) {
  if (!item || typeof item !== 'object') {
    return null;
  }

  const timestamp = Number(item.timestamp || 0) || 0;
  const encodingLayers = Array.isArray(item.encoding_layers)
    ? item.encoding_layers.map((layer) => String(layer || '')).filter(Boolean)
    : [];

  return {
    request_id: String(item.request_id || ''),
    ip: String(item.ip || item.client_ip || ''),
    host: String(item.host || ''),
    method: String(item.method || 'GET'),
    uri: String(item.uri || ''),
    status: Number(item.status || 0) || 0,
    is_blocked: Boolean(item.is_blocked),
    trigger_reason: String(item.trigger_reason || item.reason || ''),
    source: String(item.source || 'unknown'),
    label: String(item.label || 'payload'),
    matched_signature: String(item.matched_signature || 'unknown'),
    score: Number(item.score || 0) || 0,
    body_preview: String(item.body_preview || ''),
    normalized_preview: String(item.normalized_preview || ''),
    encoding_layers: encodingLayers,
    encoding_layer_count: Number(item.encoding_layer_count || encodingLayers.length || 0) || 0,
    obfusc_score: Number(item.obfusc_score || 0) || 0,
    attack_class: String(item.attack_class || 'unknown'),
    confidence: Number(item.confidence || 0) || 0,
    sql_hits: Number(item.sql_hits || 0) || 0,
    xss_hits: Number(item.xss_hits || 0) || 0,
    timestamp
  };
}

function matchesInspectionFilters(item, filters) {
  if (!item) {
    return false;
  }

  if (filters.requestId && item.request_id !== filters.requestId) {
    return false;
  }

  if (filters.ip && item.ip !== filters.ip) {
    return false;
  }

  if (filters.attackClass && item.attack_class !== filters.attackClass) {
    return false;
  }

  if (filters.triggerReason && item.trigger_reason !== filters.triggerReason) {
    return false;
  }

  if (filters.uri && !item.uri.includes(filters.uri)) {
    return false;
  }

  return true;
}

async function readInspectionItems(limit) {
  const raw = await redis.lrange('inspection:events', 0, Math.max(0, limit - 1));
  return raw.map((entry) => normalizeInspectionItem(safeJsonParse(entry))).filter(Boolean);
}

function normalizeIpAddress(value) {
  const raw = String(value || '').trim().replace(/^\[/, '').replace(/\]$/, '');
  if (!raw) {
    return '';
  }

  return net.isIP(raw) ? raw.toLowerCase() : '';
}

function normalizeCidr(value) {
  const raw = String(value || '').trim().toLowerCase();
  const match = raw.match(/^(.+)\/(\d{1,3})$/);
  if (!match) {
    return '';
  }

  const ip = normalizeIpAddress(match[1]);
  if (!ip) {
    return '';
  }

  const family = net.isIP(ip);
  if (!family) {
    return '';
  }

  const prefix = Number(match[2]);
  const maxPrefix = family === 6 ? 128 : 32;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
    return '';
  }

  return `${ip}/${prefix}`;
}

function ipv4ToNumber(ip) {
  const parts = String(ip || '').split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return NaN;
  }

  return ((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3];
}

function normalizeIpRangeSpan(value) {
  const raw = String(value || '').trim().toLowerCase();
  const match = raw.match(/^([^-\s]+)\s*-\s*([^\s]+)$/);
  if (!match) {
    return null;
  }

  const startIp = normalizeIpAddress(match[1]);
  const endIp = normalizeIpAddress(match[2]);
  if (!startIp || !endIp || net.isIP(startIp) !== 4 || net.isIP(endIp) !== 4) {
    return null;
  }

  const startNum = ipv4ToNumber(startIp);
  const endNum = ipv4ToNumber(endIp);
  if (!Number.isFinite(startNum) || !Number.isFinite(endNum)) {
    return null;
  }

  const normalizedStartIp = startNum <= endNum ? startIp : endIp;
  const normalizedEndIp = startNum <= endNum ? endIp : startIp;
  const normalizedStartNum = Math.min(startNum, endNum);
  const normalizedEndNum = Math.max(startNum, endNum);

  return {
    type: 'range',
    value: `${normalizedStartIp}-${normalizedEndIp}`,
    identity: `range:${normalizedStartNum}-${normalizedEndNum}`,
    raw: {
      start: normalizedStartNum,
      end_num: normalizedEndNum,
      start_ip: normalizedStartIp,
      end_ip: normalizedEndIp
    }
  };
}

function normalizeIpRangeEntry(entry) {
  if (typeof entry === 'string') {
    const cidr = normalizeCidr(entry);
    if (cidr) {
      return {
        type: 'cidr',
        value: cidr,
        identity: `cidr:${cidr}`,
        raw: cidr
      };
    }

    const range = normalizeIpRangeSpan(entry);
    if (range) {
      return range;
    }

    return null;
  }

  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    return null;
  }

  const cidr = normalizeCidr(entry.cidr || entry.entry);
  if (cidr) {
    return {
      type: 'cidr',
      value: cidr,
      identity: `cidr:${cidr}`,
      raw: cidr
    };
  }

  if (typeof entry.entry === 'string') {
    const range = normalizeIpRangeSpan(entry.entry);
    if (range) {
      return range;
    }
  }

  const start = Number(entry.start_num ?? entry.start);
  const end = Number(entry.end_num ?? entry.finish ?? entry.end);
  const startIp = normalizeIpAddress(entry.start_ip);
  const endIp = normalizeIpAddress(entry.end_ip);
  const hasNumericRange = Number.isFinite(start) && Number.isFinite(end);
  const hasIpRange = Boolean(startIp && endIp);

  if (!hasNumericRange && !hasIpRange) {
    return null;
  }

  const normalizedStart = hasNumericRange ? Math.min(start, end) : start;
  const normalizedEnd = hasNumericRange ? Math.max(start, end) : end;
  const left = hasIpRange ? startIp : normalizedStart;
  const right = hasIpRange ? endIp : normalizedEnd;

  return {
    type: 'range',
    value: `${left}-${right}`,
    identity: `range:${left}-${right}`,
    raw: {
      ...(hasNumericRange ? { start: normalizedStart, end_num: normalizedEnd } : {}),
      ...(hasIpRange ? { start_ip: startIp, end_ip: endIp } : {})
    }
  };
}

function collectNormalizedIpRanges(entries) {
  const list = Array.isArray(entries) ? entries : [];
  const result = [];
  const seen = new Set();

  list.forEach((entry) => {
    const normalized = normalizeIpRangeEntry(entry);
    if (!normalized || seen.has(normalized.identity)) {
      return;
    }

    seen.add(normalized.identity);
    result.push(normalized);
  });

  return result;
}

function normalizeBlacklistEntry(value) {
  const ip = normalizeIpAddress(value);
  if (ip) {
    return { type: 'ip', value: ip };
  }

  const cidr = normalizeCidr(value);
  if (cidr) {
    return { type: 'cidr', value: cidr };
  }

  const range = normalizeIpRangeSpan(value);
  if (range) {
    return range;
  }

  return null;
}

async function scanRedisKeys(pattern, count = 200) {
  const keys = [];
  let cursor = '0';

  do {
    const result = await redis.scan(cursor, 'MATCH', pattern, 'COUNT', count);
    cursor = Array.isArray(result) ? String(result[0]) : '0';
    const batch = Array.isArray(result && result[1]) ? result[1] : [];
    keys.push(...batch);
  } while (cursor !== '0');

  return keys;
}

function parseZsetWithScores(items) {
  const result = [];
  if (!Array.isArray(items)) {
    return result;
  }

  for (let index = 0; index < items.length; index += 2) {
    const member = items[index];
    const rawScore = items[index + 1];
    if (typeof member !== 'string') {
      continue;
    }

    const score = Number(rawScore);
    result.push({
      name: member,
      score: Number.isFinite(score) ? score : 0
    });
  }

  return result;
}

async function readTopFromRedis(key, limit) {
  const data = await redis.zrevrange(key, 0, Math.max(0, limit - 1), 'WITHSCORES');
  return parseZsetWithScores(data);
}

async function fetchNginxInternalMetrics() {
  const url = process.env.NGINX_METRICS_URL || 'http://nginx:80/_metrics';
  try {
    const response = await axios.get(url, { timeout: 8000 });
    const payload = isObject(response.data) ? response.data : {};
    const data = isObject(payload.data) ? payload.data : {};
    return { success: payload.success === true, data };
  } catch (error) {
    return {
      success: false,
      error: isObject(error && error.response && error.response.data)
        ? error.response.data
        : { message: error.message || 'failed to fetch nginx metrics' }
    };
  }
}

apiRouter.post('/snapshot/publish', async (req, res) => {
  try {
    const bundle = await compileAndPublishSnapshot();
    return res.json({
      code: 0,
      data: {
        version: bundle.version,
        compiled_at: bundle.compiled_at
      }
    });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to publish snapshot');
  }
});

apiRouter.get('/snapshot/status', async (req, res) => {
  try {
    const status = await snapshotPublisher.getStatus(redis);
    return res.json({ code: 0, data: status });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to fetch snapshot status');
  }
});

// 璺敱: 鑾峰彇鍏ㄥ眬閰嶇疆
apiRouter.get('/config', async (req, res) => {
  try {
    const config = await readConfigFile(DEFAULT_CONFIG_PATH);
    if (!config) {
      return sendError(res, 404, 'Configuration file not found');
    }

    config.cluster = normalizeClusterConfig(config);
    config.anti_bypass = normalizeAntiBypassConfig(config);
    res.json({ success: true, data: config });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to fetch configuration');
  }
});

// 璺敱: 鏇存柊鍏ㄥ眬閰嶇疆
apiRouter.put('/config', async (req, res) => {
  try {
    // 楠岃瘉璇锋眰鏁版嵁
    if (!req.body || typeof req.body !== 'object') {
      return sendError(res, 400, 'Invalid configuration payload');
    }

    const mergedConfig = deepMerge(await readConfigFile(DEFAULT_CONFIG_PATH) || {}, req.body);
    mergedConfig.cluster = normalizeClusterConfig(mergedConfig);
    mergedConfig.anti_bypass = normalizeAntiBypassConfig(mergedConfig);
    delete mergedConfig.traffic_notifications;
    delete mergedConfig.traffic_packages;
    const previousConfigRaw = await readTextFileIfExists(DEFAULT_CONFIG_PATH);

    // 鏇存柊閰嶇疆鏂囦欢
    const saved = await writeConfigFile(DEFAULT_CONFIG_PATH, mergedConfig);
    if (!saved) {
      return sendError(res, 500, 'Failed to save configuration');
    }

    await setupClusterSyncLoop();

    let snapshotBundle;
    try {
      snapshotBundle = await compileAndPublishSnapshot();
    } catch (publishError) {
      await restoreTextFile(DEFAULT_CONFIG_PATH, previousConfigRaw);
      await setupClusterSyncLoop();
      return sendError(res, 500, publishError.message || 'Snapshot publish failed');
    }

    let replication = [];
    try {
      replication = await replicateConfigToSecondaries(mergedConfig);
    } catch (replicationError) {
      console.error('[Cluster] config replication failed:', replicationError.message || replicationError);
      replication = [];
    }

    const replicatedOk = replication.filter((item) => item.success).length;
    const replicatedFail = replication.length - replicatedOk;

    return res.json({
      success: true,
      message: 'Configuration updated and published',
      snapshot: {
        version: snapshotBundle.version,
        compiled_at: snapshotBundle.compiled_at
      },
      replication: {
        total: replication.length,
        success: replicatedOk,
        failed: replicatedFail,
        details: replication
      }
    });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to update configuration');
  }
});

// 璺敱: 鑾峰彇绔欑偣鍒楄〃
apiRouter.get('/sites', async (req, res) => {
  try {
    const files = await fs.readdir(SITES_DIR);
    const siteFiles = files.filter(file => file.endsWith('.json'));

    const sites = [];
    for (const file of siteFiles) {
      const siteConfig = await readConfigFile(path.join(SITES_DIR, file));
      if (siteConfig && siteConfig.domain) {
        const normalizedDomain = String(siteConfig.domain || '').toLowerCase();
        const normalizedSiteConfig = normalizeSiteConfig(siteConfig, normalizedDomain);
        const tlsConfig = normalizeSiteTlsConfig(normalizedSiteConfig, normalizedDomain);
        sites.push({
          domain: normalizedSiteConfig.domain,
          enabled: normalizedSiteConfig.enabled || false,
          backend_server: normalizedSiteConfig.backend_server || '',
          backend_port_follow: normalizedSiteConfig.backend_port_follow === true,
          tls_enabled: tlsConfig.enabled,
          filename: file
        });
      }
    }

    res.json({ success: true, data: sites });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to fetch sites list');
  }
});

// 路由: 证书文件上传（multipart/form-data）
apiRouter.post('/certificates/upload', (req, res) => {
  const uploadHandler = certUpload.fields([
    { name: 'cert_file', maxCount: 1 },
    { name: 'key_file', maxCount: 1 }
  ]);

  uploadHandler(req, res, async (uploadError) => {
    if (uploadError) {
      return sendError(res, 400, `Certificate upload failed: ${uploadError.message}`);
    }

    try {
      const certFile = req.files && req.files.cert_file && req.files.cert_file[0];
      const keyFile = req.files && req.files.key_file && req.files.key_file[0];
      const domain = normalizeCertificateDomain(req.body.domain);

      if (!certFile || !keyFile) {
        return sendError(res, 400, 'cert_file and key_file are required');
      }

      const certContent = ensurePemLikeContent(certFile.buffer.toString('utf8'), 'Certificate');
      const keyContent = ensurePemLikeContent(keyFile.buffer.toString('utf8'), 'Private key');
      const validation = validateCertificateBundle(certContent, keyContent, domain);

      const names = resolveCertFilenames(req.body || {}, domain);
      const certHostPath = path.join(CERTS_DIR, names.cert_file_name);
      const keyHostPath = path.join(CERTS_DIR, names.key_file_name);

      await fs.writeFile(certHostPath, certContent, 'utf8');
      await fs.writeFile(keyHostPath, keyContent, 'utf8');

      res.json({
        success: true,
        message: 'Certificate files uploaded and validated successfully',
        data: {
          cert_path: `${NGINX_CERT_DIR}/${names.cert_file_name}`,
          key_path: `${NGINX_CERT_DIR}/${names.key_file_name}`,
          cert_file_name: names.cert_file_name,
          key_file_name: names.key_file_name,
          validation
        }
      });
    } catch (error) {
      return sendError(res, 400, error.message || 'Failed to upload certificate files');
    }
  });
});

apiRouter.post('/certificates/content', async (req, res) => {
  try {
    const domain = normalizeCertificateDomain(req.body.domain);
    const names = resolveCertFilenames(req.body || {}, domain);
    const certContent = ensurePemLikeContent(req.body.cert_content, 'Certificate');
    const keyContent = ensurePemLikeContent(req.body.key_content, 'Private key');
    const validation = validateCertificateBundle(certContent, keyContent, domain);

    const certHostPath = path.join(CERTS_DIR, names.cert_file_name);
    const keyHostPath = path.join(CERTS_DIR, names.key_file_name);

    await fs.writeFile(certHostPath, certContent, 'utf8');
    await fs.writeFile(keyHostPath, keyContent, 'utf8');

    res.json({
      success: true,
      message: 'Certificate content uploaded and validated successfully',
      data: {
        cert_path: `${NGINX_CERT_DIR}/${names.cert_file_name}`,
        key_path: `${NGINX_CERT_DIR}/${names.key_file_name}`,
        cert_file_name: names.cert_file_name,
        key_file_name: names.key_file_name,
        validation
      }
    });
  } catch (error) {
    return sendError(res, 400, error.message || 'Invalid certificate content');
  }
});

apiRouter.get('/sites/:domain', async (req, res) => {
  try {
    const { domain } = req.params;
    const normalizedDomain = domain.toLowerCase();

    const sitePath = path.join(SITES_DIR, `${normalizedDomain}.json`);

    let siteConfig = await readConfigFile(sitePath);
    if (!siteConfig && normalizedDomain !== domain) {
      siteConfig = await readConfigFile(path.join(SITES_DIR, `${domain}.json`));
    }
    if (!siteConfig) {
      return sendError(res, 404, 'Site configuration not found');
    }

    const globalConfig = await readConfigFile(DEFAULT_CONFIG_PATH) || {};
    const antiBypassConfig = normalizeAntiBypassConfig(globalConfig);
    const normalizedSiteConfig = normalizeSiteConfig(siteConfig, normalizedDomain, antiBypassConfig);
    res.json({ success: true, data: normalizedSiteConfig });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to fetch site configuration');
  }
});

// 璺敱: 鍒涘缓鎴栨洿鏂扮珯鐐归厤缃?
apiRouter.put('/sites/:domain', async (req, res) => {
  try {
    const { domain } = req.params;
    const normalizedDomain = domain.toLowerCase();

    // 楠岃瘉璇锋眰鏁版嵁
    if (!req.body || !req.body.domain) {
      return sendError(res, 400, 'Invalid site configuration payload');
    }

    const normalizedBodyDomain = String(req.body.domain).toLowerCase();

    if (normalizedBodyDomain !== normalizedDomain) {
      return sendError(res, 400, 'URL 中的域名与配置数据不匹配');
    }

    let normalizedSiteConfig;
    try {
      const globalConfig = await readConfigFile(DEFAULT_CONFIG_PATH) || {};
      const antiBypassConfig = normalizeAntiBypassConfig(globalConfig);
      normalizedSiteConfig = normalizeSiteConfig(req.body, normalizedDomain, antiBypassConfig);
    } catch (normalizeError) {
      return sendError(res, 400, normalizeError.message);
    }

    try {
      await validateSiteTlsFiles(normalizedSiteConfig);
    } catch (tlsError) {
      return sendError(res, 400, tlsError.message);
    }
    
    // 鍐欏叆绔欑偣閰嶇疆鏂囦欢
    const sitePath = path.join(SITES_DIR, `${normalizedDomain}.json`);
    const nginxConfigPath = path.join(NGINX_CONF_DIR, `${normalizedDomain}.conf`);
    const previousSiteRaw = await readTextFileIfExists(sitePath);
    const previousNginxRaw = await readTextFileIfExists(nginxConfigPath);
    const success = await writeConfigFile(sitePath, normalizedSiteConfig);
    
    if (!success) {
      return sendError(res, 500, 'Failed to save site configuration');
    }
    
    // 鐢熸垚Nginx閰嶇疆
    try {
      await generateNginxConfig(normalizedDomain, normalizedSiteConfig);
    } catch (generateError) {
      await restoreTextFile(sitePath, previousSiteRaw);
      await restoreTextFile(nginxConfigPath, previousNginxRaw);
      return sendError(
        res,
        500,
        generateError && generateError.message
          ? `Failed to generate Nginx configuration (rolled back): ${generateError.message}`
          : 'Failed to generate Nginx configuration (rolled back)'
      );
    }

    // 清理可能存在的大小写不一致旧文件
    if (domain !== normalizedDomain) {
      try {
        await fs.unlink(path.join(SITES_DIR, `${domain}.json`));
      } catch (_) {
        // ignore
      }

      try {
        await fs.unlink(path.join(NGINX_CONF_DIR, `${domain}.conf`));
      } catch (_) {
        // ignore
      }
    }
    
    let snapshotBundle;
    try {
      snapshotBundle = await compileAndPublishSnapshot();
    } catch (publishError) {
      await restoreTextFile(sitePath, previousSiteRaw);
      await restoreTextFile(nginxConfigPath, previousNginxRaw);
      return sendError(res, 500, publishError.message || 'Snapshot publish failed');
    }

    return res.json({
      success: true,
      message: '站点配置已更新并已发布',
      snapshot: {
        version: snapshotBundle.version,
        compiled_at: snapshotBundle.compiled_at
      }
    });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to update site configuration');
  }
});

// 璺敱: 鍒犻櫎绔欑偣閰嶇疆
apiRouter.delete('/sites/:domain', async (req, res) => {
  try {
    const { domain } = req.params;
    const normalizedDomain = domain.toLowerCase();
    let sitePath = path.join(SITES_DIR, `${normalizedDomain}.json`);
    const nginxConfigPath = path.join(NGINX_CONF_DIR, `${normalizedDomain}.conf`);
    const legacyNginxConfigPath = domain !== normalizedDomain
      ? path.join(NGINX_CONF_DIR, `${domain}.conf`)
      : null;
    
    // 检查站点文件是否存在
    try {
      await fs.access(sitePath);
    } catch (error) {
      const legacySitePath = path.join(SITES_DIR, `${domain}.json`);
      try {
        await fs.access(legacySitePath);
        sitePath = legacySitePath;
      } catch (_) {
        return sendError(res, 404, 'Site configuration not found');
      }
    }

    const previousSiteRaw = await readTextFileIfExists(sitePath);
    const previousNginxRaw = await readTextFileIfExists(nginxConfigPath);
    const previousLegacyNginxRaw = legacyNginxConfigPath
      ? await readTextFileIfExists(legacyNginxConfigPath)
      : null;
    
    // 鍒犻櫎绔欑偣閰嶇疆鏂囦欢
    await fs.unlink(sitePath);
    
    // 鍒犻櫎Nginx閰嶇疆
    try {
      await fs.unlink(nginxConfigPath);
    } catch (error) {
      console.error(`鍒犻櫎Nginx閰嶇疆澶辫触 ${nginxConfigPath}:`, error);
    }

    if (legacyNginxConfigPath) {
      try {
        await fs.unlink(legacyNginxConfigPath);
      } catch (_) {
        // ignore
      }
    }
    
    let snapshotBundle;
    try {
      snapshotBundle = await compileAndPublishSnapshot();
    } catch (publishError) {
      await restoreTextFile(sitePath, previousSiteRaw);
      await restoreTextFile(nginxConfigPath, previousNginxRaw);
      if (legacyNginxConfigPath) {
        await restoreTextFile(legacyNginxConfigPath, previousLegacyNginxRaw);
      }
      return sendError(res, 500, publishError.message || 'Snapshot publish failed');
    }

    return res.json({
      success: true,
      message: 'Site configuration deleted and published',
      snapshot: {
        version: snapshotBundle.version,
        compiled_at: snapshotBundle.compiled_at
      }
    });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to delete site configuration');
  }
});

// 璺敱: 鑾峰彇IP榛戝悕鍗?
apiRouter.get('/blacklist', async (req, res) => {
  try {
    const prefix = 'safeline:blacklist:';
    const keys = await scanRedisKeys(`${prefix}*`, 500);
    const blacklist = [];

    if (keys.length > 0) {
      const pipeline = redis.pipeline();
      keys.forEach((key) => pipeline.ttl(key));
      const ttlResults = await pipeline.exec();

      keys.forEach((key, index) => {
        if (typeof key !== 'string' || !key.startsWith(prefix)) {
          return;
        }

        const ip = key.slice(prefix.length);
        if (!ip) {
          return;
        }

        const ttlResult = Array.isArray(ttlResults[index]) ? ttlResults[index][1] : -2;
        const ttl = Number(ttlResult);
        if (ttl === -2) {
          return;
        }

        blacklist.push({
          entry: ip,
          ip,
          type: 'ip',
          source: 'redis',
          expires_in: Number.isFinite(ttl) ? ttl : -2,
          permanent: ttl === -1
        });
      });
    }

    const config = await readConfigFile(DEFAULT_CONFIG_PATH);
    const configuredRanges = collectNormalizedIpRanges(config && config.ip_ranges);
    configuredRanges.forEach((entry) => {
      blacklist.push({
        entry: entry.value,
        type: entry.type,
        source: 'config',
        expires_in: -1,
        permanent: true,
        range: true,
        ...(entry.type === 'cidr' ? { cidr: entry.value } : {}),
        ...(entry.type === 'range' ? entry.raw : {})
      });
    });

    blacklist.sort((a, b) => {
      if (a.permanent !== b.permanent) {
        return a.permanent ? -1 : 1;
      }

      if (a.expires_in !== b.expires_in) {
        return a.expires_in - b.expires_in;
      }

      const left = String(a.entry || a.ip || '');
      const right = String(b.entry || b.ip || '');
      return left.localeCompare(right);
    });
    
    res.json({ success: true, data: blacklist });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to fetch IP blacklist');
  }
});

// 璺敱: 娣诲姞IP鍒伴粦鍚嶅崟
apiRouter.post('/blacklist', async (req, res) => {
  try {
    const entry = normalizeBlacklistEntry(req.body && (req.body.entry || req.body.ip));
    const rawDuration = req.body && req.body.duration;
    
    if (!entry) {
      return sendError(res, 400, 'IP address or CIDR is required');
    }

    const duration = rawDuration === -1 || rawDuration === '-1'
      ? -1
      : clampInteger(rawDuration, 60, 365 * 24 * 60 * 60, 86400);

    if (entry.type !== 'ip') {
      const label = entry.type === 'range' ? 'IP range' : 'CIDR';
      const configUpdate = await updateDefaultConfigWithReload((config) => {
        const ipRanges = collectNormalizedIpRanges(config.ip_ranges);
        if (ipRanges.some((item) => item.identity === entry.identity)) {
          return {
            changed: false,
            message: `${label} already exists in blacklist`
          };
        }

        config.ip_ranges = [
          ...ipRanges.map((item) => item.raw),
          entry.raw
        ];

        return {
          changed: true,
          message: `${label} added to blacklist`
        };
      });

      if (!configUpdate.success) {
        return sendError(res, configUpdate.status || 500, configUpdate.message || 'Failed to update configuration');
      }

      return res.json({
        success: true,
        message: configUpdate.message,
        entry: entry.value,
        type: entry.type,
        replication: configUpdate.replication,
        snapshot: configUpdate.snapshot || null
      });
    }

    // 娣诲姞鍒癛edis榛戝悕鍗?
    const key = `safeline:blacklist:${entry.value}`;
    const previousTtl = await redis.ttl(key);
    
    if (duration === -1) {
      await redis.set(key, 1);
    } else {
      // 涓存椂榛戝悕鍗?(榛樿24灏忔椂)
      const seconds = duration || 86400;
      await redis.setex(key, seconds, 1);
    }

    let snapshotBundle;
    try {
      snapshotBundle = await compileAndPublishSnapshot();
    } catch (publishError) {
      try {
        if (previousTtl === -2) {
          await redis.del(key);
        } else if (previousTtl === -1) {
          await redis.set(key, 1);
        } else if (Number.isFinite(previousTtl) && previousTtl > 0) {
          await redis.setex(key, Math.max(1, previousTtl), 1);
        }
      } catch (rollbackError) {
        console.error('[Snapshot] rollback redis blacklist key failed:', rollbackError.message || rollbackError);
      }

      return sendError(res, 500, publishError.message || 'Snapshot publish failed');
    }

    const config = await readConfigFile(DEFAULT_CONFIG_PATH);
    const replication = config
      ? await replicateBlacklistToSecondaries(config, { action: 'add', ip: entry.value, duration: duration === -1 ? -1 : (duration || 86400) })
      : [];
    
    return res.json({
      success: true,
      message: 'IP added to blacklist',
      entry: entry.value,
      type: 'ip',
      snapshot: {
        version: snapshotBundle.version,
        compiled_at: snapshotBundle.compiled_at
      },
      replication: {
        total: replication.length,
        success: replication.filter((item) => item.success).length,
        failed: replication.filter((item) => !item.success).length,
        details: replication
      }
    });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to add blacklist entry');
  }
});

async function handleBlacklistDelete(req, res, rawEntry) {
  const entry = normalizeBlacklistEntry(rawEntry || req.query.entry || req.query.ip);
  if (!entry) {
    return sendError(res, 400, 'Invalid blacklist entry');
  }

  if (entry.type !== 'ip') {
    const label = entry.type === 'range' ? 'IP range' : 'CIDR';
    const configUpdate = await updateDefaultConfigWithReload((config) => {
      const ipRanges = collectNormalizedIpRanges(config.ip_ranges);
      const filtered = ipRanges.filter((item) => item.identity !== entry.identity);

      if (filtered.length === ipRanges.length) {
        return {
          changed: false,
          message: `${label} was not present in blacklist`
        };
      }

      config.ip_ranges = filtered.map((item) => item.raw);
      return {
        changed: true,
        message: `${label} removed from blacklist`
      };
    });

    if (!configUpdate.success) {
      return sendError(res, configUpdate.status || 500, configUpdate.message || 'Failed to update configuration');
    }

    return res.json({
      success: true,
      message: configUpdate.message,
      entry: entry.value,
      type: entry.type,
      replication: configUpdate.replication,
      snapshot: configUpdate.snapshot || null
    });
  }

  const key = `safeline:blacklist:${entry.value}`;
  const previousTtl = await redis.ttl(key);
  await redis.del(key);

  let snapshotBundle;
  try {
    snapshotBundle = await compileAndPublishSnapshot();
  } catch (publishError) {
    try {
      if (previousTtl === -1) {
        await redis.set(key, 1);
      } else if (Number.isFinite(previousTtl) && previousTtl > 0) {
        await redis.setex(key, Math.max(1, previousTtl), 1);
      }
    } catch (rollbackError) {
      console.error('[Snapshot] rollback redis blacklist key failed:', rollbackError.message || rollbackError);
    }

    return sendError(res, 500, publishError.message || 'Snapshot publish failed');
  }

  const config = await readConfigFile(DEFAULT_CONFIG_PATH);
  const replication = config
    ? await replicateBlacklistToSecondaries(config, { action: 'remove', ip: entry.value })
    : [];

  return res.json({
    success: true,
    message: 'IP宸蹭粠榛戝悕鍗曚腑绉婚櫎',
    entry: entry.value,
    type: 'ip',
    snapshot: {
      version: snapshotBundle.version,
      compiled_at: snapshotBundle.compiled_at
    },
    replication: {
      total: replication.length,
      success: replication.filter((item) => item.success).length,
      failed: replication.filter((item) => !item.success).length,
      details: replication
    }
  });
}

apiRouter.delete('/blacklist', async (req, res) => {
  try {
    return await handleBlacklistDelete(req, res, req.query.entry || req.query.ip);
  } catch (error) {
    return res.status(500).json({ success: false, message: '浠庨粦鍚嶅崟涓Щ闄P澶辫触', error: error.message });
  }
});

// 璺敱: 浠庨粦鍚嶅崟涓Щ闄P
apiRouter.delete('/blacklist/:ip', async (req, res) => {
  try {
    return await handleBlacklistDelete(req, res, req.params.ip);
  } catch (error) {
    res.status(500).json({ success: false, message: '浠庨粦鍚嶅崟涓Щ闄P澶辫触', error: error.message });
  }
});

// 璺敱: 鑾峰彇缁熻鏁版嵁
apiRouter.get('/stats', async (req, res) => {
  try {
    const stats = {
      total_requests: parseInt(await redis.get('safeline:stats:total_requests') || '0', 10),
      blocked_requests: parseInt(await redis.get('safeline:stats:blocked_requests') || '0', 10),
      sites: {}
    };

    const topSites = await readTopFromRedis('safeline:metrics:top:sites', 200);
    if (topSites.length > 0) {
      topSites.forEach((item) => {
        stats.sites[item.name] = item.score;
      });
    } else {
      // 兼容旧版统计结构
      const prefix = 'safeline:stats:site:';
      const siteKeys = await scanRedisKeys(`${prefix}*`, 500);
      if (siteKeys.length > 0) {
        const pipeline = redis.pipeline();
        siteKeys.forEach((key) => pipeline.get(key));
        const values = await pipeline.exec();

        siteKeys.forEach((key, index) => {
          if (typeof key !== 'string' || !key.startsWith(prefix)) {
            return;
          }

          const domain = key.slice(prefix.length);
          if (!domain) {
            return;
          }

          const value = Array.isArray(values[index]) ? values[index][1] : '0';
          stats.sites[domain] = parseInt(value || '0', 10) || 0;
        });
      }
    }

    res.json({ success: true, data: stats });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to fetch statistics');
  }
});

apiRouter.get('/logs', async (req, res) => {
  try {
    const limit = clampInteger(req.query.limit, 1, 500, 100);

    // 浠嶳edis鑾峰彇鏈€杩戠殑鏃ュ織
    const logs = await redis.lrange('safeline:logs', 0, limit - 1);
    const parsedLogs = logs.map((log) => safeJsonParse(log)).filter(Boolean);

    res.json({ success: true, data: parsedLogs });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to fetch logs');
  }
});

apiRouter.get('/inspection/stats', async (req, res) => {
  try {
    const items = await readInspectionItems(500);
    const attackClasses = {};
    let highObfuscationCount = 0;
    let latestTimestamp = 0;

    items.forEach((item) => {
      const attackClass = item.attack_class || 'unknown';
      attackClasses[attackClass] = (attackClasses[attackClass] || 0) + 1;
      if ((item.obfusc_score || 0) >= 6) {
        highObfuscationCount += 1;
      }
      if ((item.timestamp || 0) > latestTimestamp) {
        latestTimestamp = item.timestamp || 0;
      }
    });

    res.json({
      success: true,
      data: {
        total: items.length,
        high_obfuscation_count: highObfuscationCount,
        latest_timestamp: latestTimestamp,
        attack_classes: attackClasses
      }
    });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to fetch inspection stats');
  }
});

apiRouter.get('/inspection/events', async (req, res) => {
  try {
    const limit = clampInteger(req.query.limit, 1, 200, 50);
    const offset = clampInteger(req.query.offset, 0, 5000, 0);
    const filters = {
      requestId: String(req.query.request_id || '').trim(),
      ip: String(req.query.ip || '').trim(),
      uri: String(req.query.uri || '').trim(),
      triggerReason: String(req.query.trigger_reason || '').trim(),
      attackClass: String(req.query.attack_class || '').trim()
    };

    const scanLimit = Math.min(Math.max(offset + limit + 200, 200), 1000);
    const items = await readInspectionItems(scanLimit);
    const filtered = items.filter((item) => matchesInspectionFilters(item, filters));
    const paginated = filtered.slice(offset, offset + limit);

    res.json({
      success: true,
      data: {
        items: paginated,
        total: filtered.length,
        limit,
        offset
      }
    });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to fetch inspection events');
  }
});

apiRouter.get('/inspection/events/:requestId', async (req, res) => {
  try {
    const requestId = String(req.params.requestId || '').trim();
    if (!requestId) {
      return sendError(res, 400, 'requestId is required');
    }

    const raw = await redis.get(`inspection:event:${requestId}`);
    const item = normalizeInspectionItem(safeJsonParse(raw));
    if (!item) {
      return sendError(res, 404, 'Inspection event not found');
    }

    return res.json({ success: true, data: item });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to fetch inspection event');
  }
});

apiRouter.get('/monitor/attack-status', async (req, res) => {
  try {
    const limit = clampInteger(req.query.limit, 1, 50, 20);
    const now = Date.now();

    const [
      telemetry,
      shieldStateRaw,
      historyRaw,
      topSites,
      topUris,
      topBlockReasons,
      logsRaw,
      previousStateRaw,
      cfConfigRaw
    ] = await Promise.all([
      readAttackTelemetry(redis),
      redis.get('cf:state'),
      redis.lrange('cf:history', 0, Math.max(0, limit - 1)),
      readTopFromRedis('safeline:metrics:top:sites', limit),
      readTopFromRedis('safeline:metrics:top:uris', limit),
      readTopFromRedis('safeline:metrics:top:block_reasons', limit),
      redis.lrange('safeline:logs', 0, Math.max(0, limit - 1)),
      redis.get('monitor:attack_status:last'),
      redis.get('cf:config')
    ]);

    const shieldState = safeJsonParse(shieldStateRaw) || { active: false };
    const historyItems = parseJsonLines(historyRaw);
    const logs = parseJsonLines(logsRaw);
    const cfConfig = safeJsonParse(cfConfigRaw) || {};
    const currentState = summarizeAttackStatus({
      telemetry,
      shieldState,
      topSites,
      topUris,
      topBlockReasons,
      logs,
      historyItems,
      activateThreshold: Number(cfConfig.activate_threshold || 50),
      now
    });
    const previousState = safeJsonParse(previousStateRaw);
    const payload = buildAttackStatusPayload(currentState, previousState);

    await redis.set('monitor:attack_status:last', JSON.stringify(currentState));

    return res.json({
      success: true,
      data: payload
    });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to fetch attack status');
  }
});

apiRouter.get('/monitor/overview', async (req, res) => {
  try {
    const limit = clampInteger(req.query.limit, 5, 100, 20);

    const [
      nginxMetrics,
      topSites,
      topIps,
      topUris,
      topBlockReasons,
      logsRaw,
      redisTotalRaw,
      redisBlockedRaw
    ] = await Promise.all([
      fetchNginxInternalMetrics(),
      readTopFromRedis('safeline:metrics:top:sites', limit),
      readTopFromRedis('safeline:metrics:top:ips', limit),
      readTopFromRedis('safeline:metrics:top:uris', limit),
      readTopFromRedis('safeline:metrics:top:block_reasons', limit),
      redis.lrange('safeline:logs', 0, limit - 1),
      redis.get('safeline:stats:total_requests'),
      redis.get('safeline:stats:blocked_requests')
    ]);

    const parsedLogs = (logsRaw || []).map((line) => {
      try {
        return JSON.parse(line);
      } catch (_) {
        return null;
      }
    }).filter(Boolean);

    const redisTotals = {
      total_requests: parseInt(redisTotalRaw || '0', 10) || 0,
      blocked_requests: parseInt(redisBlockedRaw || '0', 10) || 0
    };

    const metricsData = nginxMetrics.success ? nginxMetrics.data : {};
    const totalRequests = Number(metricsData.total_requests);
    const blockedRequests = Number(metricsData.blocked_requests);
    const totals = {
      total_requests: Number.isFinite(totalRequests) ? totalRequests : redisTotals.total_requests,
      blocked_requests: Number.isFinite(blockedRequests) ? blockedRequests : redisTotals.blocked_requests
    };
    totals.allowed_requests = Math.max(0, totals.total_requests - totals.blocked_requests);
    totals.block_rate = totals.total_requests > 0 ? (totals.blocked_requests / totals.total_requests) : 0;

    res.json({
      success: true,
      data: {
        timestamp: Date.now(),
        totals,
        trend: Array.isArray(metricsData.trend) ? metricsData.trend : [],
        sites: isObject(metricsData.sites) ? metricsData.sites : {},
        block_reasons: isObject(metricsData.block_reasons) ? metricsData.block_reasons : {},
        top: {
          sites: topSites,
          ips: topIps,
          uris: topUris,
          block_reasons: topBlockReasons
        },
        recent_logs: parsedLogs,
        source: {
          nginx_metrics_ok: nginxMetrics.success,
          nginx_metrics_error: nginxMetrics.success ? null : nginxMetrics.error
        },
        system: {
          backend_uptime_seconds: Math.floor(process.uptime()),
          backend_pid: process.pid,
          backend_memory_mb: Math.round((process.memoryUsage().rss / (1024 * 1024)) * 100) / 100,
          backend_loadavg: os.loadavg(),
          backend_hostname: os.hostname()
        }
      }
    });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to fetch monitor overview');
  }
});

apiRouter.get('/monitor/health', async (req, res) => {
  try {
    const redisStart = Date.now();
    let redisOk = false;
    let redisError = null;
    try {
      const pong = await redis.ping();
      redisOk = pong === 'PONG';
      if (!redisOk) {
        redisError = `unexpected redis ping response: ${pong}`;
      }
    } catch (error) {
      redisError = error.message || 'redis ping failed';
    }
    const redisLatencyMs = Date.now() - redisStart;

    const nginxStart = Date.now();
    const nginxMetrics = await fetchNginxInternalMetrics();
    const nginxLatencyMs = Date.now() - nginxStart;

    const healthy = redisOk && nginxMetrics.success;
    res.status(healthy ? 200 : 503).json({
      success: healthy,
      data: {
        healthy,
        timestamp: Date.now(),
        redis: {
          ok: redisOk,
          latency_ms: redisLatencyMs,
          error: redisError
        },
        nginx: {
          ok: nginxMetrics.success,
          latency_ms: nginxLatencyMs,
          error: nginxMetrics.success ? null : nginxMetrics.error
        }
      }
    });
  } catch (error) {
    return sendError(res, 500, error.message || 'Health check failed');
  }
});

// 璺敱: 闆嗙兢鑺傜偣鑷韩淇℃伅
apiRouter.get('/cluster/node', async (req, res) => {
  try {
    const config = await readConfigFile(DEFAULT_CONFIG_PATH);
    if (!config) {
      return sendError(res, 404, 'Configuration file not found');
    }

    const node = getCurrentNode(config);
    const version = getConfigVersionInfo(config);
    res.json({ success: true, data: { ...node, config_version: version } });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to fetch cluster node info');
  }
});

// 璺敱: 闆嗙兢鐘舵€佹€昏
apiRouter.get('/cluster/status', async (req, res) => {
  try {
    const config = await readConfigFile(DEFAULT_CONFIG_PATH);
    if (!config) {
      return sendError(res, 404, 'Configuration file not found');
    }

    const cluster = normalizeClusterConfig(config);
    const current = getCurrentNode(config);
    const timeoutMs = cluster.sync.request_timeout_ms;

    const statuses = [];
    for (const node of cluster.nodes) {
      if (node.id === cluster.node_id) {
        statuses.push({
          id: node.id,
          name: node.name,
          role: node.role,
          enabled: node.enabled,
          sync: node.sync,
          healthy: true,
          message: 'local'
        });
      } else {
        statuses.push(await fetchNodeStatus(node, timeoutMs));
      }
    }

    res.json({
      success: true,
      data: {
        enabled: cluster.enabled,
        current,
        nodes: statuses
      }
    });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to fetch cluster status');
  }
});

// 路由: 手动触发主->从配置同步
apiRouter.post('/cluster/sync', async (req, res) => {
  try {
    const config = await readConfigFile(DEFAULT_CONFIG_PATH);
    if (!config) {
      return sendError(res, 404, 'Configuration file not found');
    }

    const current = getCurrentNode(config);
    if (current.role !== 'primary') {
      return sendError(res, 403, 'Only primary nodes can trigger config sync');
    }

    const replication = await replicateConfigToSecondaries(config, {
      timeoutMs: normalizeClusterConfig(config).sync.request_timeout_ms
    });

    res.json({
      success: true,
      data: {
        total: replication.length,
        success: replication.filter((item) => item.success).length,
        failed: replication.filter((item) => !item.success).length,
        details: replication
      }
    });
  } catch (error) {
    return sendError(res, 500, error.message || 'Manual sync failed');
  }
});

// 璺敱: 浠庝富鑺傜偣鎺ユ敹閰嶇疆鍚屾
apiRouter.post('/cluster/sync/config', async (req, res) => {
  try {
    const payload = req.body;
    if (!payload || !isObject(payload.config)) {
      return sendError(res, 400, 'Invalid sync payload');
    }

    const localConfig = await readConfigFile(DEFAULT_CONFIG_PATH) || {};
    const cluster = normalizeClusterConfig(localConfig);
    const localNode = getCurrentNode(localConfig);
    if (localNode.role !== 'secondary') {
      return sendError(res, 403, 'Only secondary nodes can receive config sync');
    }

    if (cluster.sync.enabled && payload.source && payload.source.ts) {
      const maxSkew = Math.max(10, parseInt(cluster.sync.max_skew_seconds || 60, 10));
      const skewSeconds = Math.abs(Date.now() - Number(payload.source.ts || 0)) / 1000;
      if (skewSeconds > maxSkew) {
        return res.status(400).json({ success: false, message: '鍚屾璇锋眰宸茶繃鏈熸垨鏃堕棿鍋忓樊杩囧ぇ' });
      }
    }

    if (cluster.sync.enabled && payload.source && payload.source.node_id) {
      const knownPrimary = (cluster.nodes || []).find((node) => node.role === 'primary');
      if (knownPrimary && knownPrimary.id && knownPrimary.id !== payload.source.node_id) {
        return res.status(403).json({ success: false, message: '鍚屾鏉ユ簮鑺傜偣涓嶅尮閰嶄富鑺傜偣' });
      }
    }

    const skip = await shouldSkipIncomingConfigSync(payload.version);
    if (skip) {
      return res.json({ success: true, message: '閰嶇疆鐗堟湰涓€鑷达紝璺宠繃鍚屾', skipped: true });
    }

    const result = await applyIncomingClusterConfig(payload.config, localConfig);
    if (!result.success) {
      return res.status(500).json({
        success: false,
        message: result.message,
        reload: result.reload || null,
        rollback: result.rollback || null
      });
    }

    res.json({ success: true, message: '閰嶇疆鍚屾鎴愬姛' });
  } catch (error) {
    res.status(500).json({ success: false, message: '閰嶇疆鍚屾澶辫触', error: error.message });
  }
});

// 路由: 从主节点接收黑名单同步
apiRouter.post('/cluster/sync/blacklist', async (req, res) => {
  try {
    const { action, duration, source } = req.body || {};
    const ip = normalizeIpAddress(req.body && req.body.ip);
    if (!ip || !['add', 'remove'].includes(action)) {
      return res.status(400).json({ success: false, message: 'Invalid blacklist sync payload' });
    }

    const localConfig = await readConfigFile(DEFAULT_CONFIG_PATH) || {};
    const cluster = normalizeClusterConfig(localConfig);
    const localNode = getCurrentNode(localConfig);
    if (localNode.role !== 'secondary') {
      return res.status(403).json({ success: false, message: 'Only secondary nodes can receive blacklist sync' });
    }

    if (cluster.sync.enabled && source && source.ts) {
      const maxSkew = Math.max(10, parseInt(cluster.sync.max_skew_seconds || 60, 10));
      const skewSeconds = Math.abs(Date.now() - Number(source.ts || 0)) / 1000;
      if (skewSeconds > maxSkew) {
        return res.status(400).json({ success: false, message: '鍚屾璇锋眰宸茶繃鏈熸垨鏃堕棿鍋忓樊杩囧ぇ' });
      }
    }

    if (cluster.sync.enabled && source && source.node_id) {
      const knownPrimary = (cluster.nodes || []).find((node) => node.role === 'primary');
      if (knownPrimary && knownPrimary.id && knownPrimary.id !== source.node_id) {
        return res.status(403).json({ success: false, message: '鍚屾鏉ユ簮鑺傜偣涓嶅尮閰嶄富鑺傜偣' });
      }
    }

    const key = `safeline:blacklist:${ip}`;
    if (action === 'add') {
      if (duration === -1) {
        await redis.set(key, 1);
      } else {
        const seconds = Math.max(1, parseInt(duration || 86400, 10));
        await redis.setex(key, seconds, 1);
      }
    } else {
      await redis.del(key);
    }

    res.json({ success: true, message: 'Blacklist sync successful' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Blacklist sync failed', error: error.message });
  }
});

// ============ New Redis-based Cluster Management APIs ============

// Rate limiter for cluster API
const clusterApiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false
});

// Get all cluster nodes
apiRouter.get('/cluster/nodes', async (req, res) => {
  try {
    const status = await clusterManager.getClusterStatus();
    res.json({ success: true, data: status });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to fetch cluster nodes');
  }
});

// Register a new node (requires cluster token)
app.post('/api/cluster/register', clusterAuthMiddleware, clusterApiLimiter, async (req, res) => {
  try {
    const { node_id, metadata } = req.body;
    if (!node_id) {
      return sendError(res, 400, 'Missing node_id');
    }

    const nodeData = await clusterManager.registerNode(node_id, metadata || {});
    res.json({ success: true, data: nodeData });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to register node');
  }
});

// Update node heartbeat (requires cluster token)
app.post('/api/cluster/heartbeat', clusterAuthMiddleware, clusterApiLimiter, async (req, res) => {
  try {
    const { node_id } = req.body;
    const success = await clusterManager.updateHeartbeat(node_id);

    if (success) {
      res.json({ success: true, message: 'Heartbeat updated' });
    } else {
      return sendError(res, 500, 'Failed to update heartbeat');
    }
  } catch (error) {
    return sendError(res, 500, error.message || 'Heartbeat update failed');
  }
});

// Broadcast config reload to all nodes (requires admin JWT)
apiRouter.post('/cluster/config/reload', async (req, res) => {
  try {
    const result = await clusterManager.broadcastConfigReload();
    res.json({ success: true, data: result });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to broadcast config reload');
  }
});

// Get cluster statistics
apiRouter.get('/cluster/stats', async (req, res) => {
  try {
    const stats = await clusterManager.getClusterStats();
    res.json({ success: true, data: stats });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to fetch cluster stats');
  }
});

// Remove a node from cluster
apiRouter.delete('/cluster/nodes/:nodeId', async (req, res) => {
  try {
    const { nodeId } = req.params;
    if (!nodeId) {
      return sendError(res, 400, 'Missing nodeId');
    }

    await clusterManager.removeNode(nodeId);
    res.json({ success: true, message: 'Node removed' });
  } catch (error) {
    return sendError(res, 500, error.message || 'Failed to remove node');
  }
});

// 路由: 多核心运行建议
apiRouter.get('/runtime/profile', async (req, res) => {
  try {
    const config = await readConfigFile(DEFAULT_CONFIG_PATH);
    if (!config) {
      return res.status(404).json({ success: false, message: 'Configuration file not found' });
    }

    res.json({ success: true, data: getRuntimeProfile(config) });
  } catch (error) {
    res.status(500).json({ success: false, message: '鑾峰彇杩愯閰嶇疆寤鸿澶辫触', error: error.message });
  }
});

// 鐢熸垚Nginx閰嶇疆鏂囦欢
async function generateNginxConfig(domain, siteConfig) {
  const isValidDomain = /^[a-zA-Z0-9.-]{1,255}$/.test(domain);
  if (!isValidDomain) {
    throw new Error('Invalid domain format');
  }

  const normalizedSiteConfig = normalizeSiteConfig(siteConfig, domain);
  const configPath = path.join(NGINX_CONF_DIR, `${domain}.conf`);

  await validateSiteTlsFiles(normalizedSiteConfig);

  if (!normalizedSiteConfig.enabled) {
    // 禁用站点时删除对应 Nginx 配置，避免残留生效
    try {
      await fs.unlink(configPath);
    } catch (_) {
      // ignore
    }
    return;
  }

  const backendProxyConfig = buildBackendProxyConfig(
    normalizedSiteConfig.backend_server,
    normalizedSiteConfig.backend_port_follow
  );
  const proxyPassTarget = backendProxyConfig.portFollow
    ? backendProxyConfig.followProxyPass
    : backendProxyConfig.fixedProxyPass;
  const proxySslDirectives = backendProxyConfig.usesHttps
    ? `        proxy_ssl_server_name on;
        proxy_ssl_name ${backendProxyConfig.serverName};
`
    : '';
  const proxyPortFollowDirective = backendProxyConfig.portFollow
    ? '        proxy_set_header X-Safeline-Upstream-Port $server_port;\n'
    : '';
  
  // 閰嶇疆妯℃澘
  let configTemplate = `
server {
    listen 80;
    server_name ${domain};

    # 鍩虹闄愭祦/闄愯繛锛堝彲鎸変笟鍔¤皟鏁达紱鐢ㄤ簬鎶靛尽 storm/杩炴帴椋庢毚/鐖嗗彂鎬ц姹傦級
    limit_conn safeline_conn_per_ip 50;
    limit_req zone=safeline_req_per_ip burst=200 nodelay;

    # HTTPS/HTTP2/HTTP3(QUIC) 閰嶇疆绀轰緥锛堥粯璁や笉鍚敤锛岄伩鍏嶅綋鍓嶉暅鍍忎笉鏀寔瀵艰嚧鍚姩澶辫触锛?    # listen 443 ssl http2;
    # ssl_certificate /usr/local/openresty/nginx/certs/${domain}.crt;
    # ssl_certificate_key /usr/local/openresty/nginx/certs/${domain}.key;
    #
    # 闃插尽HTTP/2鏀诲嚮锛堝 Rapid Reset / 澶撮儴鐐稿脊 / 杩囬珮骞跺彂娴侊級锛?    # - 闇€浼樺厛纭繚Nginx/OpenResty鐗堟湰宸插寘鍚拡瀵?CVE-2023-44487 鐨勪慨澶?    # - 鍐嶉€氳繃骞跺彂娴併€佸ご閮ㄥぇ灏忎笌瓒呮椂鏀剁揣璧勬簮涓婇檺锛堜笉鍚岀増鏈寚浠ゆ敮鎸佹儏鍐典笉鍚岋紝鎸夊疄闄呰皟鏁达級
    # http2_max_concurrent_streams 128;
    # http2_max_header_size 32k;
    # http2_max_field_size 16k;
    # http2_recv_timeout 10s;
    # http2_idle_timeout 30s;
    #
    # HTTP/3(QUIC) 闇€瑕丯ginx/OpenResty缂栬瘧鍚敤 http_v3/quic锛?    # listen 443 quic reuseport;
    # add_header Alt-Svc 'h3=":443"; ma=86400'; always;
    # add_header QUIC-Status $quic; always;
    
    # 闈欐€佽祫婧愮洰褰?    location /safeline-static/ {
        alias /usr/local/openresty/nginx/lua/static/;
        expires 30d;
    }
    
  # 楠岃瘉API
  location /safeline-api/ {
        content_by_lua_block {
            require("captcha").handle()
        }
  }

    location = /pow {
        default_type text/html;
        content_by_lua_block {
            local pow = require "pow"
            ngx.header.content_type = "text/html; charset=utf-8"
            ngx.say(pow.get_pow_script())
        }
    }

    location /pow/ {
        content_by_lua_block {
            require("captcha").handle()
        }
    }
    
    # WAF澶勭悊閫昏緫
    access_by_lua_file /usr/local/openresty/nginx/lua/access.lua;
    header_filter_by_lua_file /usr/local/openresty/nginx/lua/header_filter.lua;
    body_filter_by_lua_file /usr/local/openresty/nginx/lua/body_filter.lua;
    
    # 鍙嶅悜浠ｇ悊璁剧疆
    location / {
        proxy_pass ${proxyPassTarget};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Port $server_port;
${proxyPortFollowDirective}${proxySslDirectives}

        # WebSocket鏀寔
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 3600;
        proxy_send_timeout 3600;
    }
}
  `;

  const tlsConfig = normalizeSiteTlsConfig(normalizedSiteConfig, domain);
  if (tlsConfig.enabled) {
    const sharedDirectives = `
    limit_conn safeline_conn_per_ip 50;
    limit_req zone=safeline_req_per_ip burst=200 nodelay;

    location /safeline-static/ {
        alias /usr/local/openresty/nginx/lua/static/;
        expires 30d;
    }

    location /safeline-api/ {
        content_by_lua_block {
            require("captcha").handle()
        }
    }

    location = /pow {
        default_type text/html;
        content_by_lua_block {
            local pow = require "pow"
            ngx.header.content_type = "text/html; charset=utf-8"
            ngx.say(pow.get_pow_script())
        }
    }

    location /pow/ {
        content_by_lua_block {
            require("captcha").handle()
        }
    }

    access_by_lua_file /usr/local/openresty/nginx/lua/access.lua;
    header_filter_by_lua_file /usr/local/openresty/nginx/lua/header_filter.lua;
    body_filter_by_lua_file /usr/local/openresty/nginx/lua/body_filter.lua;

    location / {
        proxy_pass ${proxyPassTarget};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Port $server_port;
${proxyPortFollowDirective}${proxySslDirectives}
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 3600;
        proxy_send_timeout 3600;
    }`;

    const httpsListenDirective = 'listen 443 ssl;';
    const httpsHttp2Directive = tlsConfig.http2_enabled ? '\n    http2 on;' : '';
    const httpBlock = tlsConfig.redirect_http_to_https
      ? `
server {
    listen 80;
    server_name ${domain};
    return 301 https://$host$request_uri;
}`
      : `
server {
    listen 80;
    server_name ${domain};
${sharedDirectives}
}`;

    const httpsBlock = `
server {
    ${httpsListenDirective}
${httpsHttp2Directive}
    server_name ${domain};
    ssl_certificate ${tlsConfig.cert_path};
    ssl_certificate_key ${tlsConfig.key_path};
${sharedDirectives}
}`;

    configTemplate = `${httpBlock}\n${httpsBlock}`;
  }

  await fs.writeFile(configPath, configTemplate, 'utf8');
}

// ── ML Management Routes ──────────────────────────────────────────────────
const mountMlRoutes = require('./ml_routes');
mountMlRoutes(apiRouter, redis, clusterManager);

// ── LLM Audit Routes ───────────────────────────────────────────────────────
const mountLlmRoutes = require('./llm_routes');
mountLlmRoutes(apiRouter, redis, JWT_SECRET);

// ── Cloudflare Shield Routes ───────────────────────────────────────────────
const mountCfRoutes = require('./cf_routes');
mountCfRoutes(apiRouter, redis, JWT_SECRET);

// ── Attack Map Routes ────────────────────────────────────────────────────────
const mountMapRoutes = require('./map_routes');
mountMapRoutes(apiRouter, redis);

// Final error handler (must be after routes)
app.use((err, req, res, next) => {
  console.error('[API] Unhandled error:', err && err.stack ? err.stack : err);
  if (res.headersSent) {
    return next(err);
  }
  return sendError(res, 500, (err && err.message) || 'Internal server error');
});

// 鍚姩搴旂敤
async function start() {
  await ensureDirectories();

  // Initialize cluster manager if enabled
  if (process.env.CLUSTER_ENABLED !== 'false') {
    try {
      await clusterManager.initialize();
      heartbeatWorker.start();
      console.log('[Cluster] Cluster management initialized');
    } catch (error) {
      console.error('[Cluster] Failed to initialize cluster manager:', error.message);
      console.log('[Cluster] Continuing without cluster features');
    }
  }

  await setupClusterSyncLoop();

  // Start LLM audit worker (polls Redis queue every 1.5s)
  const { LLMWorker } = require('./llm_worker');
  const llmWorker = new LLMWorker(redis, JWT_SECRET);
  llmWorker.start();

  // Start CF shield worker (polls Redis attack score every 15s)
  const cfWorker = new CfShieldWorker(redis, JWT_SECRET);
  cfWorker.start();

  app.listen(PORT, () => {
    console.log(`SafeLine WAF 绠＄悊鍚庣姝ｅ湪杩愯锛岀鍙? ${PORT}`);
  });
}

start().catch(error => {
  console.error('搴旂敤鍚姩澶辫触:', error);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('[App] SIGTERM received, shutting down gracefully');
  if (clusterManager) {
    await clusterManager.shutdown();
  }
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('[App] SIGINT received, shutting down gracefully');
  if (clusterManager) {
    await clusterManager.shutdown();
  }
  process.exit(0);
});
