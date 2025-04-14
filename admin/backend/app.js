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

// Redis客户端
const redis = new Redis({
  host: process.env.REDIS_HOST || 'redis',
  port: 6379
});

// 创建Express应用
const app = express();
const PORT = process.env.PORT || 3000;

// 中间件
app.use(helmet()); // 安全HTTP头
app.use(compression()); // 压缩响应
app.use(morgan('combined')); // 日志
app.use(bodyParser.json({ limit: '1mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

// 跨域配置
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:8080',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// 登录API (不需要验证)
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  if (username === 'admin' && password === 'safeline123') {
    res.json({ 
      success: true, 
      message: '登录成功',
      user: { username: 'admin', role: 'administrator' }
    });
  } else {
    res.status(401).json({ success: false, message: '用户名或密码不正确' });
  }
});

// 简单的认证中间件
const authMiddleware = (req, res, next) => {
  // 跳过OPTIONS请求的认证（CORS预检）
  if (req.method === 'OPTIONS') {
    return next();
  }

  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return res.status(401).json({ success: false, message: '未授权访问' });
  }
  
  const credentials = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
  const username = credentials[0];
  const password = credentials[1];
  
  // 演示用途 - 硬编码认证
  if (username === 'admin' && password === 'safeline123') {
    next();
  } else {
    res.status(401).json({ success: false, message: '认证失败' });
  }
};

// 保护API路由
app.use('/api', authMiddleware);

// 修改为单独的API路由前缀
const apiRouter = express.Router();
app.use('/api', apiRouter);

// 配置目录
const CONFIG_DIR = process.env.CONFIG_DIR || '/app/config';
const SITES_DIR = path.join(CONFIG_DIR, 'sites');
const DEFAULT_CONFIG_PATH = path.join(CONFIG_DIR, 'default_config.json');

// 确保配置目录存在
async function ensureDirectories() {
  try {
    await fs.mkdir(SITES_DIR, { recursive: true });
    console.log('配置目录已确认存在');
  } catch (error) {
    console.error('创建配置目录失败:', error);
    process.exit(1);
  }
}

// 读取配置文件
async function readConfigFile(filePath) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error(`读取配置文件失败 ${filePath}:`, error);
    return null;
  }
}

// 写入配置文件
async function writeConfigFile(filePath, data) {
  try {
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf8');
    return true;
  } catch (error) {
    console.error(`写入配置文件失败 ${filePath}:`, error);
    return false;
  }
}

// 重新加载Nginx配置
async function reloadNginx() {
  try {
    const response = await axios.get(process.env.NGINX_RELOAD_URL || 'http://nginx:80/_reload');
    return response.data.success;
  } catch (error) {
    console.error('重新加载Nginx配置失败:', error);
    return false;
  }
}

// 路由: 获取全局配置
apiRouter.get('/config', async (req, res) => {
  try {
    const config = await readConfigFile(DEFAULT_CONFIG_PATH);
    if (!config) {
      return res.status(404).json({ success: false, message: '配置文件不存在' });
    }
    res.json({ success: true, data: config });
  } catch (error) {
    res.status(500).json({ success: false, message: '获取配置失败', error: error.message });
  }
});

// 路由: 更新全局配置
apiRouter.put('/config', async (req, res) => {
  try {
    // 验证请求数据
    if (!req.body || typeof req.body !== 'object') {
      return res.status(400).json({ success: false, message: '无效的配置数据' });
    }
    
    // 更新配置文件
    const success = await writeConfigFile(DEFAULT_CONFIG_PATH, req.body);
    if (!success) {
      return res.status(500).json({ success: false, message: '保存配置失败' });
    }
    
    // 重新加载Nginx配置
    const reloaded = await reloadNginx();
    
    res.json({ 
      success: true, 
      message: '配置已更新' + (reloaded ? '并已重新加载' : '，但重新加载失败') 
    });
  } catch (error) {
    res.status(500).json({ success: false, message: '更新配置失败', error: error.message });
  }
});

// 路由: 获取站点列表
apiRouter.get('/sites', async (req, res) => {
  try {
    const files = await fs.readdir(SITES_DIR);
    const siteFiles = files.filter(file => file.endsWith('.json'));
    
    const sites = [];
    for (const file of siteFiles) {
      const siteConfig = await readConfigFile(path.join(SITES_DIR, file));
      if (siteConfig && siteConfig.domain) {
        sites.push({
          domain: siteConfig.domain,
          enabled: siteConfig.enabled || false,
          filename: file
        });
      }
    }
    
    res.json({ success: true, data: sites });
  } catch (error) {
    res.status(500).json({ success: false, message: '获取站点列表失败', error: error.message });
  }
});

// 路由: 获取站点配置
apiRouter.get('/sites/:domain', async (req, res) => {
  try {
    const { domain } = req.params;
    const sitePath = path.join(SITES_DIR, `${domain}.json`);
    
    const siteConfig = await readConfigFile(sitePath);
    if (!siteConfig) {
      return res.status(404).json({ success: false, message: '站点配置不存在' });
    }
    
    res.json({ success: true, data: siteConfig });
  } catch (error) {
    res.status(500).json({ success: false, message: '获取站点配置失败', error: error.message });
  }
});

// 路由: 创建或更新站点配置
apiRouter.put('/sites/:domain', async (req, res) => {
  try {
    const { domain } = req.params;
    
    // 验证请求数据
    if (!req.body || !req.body.domain) {
      return res.status(400).json({ success: false, message: '无效的站点配置数据' });
    }
    
    if (req.body.domain !== domain) {
      return res.status(400).json({ success: false, message: 'URL中的域名与配置数据不匹配' });
    }
    
    // 写入站点配置文件
    const sitePath = path.join(SITES_DIR, `${domain}.json`);
    const success = await writeConfigFile(sitePath, req.body);
    
    if (!success) {
      return res.status(500).json({ success: false, message: '保存站点配置失败' });
    }
    
    // 生成Nginx配置
    await generateNginxConfig(domain, req.body);
    
    // 重新加载Nginx配置
    const reloaded = await reloadNginx();
    
    res.json({ 
      success: true, 
      message: '站点配置已更新' + (reloaded ? '并已重新加载' : '，但重新加载失败') 
    });
  } catch (error) {
    res.status(500).json({ success: false, message: '更新站点配置失败', error: error.message });
  }
});

// 路由: 删除站点配置
apiRouter.delete('/sites/:domain', async (req, res) => {
  try {
    const { domain } = req.params;
    const sitePath = path.join(SITES_DIR, `${domain}.json`);
    
    // 检查文件是否存在
    try {
      await fs.access(sitePath);
    } catch (error) {
      return res.status(404).json({ success: false, message: '站点配置不存在' });
    }
    
    // 删除站点配置文件
    await fs.unlink(sitePath);
    
    // 删除Nginx配置
    const nginxConfigPath = '/usr/local/openresty/nginx/conf.d/' + domain + '.conf';
    try {
      await fs.unlink(nginxConfigPath);
    } catch (error) {
      console.error(`删除Nginx配置失败 ${nginxConfigPath}:`, error);
    }
    
    // 重新加载Nginx配置
    const reloaded = await reloadNginx();
    
    res.json({ 
      success: true, 
      message: '站点配置已删除' + (reloaded ? '并已重新加载' : '，但重新加载失败') 
    });
  } catch (error) {
    res.status(500).json({ success: false, message: '删除站点配置失败', error: error.message });
  }
});

// 路由: 获取IP黑名单
apiRouter.get('/blacklist', async (req, res) => {
  try {
    const keys = await redis.keys('safeline:blacklist:*');
    const blacklist = [];
    
    for (const key of keys) {
      const ip = key.split(':')[2];
      const ttl = await redis.ttl(key);
      blacklist.push({
        ip,
        expires_in: ttl,
        permanent: ttl === -1
      });
    }
    
    res.json({ success: true, data: blacklist });
  } catch (error) {
    res.status(500).json({ success: false, message: '获取IP黑名单失败', error: error.message });
  }
});

// 路由: 添加IP到黑名单
apiRouter.post('/blacklist', async (req, res) => {
  try {
    const { ip, duration } = req.body;
    
    if (!ip) {
      return res.status(400).json({ success: false, message: 'IP地址是必需的' });
    }
    
    // 验证IP格式
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (!ipRegex.test(ip)) {
      return res.status(400).json({ success: false, message: '无效的IP地址格式' });
    }
    
    // 添加到Redis黑名单
    const key = `safeline:blacklist:${ip}`;
    
    if (duration === -1) {
      // 永久黑名单
      await redis.set(key, 1);
    } else {
      // 临时黑名单 (默认24小时)
      const seconds = duration || 86400;
      await redis.setex(key, seconds, 1);
    }
    
    res.json({ success: true, message: 'IP已添加到黑名单' });
  } catch (error) {
    res.status(500).json({ success: false, message: '添加IP到黑名单失败', error: error.message });
  }
});

// 路由: 从黑名单中移除IP
apiRouter.delete('/blacklist/:ip', async (req, res) => {
  try {
    const { ip } = req.params;
    
    // 验证IP格式
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (!ipRegex.test(ip)) {
      return res.status(400).json({ success: false, message: '无效的IP地址格式' });
    }
    
    // 从Redis黑名单中删除
    const key = `safeline:blacklist:${ip}`;
    await redis.del(key);
    
    res.json({ success: true, message: 'IP已从黑名单中移除' });
  } catch (error) {
    res.status(500).json({ success: false, message: '从黑名单中移除IP失败', error: error.message });
  }
});

// 路由: 获取统计数据
apiRouter.get('/stats', async (req, res) => {
  try {
    const stats = {
      total_requests: parseInt(await redis.get('safeline:stats:total_requests') || '0'),
      blocked_requests: parseInt(await redis.get('safeline:stats:blocked_requests') || '0'),
      sites: {}
    };
    
    // 获取站点统计
    const siteKeys = await redis.keys('safeline:stats:site:*');
    for (const key of siteKeys) {
      const domain = key.split(':')[3];
      stats.sites[domain] = parseInt(await redis.get(key) || '0');
    }
    
    res.json({ success: true, data: stats });
  } catch (error) {
    res.status(500).json({ success: false, message: '获取统计数据失败', error: error.message });
  }
});

// 路由: 获取实时日志
apiRouter.get('/logs', async (req, res) => {
  try {
    const { limit = 100 } = req.query;
    
    // 从Redis获取最近的日志
    const logs = await redis.lrange('safeline:logs', 0, limit - 1);
    const parsedLogs = logs.map(log => JSON.parse(log));
    
    res.json({ success: true, data: parsedLogs });
  } catch (error) {
    res.status(500).json({ success: false, message: '获取日志失败', error: error.message });
  }
});

// 生成Nginx配置文件
async function generateNginxConfig(domain, siteConfig) {
  if (!siteConfig.enabled) {
    return;
  }
  
  // 配置模板
  const configTemplate = `
server {
    listen 80;
    server_name ${domain};
    
    # 静态资源目录
    location /safeline-static/ {
        alias /usr/local/openresty/nginx/lua/static/;
        expires 30d;
    }
    
    # 验证API
    location /safeline-api/ {
        content_by_lua_file /usr/local/openresty/nginx/lua/captcha.lua;
    }
    
    # WAF处理逻辑
    access_by_lua_file /usr/local/openresty/nginx/lua/access_advanced.lua;
    header_filter_by_lua_file /usr/local/openresty/nginx/lua/header_filter.lua;
    body_filter_by_lua_file /usr/local/openresty/nginx/lua/body_filter.lua;
    
    # 反向代理设置
    location / {
        proxy_pass ${siteConfig.backend_server};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
  `;
  
  const configPath = '/usr/local/openresty/nginx/conf.d/' + domain + '.conf';
  await fs.writeFile(configPath, configTemplate, 'utf8');
}

// 启动应用
async function start() {
  await ensureDirectories();
  
  app.listen(PORT, () => {
    console.log(`SafeLine WAF 管理后端正在运行，端口: ${PORT}`);
  });
}

start().catch(error => {
  console.error('应用启动失败:', error);
  process.exit(1);
});
