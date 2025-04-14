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
