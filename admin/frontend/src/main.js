// 配置axios
axios.defaults.baseURL = process.env.VUE_APP_API_URL || '/safeline-admin-api'

// 添加请求拦截器
axios.interceptors.request.use(
  config => {
    // 在请求发送前添加认证信息
    const token = localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token');
    if (token) {
      config.headers['Authorization'] = `Basic ${token}`;
    }
    return config
  },
  error => {
    return Promise.reject(error)
  }
)
