import Vue from 'vue'
import App from './App.vue'
import router from './router'
import axios from 'axios'
import toast from './toast'
import { getApiErrorMessage } from './utils/http'
import 'bootstrap/dist/css/bootstrap.css'
import 'bootstrap-icons/font/bootstrap-icons.css'
import 'bootstrap/dist/js/bootstrap.bundle.min.js'

// 配置axios
axios.defaults.baseURL = process.env.VUE_APP_API_URL || '/safeline-admin-api'
axios.defaults.headers.common['X-Requested-With'] = 'XMLHttpRequest'

function readStoredAuthToken() {
  return localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token')
}

function clearStoredAuthToken() {
  localStorage.removeItem('auth_token')
  sessionStorage.removeItem('auth_token')
}

function redirectToLogin() {
  const currentRoute = router.currentRoute
  const isLoginRoute = currentRoute && currentRoute.name === 'Login'

  if (isLoginRoute) {
    return
  }

  const redirect = currentRoute && currentRoute.fullPath ? currentRoute.fullPath : '/dashboard'
  router.replace({
    name: 'Login',
    query: redirect ? { redirect } : {}
  }).catch(() => {})
}

// 添加请求拦截器
axios.interceptors.request.use(
  config => {
    // 在请求发送前添加认证信息
    const token = readStoredAuthToken()
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`
    }
    return config
  },
  error => {
    return Promise.reject(error)
  }
)

axios.interceptors.response.use(
  response => response,
  error => {
    const response = error && error.response
    const status = response ? response.status : 0

    if (status === 401) {
      const hadAuthHeader = Boolean(
        error &&
        error.config &&
        error.config.headers &&
        error.config.headers.Authorization
      )

      if (hadAuthHeader || readStoredAuthToken()) {
        error.__globalToastShown = true
        clearStoredAuthToken()
        toast.warning('登录状态已失效，请重新登录。')
        redirectToLogin()
      }
    } else if (status === 403) {
      error.__globalToastShown = true
      toast.error(getApiErrorMessage(error, '当前账号没有权限执行该操作。'))
    } else if (status >= 500) {
      error.__globalToastShown = true
      toast.error(getApiErrorMessage(error, '管理接口发生错误，请稍后重试。'))
    } else if (!response) {
      error.__globalToastShown = true
      toast.error(getApiErrorMessage(error, '无法连接管理接口，请检查服务状态或网络连接。'))
    }

    return Promise.reject(error)
  }
)

Vue.config.productionTip = false

Vue.prototype.$toast = toast

new Vue({
  router,
  render: h => h(App)
}).$mount('#app')
