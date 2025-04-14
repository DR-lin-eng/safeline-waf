import Vue from 'vue'
import App from './App.vue'
import router from './router'
import axios from 'axios'

// 引入Bootstrap CSS
import 'bootstrap/dist/css/bootstrap.min.css'
import 'bootstrap-icons/font/bootstrap-icons.css'

// 引入Bootstrap JS
import 'bootstrap/dist/js/bootstrap.bundle.min.js'

// 配置axios
axios.defaults.baseURL = process.env.VUE_APP_API_URL || '/api'

// 添加请求拦截器
axios.interceptors.request.use(
  config => {
    // 在请求发送前可以添加认证信息等
    return config
  },
  error => {
    return Promise.reject(error)
  }
)

// 添加响应拦截器
axios.interceptors.response.use(
  response => {
    return response
  },
  error => {
    // 处理响应错误，例如身份验证错误
    if (error.response && error.response.status === 401) {
      router.push('/login')
    }
    return Promise.reject(error)
  }
)

// 全局注册axios
Vue.prototype.$http = axios

Vue.config.productionTip = false

new Vue({
  router,
  render: h => h(App)
}).$mount('#app')
