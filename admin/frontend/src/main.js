import Vue from 'vue'
import App from './App.vue'
import router from './router'
import axios from 'axios'
import 'bootstrap/dist/css/bootstrap.css'
import 'bootstrap-icons/font/bootstrap-icons.css'
import 'bootstrap/dist/js/bootstrap.bundle.min.js'

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

Vue.config.productionTip = false

new Vue({
  router,
  render: h => h(App)
}).$mount('#app')
