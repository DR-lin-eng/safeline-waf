import Vue from 'vue'
import VueRouter from 'vue-router'

// 导入视图组件
import Dashboard from '../views/Dashboard.vue'

Vue.use(VueRouter)

const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: Dashboard
  },
  {
    path: '/sites',
    name: 'Sites',
    component: () => import(/* webpackChunkName: "sites" */ '../views/Sites.vue')
  },
  {
    path: '/blacklist',
    name: 'Blacklist',
    component: () => import(/* webpackChunkName: "blacklist" */ '../views/Blacklist.vue')
  },
  {
    path: '/logs',
    name: 'Logs',
    component: () => import(/* webpackChunkName: "logs" */ '../views/Logs.vue')
  },
  {
    path: '/settings',
    name: 'Settings',
    component: () => import(/* webpackChunkName: "settings" */ '../views/Settings.vue')
  }
]

const router = new VueRouter({
  mode: 'history',
  base: process.env.BASE_URL,
  routes
})

export default router
