import Vue from 'vue'
import VueRouter from 'vue-router'
import toast from '../toast'

import Dashboard from '../views/Dashboard.vue'
import Login from '../views/Login.vue'

Vue.use(VueRouter)

function readStoredAuthToken() {
  return localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token')
}

function clearStoredAuthToken() {
  localStorage.removeItem('auth_token')
  sessionStorage.removeItem('auth_token')
}

function parseJwtPayload(token) {
  if (!token || typeof token !== 'string') {
    return null
  }

  const parts = token.split('.')
  if (parts.length !== 3) {
    return null
  }

  try {
    const normalized = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4)
    return JSON.parse(window.atob(padded))
  } catch (_) {
    return null
  }
}

function isTokenExpired(token) {
  const payload = parseJwtPayload(token)
  if (!payload || typeof payload.exp !== 'number') {
    return true
  }

  return payload.exp <= Math.floor(Date.now() / 1000)
}

const routes = [
  {
    path: '/login',
    name: 'Login',
    component: Login
  },
  {
    path: '/index.html',
    redirect: '/login'
  },
  {
    path: '/admin',
    redirect: '/login'
  },
  {
    path: '/',
    redirect: '/dashboard'
  },
  {
    path: '/dashboard',
    name: 'Dashboard',
    component: Dashboard
  },
  {
    path: '/dashboard.html',
    redirect: '/dashboard'
  },
  {
    path: '/sites',
    name: 'Sites',
    component: () => import(/* webpackChunkName: "sites" */ '../views/Sites.vue')
  },
  {
    path: '/sites.html',
    redirect: '/sites'
  },
  {
    path: '/blacklist',
    name: 'Blacklist',
    component: () => import(/* webpackChunkName: "blacklist" */ '../views/Blacklist.vue')
  },
  {
    path: '/blacklist.html',
    redirect: '/blacklist'
  },
  {
    path: '/logs',
    name: 'Logs',
    component: () => import(/* webpackChunkName: "logs" */ '../views/Logs.vue')
  },
  {
    path: '/logs.html',
    redirect: '/logs'
  },
  {
    path: '/settings',
    name: 'Settings',
    component: () => import(/* webpackChunkName: "settings" */ '../views/Settings.vue')
  },
  {
    path: '/settings.html',
    redirect: '/settings'
  },
  {
    path: '/cluster',
    name: 'Cluster',
    component: () => import(/* webpackChunkName: "cluster" */ '../views/Cluster.vue')
  },
  {
    path: '/monitor',
    name: 'Monitor',
    component: () => import(/* webpackChunkName: "monitor" */ '../views/Monitor.vue')
  },
  {
    path: '/monitor.html',
    redirect: '/monitor'
  },
  {
    path: '/cluster.html',
    redirect: '/cluster'
  },
  {
    path: '/ml',
    redirect: '/ml/dashboard'
  },
  {
    path: '/ml/dashboard',
    name: 'MLDashboard',
    component: () => import(/* webpackChunkName: "ml" */ '../views/MLDashboard.vue')
  },
  {
    path: '/ml/models',
    name: 'MLModels',
    component: () => import(/* webpackChunkName: "ml" */ '../views/MLModels.vue')
  },
  {
    path: '/ml/training',
    name: 'MLTraining',
    component: () => import(/* webpackChunkName: "ml" */ '../views/MLTraining.vue')
  },
  {
    path: '/llm',
    name: 'LLMAudit',
    component: () => import(/* webpackChunkName: "llm" */ '../views/LLMAudit.vue')
  },
  {
    path: '/inspection',
    name: 'DeepInspection',
    component: () => import(/* webpackChunkName: "inspection" */ '../views/DeepInspection.vue')
  },
  {
    path: '/cf',
    name: 'CfShield',
    component: () => import(/* webpackChunkName: "cf" */ '../views/CfShield.vue')
  },
  {
    path: '/cf.html',
    redirect: '/cf'
  },
  {
    path: '/map',
    name: 'AttackMap',
    component: () => import(/* webpackChunkName: "map" */ '../views/AttackMap.vue')
  },
  {
    path: '/map.html',
    redirect: '/map'
  },
  {
    path: '*',
    redirect: '/dashboard'
  }
]

const router = new VueRouter({
  mode: 'history',
  base: process.env.BASE_URL,
  routes
})

router.beforeEach((to, from, next) => {
  const token = readStoredAuthToken()
  const isLoginRoute = to.name === 'Login'

  if (token && isTokenExpired(token)) {
    clearStoredAuthToken()
    if (isLoginRoute) {
      next()
    } else {
      toast.warning('登录状态已失效，请重新登录。')
      next({
        name: 'Login',
        query: {
          redirect: to.fullPath
        }
      })
    }
    return
  }

  if (!token && !isLoginRoute) {
    next({
      name: 'Login',
      query: {
        redirect: to.fullPath
      }
    })
    return
  }

  if (token && isLoginRoute) {
    next({ name: 'Dashboard' })
    return
  }

  next()
})

export default router
