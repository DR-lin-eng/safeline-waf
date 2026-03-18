<template>
  <div id="app">
    <div class="toast-stack" aria-live="polite" aria-atomic="true">
      <transition-group name="toast-fade" tag="div">
        <div
          v-for="toast in toastState.items"
          :key="toast.id"
          class="toast-item shadow"
          :class="`toast-${toast.level}`"
        >
          <div class="toast-item__message">{{ toast.message }}</div>
          <button
            type="button"
            class="toast-item__close"
            aria-label="关闭通知"
            @click="dismissToast(toast.id)"
          >
            &times;
          </button>
        </div>
      </transition-group>
    </div>

    <!-- 登录页面不显示导航 -->
    <template v-if="!isLoginPage">
      <nav class="navbar navbar-dark sticky-top bg-primary flex-md-nowrap p-0 shadow">
        <a class="navbar-brand col-md-3 col-lg-2 mr-0 px-3" href="#">
          <span class="font-weight-bold">SafeLine WAF</span>
        </a>
        <button 
          class="navbar-toggler position-absolute d-md-none collapsed" 
          type="button" 
          data-toggle="collapse" 
          data-target="#sidebarMenu" 
          aria-controls="sidebarMenu" 
          aria-expanded="false" 
          aria-label="Toggle navigation"
        >
          <span class="navbar-toggler-icon"></span>
        </button>
        
        <ul class="navbar-nav px-3 ml-auto">
          <li class="nav-item text-nowrap">
            <button class="btn btn-link nav-link" @click="logout">
              <i class="bi bi-box-arrow-right"></i> 退出
            </button>
          </li>
        </ul>
      </nav>

      <div class="container-fluid">
        <div class="row">
          <nav id="sidebarMenu" class="col-md-3 col-lg-2 d-md-block bg-light sidebar collapse">
            <div class="sidebar-sticky pt-3">
              <ul class="nav flex-column">
                <li class="nav-item">
                  <router-link class="nav-link" :to="{name: 'Dashboard'}" active-class="active">
                    <i class="bi bi-speedometer2 mr-2"></i>
                    仪表盘
                  </router-link>
                </li>
                <li class="nav-item">
                  <router-link class="nav-link" :to="{name: 'Sites'}" active-class="active">
                    <i class="bi bi-globe mr-2"></i>
                    站点管理
                  </router-link>
                </li>
                <li class="nav-item">
                  <router-link class="nav-link" :to="{name: 'Blacklist'}" active-class="active">
                    <i class="bi bi-shield-lock mr-2"></i>
                    IP黑名单
                  </router-link>
                </li>
                <li class="nav-item">
                  <router-link class="nav-link" :to="{name: 'Logs'}" active-class="active">
                    <i class="bi bi-list-ul mr-2"></i>
                    实时日志
                  </router-link>
                </li>
                <li class="nav-item">
                  <router-link class="nav-link" :to="{name: 'Settings'}" active-class="active">
                    <i class="bi bi-gear mr-2"></i>
                    系统设置
                  </router-link>
                </li>
                <li class="nav-item">
                  <router-link class="nav-link" :to="{name: 'Cluster'}" active-class="active">
                    <i class="bi bi-diagram-3 mr-2"></i>
                    集群管理
                  </router-link>
                </li>
                <li class="nav-item">
                  <router-link class="nav-link" :to="{name: 'Monitor'}" active-class="active">
                    <i class="bi bi-display mr-2"></i>
                    监控大屏
                  </router-link>
                </li>

                <!-- ML 分组 -->
                <li class="nav-item mt-2">
                  <span class="nav-link text-muted px-3 py-1" style="font-size:0.72rem; text-transform:uppercase; letter-spacing:.05em;">
                    机器学习
                  </span>
                </li>
                <li class="nav-item">
                  <router-link class="nav-link" :to="{name: 'MLDashboard'}" active-class="active">
                    <i class="bi bi-cpu mr-2"></i>
                    ML 仪表盘
                  </router-link>
                </li>
                <li class="nav-item">
                  <router-link class="nav-link" :to="{name: 'MLModels'}" active-class="active">
                    <i class="bi bi-box-seam mr-2"></i>
                    模型管理
                  </router-link>
                </li>
                <li class="nav-item">
                  <router-link class="nav-link" :to="{name: 'MLTraining'}" active-class="active">
                    <i class="bi bi-database mr-2"></i>
                    训练数据
                  </router-link>
                </li>

                <!-- LLM 审计 -->
                <li class="nav-item mt-2">
                  <span class="nav-link text-muted px-3 py-1" style="font-size:0.72rem; text-transform:uppercase; letter-spacing:.05em;">
                    智能审计
                  </span>
                </li>
                <li class="nav-item">
                  <router-link class="nav-link" :to="{name: 'LLMAudit'}" active-class="active">
                    <i class="bi bi-robot mr-2"></i>
                    LLM 审计
                  </router-link>
                </li>
                <li class="nav-item">
                  <router-link class="nav-link" :to="{name: 'DeepInspection'}" active-class="active">
                    <i class="bi bi-search-heart mr-2"></i>
                    深度解析
                  </router-link>
                </li>
                <li class="nav-item">
                  <router-link class="nav-link" :to="{name: 'CfShield'}" active-class="active">
                    <i class="bi bi-shield-fill-exclamation mr-2"></i>
                    CF 五秒盾
                  </router-link>
                </li>
                <li class="nav-item">
                  <router-link class="nav-link" :to="{name: 'AttackMap'}" active-class="active">
                    <i class="bi bi-globe2 mr-2"></i>
                    攻击地图
                  </router-link>
                </li>
              </ul>
            </div>
          </nav>

          <main role="main" class="col-md-9 ml-sm-auto col-lg-10 px-md-4 py-4">
            <router-view />
          </main>
        </div>
      </div>
    </template>
    
    <!-- 登录页面 -->
    <template v-else>
      <router-view />
    </template>
  </div>
</template>

<script>
import toast from './toast'

export default {
  name: 'App',
  data() {
    return {
      toastState: toast.state
    }
  },
  computed: {
    isLoginPage() {
      return this.$route.name === 'Login'
    }
  },
  methods: {
    dismissToast(id) {
      toast.remove(id)
    },
    logout() {
      // 清除认证信息
      localStorage.removeItem('auth_token')
      sessionStorage.removeItem('auth_token')
      // 跳转到登录页
      this.$router.push('/login')
    }
  }
}
</script>

<style>
.toast-stack {
  position: fixed;
  top: 1rem;
  right: 1rem;
  z-index: 1085;
  width: min(360px, calc(100vw - 2rem));
}

.toast-item {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 0.75rem;
  margin-bottom: 0.75rem;
  padding: 0.875rem 1rem;
  border-radius: 0.5rem;
  color: #fff;
}

.toast-info {
  background: #0d6efd;
}

.toast-success {
  background: #198754;
}

.toast-warning {
  background: #b7791f;
}

.toast-error {
  background: #c0392b;
}

.toast-item__message {
  flex: 1;
  word-break: break-word;
}

.toast-item__close {
  border: 0;
  background: transparent;
  color: inherit;
  font-size: 1.25rem;
  line-height: 1;
  padding: 0;
  cursor: pointer;
}

.toast-fade-enter-active,
.toast-fade-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}

.toast-fade-enter,
.toast-fade-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}

.sidebar {
  position: fixed;
  top: 0;
  bottom: 0;
  left: 0;
  z-index: 100;
  padding: 48px 0 0;
  box-shadow: inset -1px 0 0 rgba(0, 0, 0, .1);
}

.sidebar-sticky {
  position: relative;
  top: 0;
  height: calc(100vh - 48px);
  padding-top: .5rem;
  overflow-x: hidden;
  overflow-y: auto;
}

.sidebar .nav-link {
  font-weight: 500;
  color: #333;
}

.sidebar .nav-link.active {
  color: #007bff;
}

.navbar-brand {
  padding-top: .75rem;
  padding-bottom: .75rem;
  font-size: 1rem;
  background-color: rgba(0, 0, 0, .25);
  box-shadow: inset -1px 0 0 rgba(0, 0, 0, .25);
}
</style>
