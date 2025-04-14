<template>
  <div id="app">
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
            </ul>
          </div>
        </nav>

        <main role="main" class="col-md-9 ml-sm-auto col-lg-10 px-md-4 py-4">
          <router-view />
        </main>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'App'
}
</script>

<style>
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
