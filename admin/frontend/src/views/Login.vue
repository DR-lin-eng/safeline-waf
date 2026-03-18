<template>
  <div class="login-page">
    <div class="login-box">
      <div class="card card-outline card-primary">
        <div class="card-header text-center">
          <h1><b>SafeLine</b> WAF</h1>
        </div>
        <div class="card-body">
          <p class="login-box-msg">登录管理后台</p>
          <form @submit.prevent="login">
            <div class="input-group mb-3">
              <input 
                type="text" 
                class="form-control" 
                placeholder="用户名" 
                v-model="username" 
                required
              >
              <div class="input-group-append">
                <div class="input-group-text">
                  <i class="bi bi-person"></i>
                </div>
              </div>
            </div>
            <div class="input-group mb-3">
              <input 
                type="password" 
                class="form-control" 
                placeholder="密码" 
                v-model="password" 
                required
              >
              <div class="input-group-append">
                <div class="input-group-text">
                  <i class="bi bi-lock"></i>
                </div>
              </div>
            </div>
            <div class="row">
              <div class="col-8">
                <div class="icheck-primary">
                  <input type="checkbox" id="remember" v-model="remember">
                  <label for="remember">
                    记住我
                  </label>
                </div>
              </div>
              <div class="col-4">
                <button type="submit" class="btn btn-primary btn-block" :disabled="isLoading">
                  <span v-if="isLoading">
                    <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>
                    登录中...
                  </span>
                  <span v-else>登录</span>
                </button>
              </div>
            </div>
          </form>
          <div class="alert alert-danger mt-3" v-if="error">
            {{ error }}
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios'

export default {
  name: 'Login',
  data() {
    return {
      username: '',
      password: '',
      remember: false,
      isLoading: false,
      error: null
    }
  },
  created() {
    // 检查是否已经登录
    const token = localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token');
    if (token) {
      this.$router.replace(this.$route.query.redirect || '/dashboard');
    }
  },
  methods: {
    async login() {
      this.isLoading = true;
      this.error = null;

      try {
        const res = await axios.post('/login', {
          username: this.username,
          password: this.password
        });

        const token = res.data && res.data.token;
        if (!token) {
          throw new Error('No token in response');
        }

        if (this.remember) {
          localStorage.setItem('auth_token', token);
        } else {
          sessionStorage.setItem('auth_token', token);
        }

        this.$router.replace(this.$route.query.redirect || '/dashboard');
      } catch (err) {
        const msg = err.response && err.response.data && err.response.data.message;
        this.error = msg || '用户名或密码不正确';
      } finally {
        this.isLoading = false;
      }
    }
  }
}
</script>

<style scoped>
.login-page {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background: #f4f6f9;
}

.login-box {
  width: 360px;
}

.card {
  box-shadow: 0 0 1px rgba(0,0,0,.125), 0 1px 3px rgba(0,0,0,.2);
  margin-bottom: 1rem;
}

.card-header {
  padding: 1.5rem;
}

.login-box-msg {
  margin: 0;
  text-align: center;
  padding-bottom: 1rem;
}

.icheck-primary {
  margin-top: 0.5rem;
}
</style>
