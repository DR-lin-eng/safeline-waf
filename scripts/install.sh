#!/bin/bash

# SafeLine WAF 安装脚本
# 该脚本安装基于Nginx的高性能Web应用防火墙

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# 输出信息函数
info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# docker compose 兼容包装：优先 v2 插件，回退 v1 独立命令
docker_compose() {
    if docker compose version &>/dev/null 2>&1; then
        docker compose "$@"
    elif command -v docker-compose &>/dev/null; then
        docker-compose "$@"
    else
        error "未找到 docker compose 或 docker-compose，请先安装"
        exit 1
    fi
}

# 检查系统
check_system() {
    info "正在检查系统环境..."
    
    # 检查是否为root用户运行
    if [ "$(id -u)" != "0" ]; then
        error "请使用root用户运行此脚本（或使用 sudo）"
        exit 1
    fi
    
    # 检查操作系统
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        error "无法检测操作系统版本"
        exit 1
    fi
    
    info "检测到操作系统: $OS $VER"
    
    # 检查系统是否支持
    case $OS in
        "Ubuntu"|"Debian GNU/Linux"|"CentOS Linux"|"Rocky Linux"|"AlmaLinux")
            success "支持的操作系统: $OS"
            ;;
        *)
            warn "操作系统 $OS 未经过全面测试，安装可能会失败"
            read -p "是否继续? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
            ;;
    esac
    
    # 检查系统资源
    MEM_TOTAL=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    MEM_TOTAL_GB=$(awk "BEGIN {printf \"%.1f\", $MEM_TOTAL/1024/1024}")

    CPU_CORES=$(nproc)

    info "系统内存: ${MEM_TOTAL_GB}GB"
    info "CPU核心数: $CPU_CORES"

    if awk "BEGIN {exit !(${MEM_TOTAL_GB} < 1.5)}"; then
        warn "系统内存不足，推荐至少2GB内存运行SafeLine WAF"
        read -p "是否继续? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    if [ "$CPU_CORES" -lt 1 ]; then
        warn "CPU核心数过少，性能可能不佳"
    fi
}

# 安装依赖
install_dependencies() {
    info "正在安装依赖..."
    
    case $OS in
        "Ubuntu"|"Debian GNU/Linux")
            # 移除与 Docker CE 冲突的旧包
            apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
            apt-get update
            apt-get install -y curl wget git build-essential libpcre3-dev libssl-dev zlib1g-dev \
                               redis-server
            # 安装 Docker CE（若未安装）
            if ! command -v docker &>/dev/null; then
                curl -fsSL https://get.docker.com | sh
            fi
            # 安装 docker-compose（优先插件，回退独立二进制）
            if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null 2>&1; then
                apt-get install -y docker-compose-plugin 2>/dev/null || \
                curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
                     -o /usr/local/bin/docker-compose && chmod +x /usr/local/bin/docker-compose
            fi
            ;;
        "CentOS Linux"|"Rocky Linux"|"AlmaLinux")
            yum -y install epel-release
            yum -y install curl wget git gcc gcc-c++ make pcre-devel openssl-devel zlib-devel \
                           redis docker docker-compose
            systemctl enable redis
            systemctl start redis
            systemctl enable docker
            systemctl start docker
            ;;
        *)
            warn "未知操作系统，尝试安装通用依赖..."
            # 通用安装尝试
            if command -v apt-get &> /dev/null; then
                apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
                apt-get update
                apt-get install -y curl wget git build-essential libpcre3-dev libssl-dev zlib1g-dev \
                                   redis-server
                command -v docker &>/dev/null || curl -fsSL https://get.docker.com | sh
            elif command -v yum &> /dev/null; then
                yum -y install epel-release
                yum -y install curl wget git gcc gcc-c++ make pcre-devel openssl-devel zlib-devel \
                               redis docker docker-compose
                systemctl enable redis
                systemctl start redis
                systemctl enable docker
                systemctl start docker
            else
                error "无法安装依赖，请手动安装所需依赖"
                exit 1
            fi
            ;;
    esac
    
    # 检查依赖安装结果
    if [ $? -ne 0 ]; then
        error "依赖安装失败"
        exit 1
    fi
    
    success "依赖安装完成"
}

# 克隆源码
clone_source() {
    info "下载SafeLine WAF源码..."

    mkdir -p /opt/safeline-waf
    cd /opt/safeline-waf

    if [ -d ".git" ]; then
        # 已是 Git 仓库 → 拉取最新代码（确保新增文件如 docker-compose.prod.yml 到位）
        info "检测到 Git 仓库，执行 git pull..."
        git pull origin main || warn "git pull 失败，继续使用当前版本"
    elif [ -d "./nginx" ] && [ -d "./admin" ] && [ -d "./config" ]; then
        # 非 Git 仓库但文件已存在 → 补充下载缺失的关键文件
        info "检测到本地源码，补全缺失文件..."
        for f in docker-compose.prod.yml docker-compose.yml; do
            if [ ! -f "$f" ]; then
                curl -fsSL "https://raw.githubusercontent.com/DR-lin-eng/safeline-waf/main/$f" -o "$f" \
                    || warn "无法下载 $f，部分功能可能受限"
            fi
        done
    else
        git clone https://github.com/DR-lin-eng/safeline-waf.git .
        if [ $? -ne 0 ]; then
            error "源码下载失败"
            exit 1
        fi
    fi

    success "源码准备完成"
}

# 配置文件准备
prepare_config() {
    info "准备配置文件..."
    
    # 创建必要的目录
    mkdir -p /opt/safeline-waf/config/sites
    mkdir -p /opt/safeline-waf/logs
    
    # 检查默认配置文件是否存在
    if [ ! -f "/opt/safeline-waf/config/default_config.json" ]; then
        # 创建默认配置
        cat > /opt/safeline-waf/config/default_config.json <<EOF
{
  "global": {
    "log_level": "info",
    "default_action": "allow"
  },
  "ip_blacklist": [],
  "ip_ranges": [],
  "ddos_protection": {
    "url_threshold": 60,
    "url_window": 60,
    "ip_threshold": 300,
    "ip_window": 60,
    "dynamic_scaling": true
  },
  "slow_ddos": {
    "connection_threshold": 10,
    "window": 60
  },
  "anti_cc": {
    "cc_threshold": 60,
    "cc_time_window": 60,
    "cc_request_count": 60
  },
  "pow_config": {
    "base_difficulty": 4,
    "max_difficulty": 8
  },
  "behavior_analysis": {
    "window_size": 60,
    "min_requests": 10
  },
  "js_encryption": {
    "renew_interval": 3600,
    "variable_name_length": 8
  },
  "honeypot_settings": {
    "enabled": true,
    "traps": [
      "/.well-known/safeline-trap",
      "/admin_access",
      "/wp-login.php",
      "/.git/"
    ]
  },
  "sampling": {
    "enabled": true,
    "rate": 0.01,
    "anomaly_threshold": 5.0
  }
}
EOF
    fi
    
    # 配置文件权限
    chmod -R 755 /opt/safeline-waf/config
    
    success "配置文件准备完成"
}

# 构建并启动Docker容器
build_and_run() {
    info "构建并启动SafeLine WAF..."

    cd /opt/safeline-waf

    PROD_COMPOSE="/opt/safeline-waf/docker-compose.prod.yml"

    # 若 prod compose 文件缺失，尝试从 GitHub 补充下载
    if [ ! -f "$PROD_COMPOSE" ]; then
        warn "docker-compose.prod.yml 不存在，尝试下载..."
        curl -fsSL "https://raw.githubusercontent.com/DR-lin-eng/safeline-waf/main/docker-compose.prod.yml" \
             -o "$PROD_COMPOSE" || true
    fi

    # Docker 刚安装后 iptables 链可能尚未初始化，预先重启 daemon 确保网络正常
    _ensure_docker_network() {
        if ! docker network ls &>/dev/null; then
            warn "Docker 网络不可用，重启 Docker daemon..."
            systemctl restart docker
            sleep 3
        fi
    }
    _ensure_docker_network

    # 执行 compose up，若遇到 iptables 链缺失则重启 Docker 后重试一次
    _compose_up() {
        local output
        output=$(SAFELINE_TAG=${SAFELINE_TAG:-main} docker_compose -f "$1" up -d 2>&1)
        local rc=$?
        echo "$output"
        if [ $rc -ne 0 ] && echo "$output" | grep -q "No chain/target/match"; then
            warn "iptables 链缺失，重启 Docker 后重试..."
            systemctl restart docker
            sleep 5
            SAFELINE_TAG=${SAFELINE_TAG:-main} docker_compose -f "$1" up -d
            return $?
        fi
        return $rc
    }

    if [ -f "$PROD_COMPOSE" ]; then
        docker_compose -f "$PROD_COMPOSE" down 2>/dev/null || true

        info "拉取预构建多架构镜像（amd64/arm64）..."
        SAFELINE_TAG=${SAFELINE_TAG:-main} docker_compose -f "$PROD_COMPOSE" pull

        if [ $? -eq 0 ]; then
            _compose_up "$PROD_COMPOSE"
        else
            warn "拉取镜像失败，回退到本地编译..."
            docker_compose down 2>/dev/null || true
            docker_compose up -d --build
        fi
    else
        warn "docker-compose.prod.yml 仍不可用，使用本地编译..."
        docker_compose down 2>/dev/null || true
        docker_compose up -d --build
    fi

    if [ $? -ne 0 ]; then
        error "Docker 启动失败"
        exit 1
    fi

    success "SafeLine WAF 已成功启动"
}

# 检查服务状态
check_status() {
    info "检查服务状态..."
    
    sleep 5
    
    # 检查容器状态
    PROD_COMPOSE="/opt/safeline-waf/docker-compose.prod.yml"
    COMPOSE_F=""
    [ -f "$PROD_COMPOSE" ] && COMPOSE_F="-f $PROD_COMPOSE"
    CONTAINERS=$(docker_compose $COMPOSE_F ps -q)
    
    if [ -z "$CONTAINERS" ]; then
        error "没有找到运行中的容器"
        exit 1
    fi
    
    for CONTAINER in $CONTAINERS; do
        STATUS=$(docker inspect --format='{{.State.Status}}' $CONTAINER)
        NAME=$(docker inspect --format='{{.Name}}' $CONTAINER | sed 's/\///')
        
        if [ "$STATUS" != "running" ]; then
            error "容器 $NAME 状态异常: $STATUS"
            docker logs $CONTAINER
            exit 1
        else
            info "容器 $NAME 正在运行"
        fi
    done
    
    # 检查Nginx是否监听端口
    sleep 2
    NGINX_PORT=$(docker exec safeline-waf-nginx netstat -tlnp | grep -E ':80.*LISTEN')
    
    if [ -z "$NGINX_PORT" ]; then
        warn "Nginx似乎没有正确监听80端口"
    else
        success "Nginx正在监听80端口"
    fi
    
    success "所有服务已启动并运行正常"
}

# 显示安装信息
show_info() {
    IP=$(hostname -I | awk '{print $1}')
    
    echo
    echo "============================================================="
    echo -e "${GREEN}SafeLine WAF 安装完成${NC}"
    echo "============================================================="
    echo
    echo -e "管理界面: ${GREEN}http://$IP:8080${NC}"
    echo -e "默认账号: ${GREEN}admin${NC}"
    echo -e "默认密码: ${GREEN}safeline123${NC}"
    echo
    echo "请立即登录并修改默认密码！"
    echo
    echo "如需添加站点，请在管理界面操作。"
    echo "如需查看日志，请使用: docker logs safeline-waf-nginx"
    echo
    echo "感谢使用SafeLine WAF!"
    echo "============================================================="
}

# 主函数
main() {
    echo "============================================================="
    echo "                     SafeLine WAF 安装程序                    "
    echo "============================================================="
    echo
    
    check_system
    install_dependencies
    clone_source
    prepare_config
    build_and_run
    check_status
    show_info
}

# 执行主函数
main
