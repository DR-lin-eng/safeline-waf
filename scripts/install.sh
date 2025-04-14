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
    MEM_TOTAL_GB=$(echo "scale=1; $MEM_TOTAL/1024/1024" | bc)
    
    CPU_CORES=$(nproc)
    
    info "系统内存: ${MEM_TOTAL_GB}GB"
    info "CPU核心数: $CPU_CORES"
    
    if (( $(echo "$MEM_TOTAL_GB < 1.5" | bc -l) )); then
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
            apt-get update
            apt-get install -y curl wget git build-essential libpcre3-dev libssl-dev zlib1g-dev \
                               redis-server docker.io docker-compose
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
                apt-get update
                apt-get install -y curl wget git build-essential libpcre3-dev libssl-dev zlib1g-dev \
                                   redis-server docker.io docker-compose
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
    
    # 创建目录
    mkdir -p /opt/safeline-waf
    cd /opt/safeline-waf
    
    # 如果是通过脚本方式安装而非Git，直接复制文件
    if [ -d "./nginx" ] && [ -d "./admin" ] && [ -d "./config" ]; then
        info "检测到本地源码，跳过下载"
    else
        # 这里使用GitHub仓库，实际部署时替换为您的仓库
        git clone https://github.com/DR-lin-eng/safeline-waf.git .
        
        if [ $? -ne 0 ]; then
            warn "Git克隆失败，尝试使用备用方法下载..."
            # 备用下载方法
            wget -O safeline-waf.tar.gz https://your-server.com/downloads/safeline-waf.tar.gz
            tar -xzf safeline-waf.tar.gz
            rm safeline-waf.tar.gz
            
            if [ $? -ne 0 ]; then
                error "源码下载失败"
                exit 1
            fi
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
    
    # 停止可能已经运行的容器
    docker-compose down
    
    # 构建并启动
    docker-compose up -d --build
    
    if [ $? -ne 0 ]; then
        error "Docker构建或启动失败"
        exit 1
    fi
    
    success "SafeLine WAF已成功启动"
}

# 检查服务状态
check_status() {
    info "检查服务状态..."
    
    sleep 5
    
    # 检查容器状态
    CONTAINERS=$(docker-compose ps -q)
    
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
