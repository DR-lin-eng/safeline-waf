#!/bin/bash

# SafeLine WAF 安装脚本
# 该脚本安装基于Nginx的高性能Web应用防火墙

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

ENV_GENERATED_TEMP_PASSWORD=''
ENV_TEMP_PASSWORD_IS_GENERATED=0
INSTALL_MODE=''
INSTALL_MODE_LABEL=''
ENV_ACTION=''
ENV_EXISTED_BEFORE=0
ENV_WAS_REGENERATED=0

# 输出信息函数
info() {
    echo -e "${GREEN}[INFO]${NC} $1" >&2
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

select_install_mode() {
    local install_root="/opt/safeline-waf"
    local env_file="$install_root/.env"
    local mode_choice=''

    ENV_EXISTED_BEFORE=0
    if [ -f "$env_file" ]; then
        ENV_EXISTED_BEFORE=1
    fi

    if ! [ -t 0 ] || ! [ -t 1 ]; then
        mode_choice=${INSTALL_MODE:-${SAFELINE_INSTALL_MODE:-}}
        case "$mode_choice" in
            new)
                INSTALL_MODE='new'
                INSTALL_MODE_LABEL='新安装'
                ENV_ACTION='create_if_missing'
                ;;
            upgrade|'')
                INSTALL_MODE='upgrade'
                INSTALL_MODE_LABEL='升级'
                ENV_ACTION='preserve'
                ;;
            overwrite)
                INSTALL_MODE='overwrite'
                INSTALL_MODE_LABEL='覆盖安装'
                ENV_ACTION='regenerate'
                ;;
            exit)
                info "已退出安装程序"
                exit 0
                ;;
            *)
                error "非交互模式下 INSTALL_MODE/SAFELINE_INSTALL_MODE 仅支持: new、upgrade、overwrite、exit"
                exit 1
                ;;
        esac
        info "非交互模式，已选择安装模式: $INSTALL_MODE_LABEL"
        return 0
    fi

    echo "请选择安装模式:"
    echo "  1) 新安装"
    echo "  2) 升级"
    echo "  3) 覆盖安装"
    echo "  4) 退出"

    while true; do
        read -r -p "请输入选项 [1-4]: " mode_choice
        case "$mode_choice" in
            1)
                INSTALL_MODE='new'
                INSTALL_MODE_LABEL='新安装'
                ENV_ACTION='create_if_missing'
                break
                ;;
            2)
                INSTALL_MODE='upgrade'
                INSTALL_MODE_LABEL='升级'
                ENV_ACTION='preserve'
                break
                ;;
            3)
                INSTALL_MODE='overwrite'
                INSTALL_MODE_LABEL='覆盖安装'
                ENV_ACTION='regenerate'
                break
                ;;
            4)
                info "已退出安装程序"
                exit 0
                ;;
            *)
                warn "无效选项，请输入 1-4"
                ;;
        esac
    done

    info "已选择安装模式: $INSTALL_MODE_LABEL"
}

installation_exists() {
    local install_root="/opt/safeline-waf"

    if [ -f "$install_root/.env" ]; then
        return 0
    fi

    if [ -d "$install_root/.git" ] || [ -d "$install_root/nginx" ] || [ -d "$install_root/admin" ] || [ -d "$install_root/config" ]; then
        return 0
    fi

    return 1
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
            if [ -t 0 ] && [ -t 1 ]; then
                read -r -p "是否继续? (y/n) " -n 1
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    exit 1
                fi
            else
                warn "非交互模式，自动继续..."
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
        if [ -t 0 ] && [ -t 1 ]; then
            read -r -p "是否继续? (y/n) " -n 1
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        else
            warn "非交互模式，自动继续..."
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

    if [ "$INSTALL_MODE" = "new" ] && installation_exists; then
        error "检测到现有安装或源码目录，不能以“新安装”模式继续"
        error "请重新运行脚本并选择“升级”或“覆盖安装”"
        exit 1
    fi

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
    local backend_writable_paths=(
        /opt/safeline-waf/config
        /opt/safeline-waf/nginx/conf.d
    )

    info "准备配置文件..."

    # 创建必要的目录
    mkdir -p /opt/safeline-waf/config/sites
    mkdir -p /opt/safeline-waf/config/certs
    mkdir -p /opt/safeline-waf/nginx/conf.d
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

    # 挂载目录需兼容新旧 backend 镜像中的运行用户，避免因 UID 不一致导致启动失败
    for path in "${backend_writable_paths[@]}"; do
        chmod -R u+rwX,go+rwX "$path"
    done

    success "配置文件准备完成"
}

# 环境变量文件准备
prepare_env() {
    local env_file="/opt/safeline-waf/.env"
    local jwt_secret
    local redis_password
    local admin_username=''
    local admin_password_hash=''
    local admin_password=''
    local admin_password_confirm=''
    local is_interactive=0
    local env_has_required_fields=0

    info "准备环境变量文件..."

    ENV_WAS_REGENERATED=0

    if [ -f "$env_file" ]; then
        ENV_EXISTED_BEFORE=1
        chmod 600 "$env_file"

        if grep -q '^JWT_SECRET=' "$env_file" && \
           grep -q '^REDIS_PASSWORD=' "$env_file" && \
           grep -q '^ADMIN_USERNAME=' "$env_file" && \
           grep -q '^ADMIN_PASSWORD_HASH=' "$env_file"; then
            env_has_required_fields=1
        fi
    fi

    if [ "$ENV_ACTION" = "create_if_missing" ]; then
        if [ "$ENV_EXISTED_BEFORE" -eq 1 ] || installation_exists; then
            error "检测到现有安装痕迹，不能以“新安装”模式继续"
            error "请重新运行脚本并选择“升级”或“覆盖安装”"
            exit 1
        fi
    fi

    if [ "$ENV_ACTION" = "preserve" ]; then
        if [ "$ENV_EXISTED_BEFORE" -eq 1 ] && [ "$env_has_required_fields" -eq 1 ]; then
            info "升级模式：保留现有 .env、JWT_SECRET、REDIS_PASSWORD 和管理员凭据"
            return 0
        fi

        if [ "$ENV_EXISTED_BEFORE" -eq 1 ] && [ "$env_has_required_fields" -eq 0 ]; then
            error "检测到现有 .env 缺少必要字段（JWT_SECRET、REDIS_PASSWORD、ADMIN_USERNAME、ADMIN_PASSWORD_HASH）"
            error "请先手动修复 .env，或重新运行脚本并选择“覆盖安装”"
            exit 1
        fi

        info "升级模式：未检测到 .env，将执行缺失 .env 的升级初始化"
    fi

    if [ "$ENV_ACTION" = "regenerate" ]; then
        if [ "$ENV_EXISTED_BEFORE" -eq 1 ]; then
            warn "覆盖安装将重建 .env 中的管理员凭据，旧管理员密码将失效"
        else
            info "覆盖安装模式：未检测到现有 .env，将按全新凭据初始化"
        fi
    fi

    if [ -t 0 ] && [ -t 1 ]; then
        is_interactive=1
    fi

    if ! command -v openssl &>/dev/null; then
        error "未找到 openssl，无法生成安全随机密钥"
        exit 1
    fi

    hash_password() {
        local plain_password="$1"
        local _tmpfile
        local _result

        _tmpfile=$(mktemp 2>/dev/null) || _tmpfile="/tmp/.safeline_bcrypt_$$"

        if command -v docker &>/dev/null; then
            docker run --rm -i node:20-alpine \
                node -e "const bcrypt=require('bcryptjs');let data='';process.stdin.setEncoding('utf8');process.stdin.on('data',c=>data+=c);process.stdin.on('end',async()=>{process.stdout.write(await bcrypt.hash(data.replace(/\r?\n$/, ''), 12));});" \
                <<< "$plain_password" > "$_tmpfile" 2>/dev/null
            if [ $? -eq 0 ] && [ -s "$_tmpfile" ]; then
                _result=$(cat "$_tmpfile")
                if printf '%s' "$_result" | grep -qE '^\$2[ab]\$[0-9]{2}\$'; then
                    rm -f "$_tmpfile"
                    printf '%s\n' "$_result"
                    return 0
                fi
            fi
            rm -f "$_tmpfile"
            echo "使用 Docker 生成 bcrypt 哈希失败，尝试本机 node 兜底" >&2
        fi

        if command -v node &>/dev/null; then
            node -e "const fs=require('fs');const path=require('path');const candidates=['/opt/safeline-waf/admin/backend/node_modules/bcryptjs','/opt/safeline-waf/admin/backend/node_modules','/opt/safeline-waf/node_modules/bcryptjs','bcryptjs'];let bcrypt=null;for(const candidate of candidates){try{if(candidate.endsWith('/node_modules')){bcrypt=require(path.join(candidate,'bcryptjs'));}else{bcrypt=require(candidate);}break;}catch(_) {}}if(!bcrypt){console.error('missing bcryptjs');process.exit(1);}const password=fs.readFileSync(0,'utf8').replace(/\r?\n$/, '');bcrypt.hash(password,12).then(hash=>process.stdout.write(hash)).catch(err=>{console.error(err.message);process.exit(1);});" \
                <<< "$plain_password" > "$_tmpfile" 2>/dev/null
            if [ $? -eq 0 ] && [ -s "$_tmpfile" ]; then
                _result=$(cat "$_tmpfile")
                if printf '%s' "$_result" | grep -qE '^\$2[ab]\$[0-9]{2}\$'; then
                    rm -f "$_tmpfile"
                    printf '%s\n' "$_result"
                    return 0
                fi
            fi
            rm -f "$_tmpfile"
        fi

        return 1
    }

    collect_interactive_admin_credentials() {
        while true; do
            read -r -p "请输入管理员用户名 [admin]: " admin_username
            admin_username=${admin_username:-admin}
            if [ -n "$admin_username" ]; then
                break
            fi
            warn "管理员用户名不能为空"
        done

        while true; do
            read -r -s -p "请输入管理员密码: " admin_password
            echo
            if [ -z "$admin_password" ]; then
                warn "管理员密码不能为空"
                continue
            fi
            if [ ${#admin_password} -lt 12 ]; then
                warn "管理员密码长度至少为 12 位"
                continue
            fi

            read -r -s -p "请再次输入管理员密码: " admin_password_confirm
            echo
            if [ "$admin_password" != "$admin_password_confirm" ]; then
                warn "两次输入的密码不一致，请重新输入"
                continue
            fi

            admin_password_hash=$(hash_password "$admin_password")
            if [ -z "$admin_password_hash" ]; then
                error "无法生成管理员密码哈希，请确认 Docker 或 Node 环境可用"
                exit 1
            fi

            admin_password=''
            admin_password_confirm=''
            break
        done
    }

    prepare_non_interactive_admin_credentials() {
        admin_username=${ADMIN_USERNAME:-admin}
        admin_password_hash=${ADMIN_PASSWORD_HASH:-}
        admin_password=${ADMIN_PASSWORD:-}

        if [ -n "$admin_password_hash" ]; then
            # 外部传入哈希时提前校验格式，给出明确错误而不是等到写入 .env 前才报
            if ! printf '%s' "$admin_password_hash" | grep -qE '^\$2[ab]\$[0-9]{2}\$'; then
                error "外部传入的 ADMIN_PASSWORD_HASH 格式无效（应以 \$2a\$ 或 \$2b\$ 开头）"
                exit 1
            fi
            return 0
        fi

        if [ -n "$admin_password" ]; then
            admin_password_hash=$(hash_password "$admin_password")
            admin_password=''
            if [ -z "$admin_password_hash" ]; then
                error "已提供 ADMIN_PASSWORD，但无法生成 bcrypt 哈希，请确认 Docker 或 Node 环境可用"
                exit 1
            fi
            return 0
        fi

        ENV_GENERATED_TEMP_PASSWORD=$(openssl rand -base64 18 | tr -d '\n' | tr '/+' 'AB')
        ENV_TEMP_PASSWORD_IS_GENERATED=1
        admin_password_hash=$(hash_password "$ENV_GENERATED_TEMP_PASSWORD")
        if [ -z "$admin_password_hash" ]; then
            error "无法为非交互安装生成临时管理员密码哈希，请确认 Docker 或 Node 环境可用"
            exit 1
        fi
    }

    if [ "$is_interactive" -eq 1 ]; then
        collect_interactive_admin_credentials
    else
        prepare_non_interactive_admin_credentials
    fi

    if [ "$ENV_ACTION" = "preserve" ] && [ "$ENV_EXISTED_BEFORE" -eq 0 ]; then
        info "已按升级初始化流程创建新的管理员凭据"
    fi

    jwt_secret=$(openssl rand -base64 48 | tr -d '\n')
    redis_password=$(openssl rand -hex 32)

    # 写入 .env 前严格校验哈希格式，防止任何非哈希值被写入
    if ! printf '%s' "$admin_password_hash" | grep -qE '^\$2[ab]\$[0-9]{2}\$'; then
        error "生成的管理员密码哈希格式无效（应以 \$2a\$ 或 \$2b\$ 开头），请确认 Docker 或 Node 环境可用"
        exit 1
    fi

    umask 177
    cat > "$env_file" <<EOF
JWT_SECRET=$jwt_secret
REDIS_PASSWORD=$redis_password
ADMIN_USERNAME=$admin_username
ADMIN_PASSWORD_HASH=$admin_password_hash
EOF
    chmod 600 "$env_file"

    ENV_WAS_REGENERATED=1
    admin_password=''
    admin_password_confirm=''

    success "已生成 $env_file"
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

    # compose up 失败时自动诊断并输出有用信息
    _diagnose_failure() {
        local compose_file="$1"
        echo
        error "======= 启动失败诊断 ======="

        # 1. 磁盘空间
        local disk_avail
        disk_avail=$(df -h /var/lib/docker 2>/dev/null | awk 'NR==2{print $4}')
        info "Docker 目录可用空间: ${disk_avail:-未知}"

        # 2. 端口占用
        for port in 80 443 8080; do
            if ss -tlnp 2>/dev/null | grep -q ":${port} " || \
               netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
                warn "端口 ${port} 已被占用:"
                ss -tlnp 2>/dev/null | grep ":${port} " || \
                netstat -tlnp 2>/dev/null | grep ":${port} "
            fi
        done

        # 3. 逐容器输出状态 + 末尾日志
        local containers
        containers=$(docker ps -a --filter "name=safeline-waf" --format "{{.Names}}\t{{.Status}}" 2>/dev/null)
        if [ -n "$containers" ]; then
            info "容器状态:"
            echo "$containers"
            echo
            while IFS=$'\t' read -r name status; do
                local health
                health=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}N/A{{end}}' "$name" 2>/dev/null)
                if echo "$status" | grep -qiE "exited|unhealthy|error"; then
                    error "[$name] 状态: $status  健康: $health"
                    info "--- $name 最后 30 行日志 ---"
                    docker logs --tail 30 "$name" 2>&1 | sed "s/^/  /"
                    echo
                    # 常见错误提示
                    local logs
                    logs=$(docker logs --tail 50 "$name" 2>&1)
                    if echo "$logs" | grep -qi "redis.*connect\|ECONNREFUSED.*6379"; then
                        warn "[$name] Redis 连接失败 → 检查 REDIS_PASSWORD / REDIS_HOST 环境变量"
                    fi
                    if echo "$logs" | grep -qi "JWT_SECRET\|invalid.*secret\|secret.*required"; then
                        warn "[$name] JWT_SECRET 未设置或过短（需 ≥ 32 字符）"
                        warn "       生成命令: openssl rand -hex 32"
                    fi
                    if echo "$logs" | grep -qi "EADDRINUSE\|address already in use"; then
                        warn "[$name] 端口被占用 → 检查是否有其他进程监听相同端口"
                    fi
                    if echo "$logs" | grep -qi "permission denied\|EACCES"; then
                        warn "[$name] 权限不足 → 检查挂载目录权限"
                    fi
                    if echo "$logs" | grep -qi "no space left\|ENOSPC"; then
                        error "[$name] 磁盘空间不足"
                    fi
                fi
            done <<< "$containers"
        fi

        error "============================"
        error "手动排查命令:"
        echo "  docker logs safeline-waf-admin-backend --tail 50"
        echo "  docker logs safeline-waf-nginx --tail 50"
        echo "  docker inspect safeline-waf-admin-backend | grep -A5 Health"
        echo
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
        _diagnose_failure "$PROD_COMPOSE"
        error "Docker 启动失败，请根据上方诊断信息排查"
        exit 1
    fi

    success "SafeLine WAF 已成功启动"
}

# 检查服务状态
check_status() {
    local prod_compose="/opt/safeline-waf/docker-compose.prod.yml"
    local compose_f=''
    local containers
    local container
    local status
    local name
    local health

    info "检查服务状态..."

    sleep 5

    [ -f "$prod_compose" ] && compose_f="-f $prod_compose"
    containers=$(docker_compose $compose_f ps -q)

    if [ -z "$containers" ]; then
        error "没有找到运行中的容器"
        exit 1
    fi

    for container in $containers; do
        status=$(docker inspect --format='{{.State.Status}}' "$container")
        name=$(docker inspect --format='{{.Name}}' "$container" | sed 's/\///')
        health=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}N/A{{end}}' "$container")

        if [ "$status" != "running" ] || [ "$health" = "unhealthy" ]; then
            error "容器 $name 状态异常: status=$status health=$health"
            info "--- $name 最后 30 行日志 ---"
            docker logs --tail 30 "$container" 2>&1
            exit 1
        else
            info "容器 $name 正在运行 (health=$health)"
        fi
    done

    # 检查 Nginx 是否监听端口（优先 ss，回退 netstat）
    sleep 2
    local nginx_listening=''
    if docker exec safeline-waf-nginx ss -tlnp 2>/dev/null | grep -qE ':80'; then
        nginx_listening=1
    elif docker exec safeline-waf-nginx netstat -tlnp 2>/dev/null | grep -qE ':80.*LISTEN'; then
        nginx_listening=1
    fi

    if [ -z "$nginx_listening" ]; then
        warn "Nginx 似乎没有正确监听 80 端口"
    else
        success "Nginx 正在监听 80 端口"
    fi

    success "所有服务已启动并运行正常"
}

# 显示安装信息
show_info() {
    local env_file="/opt/safeline-waf/.env"
    local ip
    local admin_port
    local admin_username

    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    [ -n "$ip" ] || ip="127.0.0.1"

    admin_port=$(grep '^ADMIN_PORT=' "$env_file" 2>/dev/null | tail -n 1 | cut -d'=' -f2-)
    admin_port=${admin_port:-8080}

    admin_username=$(grep '^ADMIN_USERNAME=' "$env_file" 2>/dev/null | tail -n 1 | cut -d'=' -f2-)
    admin_username=${admin_username:-admin}

    echo
    echo "============================================================="
    echo -e "${GREEN}SafeLine WAF 安装完成${NC}"
    echo "============================================================="
    echo
    echo -e "安装模式: ${GREEN}$INSTALL_MODE_LABEL${NC}"
    echo -e "管理界面: ${GREEN}http://$ip:$admin_port${NC}"
    echo -e "管理用户名: ${GREEN}$admin_username${NC}"
    echo -e ".env 文件: ${GREEN}/opt/safeline-waf/.env${NC}"
    echo

    if [ "$ENV_TEMP_PASSWORD_IS_GENERATED" -eq 1 ] && [ -n "$ENV_GENERATED_TEMP_PASSWORD" ]; then
        echo -e "临时管理员密码: ${YELLOW}$ENV_GENERATED_TEMP_PASSWORD${NC}"
        echo "这是一次性引导密码，请首次登录后立即修改！"
        echo
        ENV_GENERATED_TEMP_PASSWORD=''
    elif [ "$INSTALL_MODE" = "upgrade" ] && [ "$ENV_WAS_REGENERATED" -eq 0 ]; then
        echo "本次升级保留了现有管理员凭据，密码未被重置，请使用升级前的密码登录。"
        echo
    elif [ "$ENV_WAS_REGENERATED" -eq 1 ]; then
        echo "管理员密码已重置为本次安装设置的新密码。"
        echo
    else
        echo "请使用现有管理员密码登录。"
        echo
    fi

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

    select_install_mode
    check_system
    install_dependencies
    clone_source
    prepare_config
    prepare_env
    build_and_run
    check_status
    show_info
}

# 执行主函数
main
