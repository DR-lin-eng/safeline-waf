# SafeLine WAF 防护系统 - 详细文档

## 目录

1. [概述](#概述)
2. [核心功能](#核心功能)
3. [系统架构](#系统架构)
4. [安装指南](#安装指南)
5. [配置指南](#配置指南)
6. [防护机制详解](#防护机制详解)
7. [常见问题](#常见问题)
8. [性能优化](#性能优化)
9. [API参考](#api参考)
10. [贡献指南](#贡献指南)

## 概述

SafeLine WAF 是一个基于 OpenResty (Nginx + Lua) 的高性能 Web 应用防火墙，专为防御各类网络攻击特别是 DDoS 攻击而设计。它提供全面的 HTTP/HTTPS 流量分析和防护功能，能够识别并阻止恶意请求，同时对正常用户的访问影响最小。

SafeLine WAF 的主要特点：

- **高性能**：基于 Nginx 和 OpenResty，能够处理高并发流量
- **智能防护**：采用多层防护策略，动态识别攻击行为
- **低误判**：通过多种验证机制减少误判，提高用户体验
- **易于管理**：提供直观的管理界面，方便配置和监控
- **可扩展**：支持自定义规则和插件扩展

## 核心功能

SafeLine WAF 提供以下核心防护功能：

### 流量控制与分析

- **真实浏览器检测**：识别并过滤非浏览器的自动化请求
- **环境监测**：识别可疑的请求环境
- **IP 速率限制**：限制单个 IP 的请求频率
- **IP 黑名单**：阻止已知的恶意 IP 地址
- **流量动态识别**：实时分析流量模式，识别异常行为

### DDoS 防护

- **URL 级 DDoS 防护**：针对特定 URL 的动态防护
- **Anti-CC 防护**：防止恶意的高频请求攻击
- **随机参数攻击防护**：识别使用随机参数和请求方法的 DDoS 攻击
- **慢速 DDoS 防护**：防止消耗服务器连接资源的慢速攻击

### 用户验证

- **验证码**：传统的字符验证码
- **滑块验证**：用户友好的滑块拖动验证
- **POW 工作量证明**：在检测到攻击时，要求客户端完成计算工作

### 客户端防护

- **JS 加密**：对客户端 JavaScript 进行加密，防止逆向分析
- **F12 防护**：阻止恶意用户使用开发者工具分析页面

### 其他功能

- **蜜罐系统**：设置陷阱链接，捕获恶意扫描行为
- **实时监控**：提供详细的流量统计和攻击日志
- **自动封禁**：根据攻击行为自动将 IP 添加到黑名单
- **集群管理**：支持多节点部署，实现高可用和负载均衡
  - 自动节点注册和心跳监控
  - 配置实时同步（Redis Pub/Sub）
  - 黑名单集群间自动同步
  - Web界面统一管理所有节点

## 系统架构

SafeLine WAF 采用模块化架构，主要由以下组件构成：

### 核心组件

1. **Nginx + OpenResty**：提供高性能的 HTTP 服务器和反向代理能力
2. **Lua 脚本引擎**：执行核心防护逻辑
3. **Redis**：存储状态、计数器和黑名单等数据
4. **管理系统**：Vue.js 前端 + Node.js 后端

### 数据流图

```
                           ┌───────────────┐
                           │    客户端     │
                           └───────┬───────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────┐
│                  SafeLine WAF                        │
│                                                      │
│   ┌───────────┐     ┌───────────┐     ┌──────────┐   │
│   │访问控制模块│ ─── │DDoS防护模块│ ─── │验证处理模块│   │
│   └───────────┘     └───────────┘     └──────────┘   │
│                                                      │
│   ┌───────────┐     ┌───────────┐     ┌──────────┐   │
│   │  Redis    │ ─── │状态和计数器│ ─── │  日志系统 │   │
│   └───────────┘     └───────────┘     └──────────┘   │
│                                                      │
└──────────────────────────┬──────────────────────────┘
                           │
                           ▼
                   ┌─────────────────┐
                   │  后端应用服务器  │
                   └─────────────────┘
```

### 模块交互

1. **访问控制模块**：检查请求的 IP、User-Agent 等基本信息，进行初步过滤
2. **DDoS 防护模块**：分析请求模式，检测可能的 DDoS 攻击
3. **验证处理模块**：当检测到可疑请求时，生成并验证验证码、滑块或 POW 挑战
4. **Redis 存储**：存储临时数据，如计数器、令牌和黑名单
5. **状态和计数器**：跟踪请求频率和模式
6. **日志系统**：记录请求和攻击信息

## 安装指南

### 系统要求

- **操作系统**：Linux（推荐 Ubuntu 20.04+、CentOS 7+）
- **CPU**：2+ 核心
- **内存**：4GB+ RAM
- **磁盘空间**：20GB+ 可用空间
- **软件**：Docker 和 Docker Compose

### 使用安装脚本快速部署

```bash
# 下载安装脚本
wget https://raw.githubusercontent.com/DR-lin-eng/safeline-waf/main/scripts/install.sh

# 添加执行权限
chmod +x install.sh

# 运行安装脚本
sudo ./install.sh
```

### 使用 Docker Compose 手动部署

1. 克隆代码仓库：

```bash
git clone https://github.com/DR-lin-eng/safeline-waf.git
cd safeline-waf
```

2. 配置环境：

```bash
# 创建必要的目录
mkdir -p config/sites logs
```

3. 启动服务：

```bash
docker-compose up -d
```

4. 验证安装：

访问 `http://您的服务器IP:8080` 登录管理界面。

默认管理员账号：
- 用户名：admin
- 密码：safeline123

## 配置指南

### 通过管理界面配置

1. 登录管理界面 `http://您的服务器IP:8080`
2. 首次登录后，建议修改默认密码
3. 在"站点管理"中添加新站点：
   - 填写域名
   - 设置后端服务器地址
   - 选择防护功能

### 站点配置项说明

#### 基本配置

- **域名**：网站的域名，例如 example.com
- **后端服务器**：实际应用服务器的地址，例如 http://192.168.1.10:8080
- **启用状态**：是否启用该站点的 WAF 防护

#### 防护功能

- **真实浏览器检测**：识别并过滤非浏览器的自动化请求
- **环境监测**：识别可疑的请求环境
- **IP 黑名单**：启用 IP 黑名单功能
- **全局速率限制**：限制单个 IP 的请求频率
- **DDoS 防护**：启用 DDoS 攻击防护
- **随机攻击防护**：识别随机参数和请求方法的攻击
- **Anti-CC 防护**：防止恶意的高频请求
- **JS 加密**：对客户端 JavaScript 进行加密
- **防止浏览器 F12**：阻止恶意用户使用开发者工具
- **蜜罐功能**：设置陷阱链接捕获恶意扫描
- **自动添加 IP 黑名单**：根据攻击行为自动封禁 IP
- **请求日志记录**：记录请求和攻击信息
- **流量动态识别**：实时分析流量模式

#### 验证方式

- **验证码**：传统的字符验证码
- **滑块验证**：用户友好的滑块拖动验证
- **工作量证明(POW)**：要求客户端完成计算工作
- **POW 基础难度**：工作量证明的基础难度级别(1-10)
- **POW 最大难度**：工作量证明的最大难度级别(1-15)

#### 验证方式关联

- **IP 地址**：验证结果与 IP 地址关联
- **User-Agent**：验证结果与 User-Agent 关联
- **Cookie**：验证结果与 Cookie 关联

## 防护机制详解

### URL 级 DDoS 防护

URL 级 DDoS 防护是 SafeLine WAF 的核心功能之一，它能够针对特定 URL 提供动态防护。

#### 工作原理

1. **URL 规范化**：将包含随机部分的 URL 转换为统一格式，便于统计和分析
2. **请求计数**：跟踪每个客户端对特定 URL 的请求频率
3. **动态阈值**：根据全局流量和历史数据动态调整阈值
4. **跨 IP 压力识别**：识别“多 IP 低频但总体高压”的集群型 DDoS（常见于浏览器 API 集群）
5. **行为分析**：分析客户端行为模式，识别异常行为
6. **请求特征分析**：分析请求头、参数等特征，识别自动化工具
7. **多级响应**：根据威胁级别采取不同的应对措施

#### 防护策略

当检测到可能的 DDoS 攻击时，系统会根据威胁级别采取以下措施：

1. **低威胁**：展示简单的验证码
2. **中威胁**：要求滑块验证
3. **高威胁**：要求完成工作量证明(POW)
4. **极高威胁**：直接拒绝请求并自动将 IP 添加到黑名单

#### 集群型 DDoS（浏览器 API）说明

这类攻击的典型特征是：**单个 IP 的请求频率并不高**，但在短时间内出现大量不同 IP（或大量浏览器实例）同时向同一 URL/接口发起请求，导致后端被打满。

SafeLine WAF 在 URL 级 DDoS 识别中新增了跨 IP 的全局压力判断：

- **global_burst**：短窗口内全局突发请求超过阈值（更贴近 DDoS“瞬时洪峰”）
- **unique_ip_surge**：短窗口内同一 URL 的唯一 IP 数异常增长（更贴近“浏览器集群/多 IP”）
- **global_pressure / global_hard**：全局持续高压/极高压（用于更激进的挑战与降级）

当触发上述“跨 IP 压力”原因时，系统会优先采用 **POW 工作量证明** 并支持 **短周期复验**（站点配置 `protection.ddos_reverify_window`，默认 120 秒），在不依赖单 IP 限速的情况下显著抬高每个浏览器的请求成本，从而提升流量清洗能力。

#### 关键参数（default_config.json -> ddos_protection）

以下参数用于调节 URL 级 DDoS 与“跨 IP 集群攻击”的识别阈值（将阈值设置为 `0` 可关闭对应分支）：

- `url_threshold` / `url_window`：单 IP 针对单 URL 的阈值与窗口
- `ip_threshold` / `ip_window`：单 IP 全部请求的阈值与窗口
- `global_threshold`：同一规范化 URL 的全局请求阈值（跨 IP 汇总）
- `global_hard_threshold`：全局极高压阈值（用于更激进的降级/挑战）
- `global_burst_window` / `global_burst_threshold`：短窗口突发阈值（更快触发全局防护）
- `unique_ip_window` / `unique_ip_threshold`：短窗口唯一 IP 统计与阈值（识别集群型流量）
- `unique_ip_track_start`：达到一定全局请求量后才开始统计唯一 IP（用于节省 shared dict 空间）

### 慢速 DDoS / 连接风暴防护

慢速 DDoS（如 Slowloris/慢速上传）以及连接风暴类攻击，往往不会表现为“单 IP 高 QPS”，而是通过 **大量连接** 或 **缓慢发送请求头/请求体** 来消耗 Nginx/后端连接资源。

SafeLine WAF 对这类攻击的处置思路是：

1. **Nginx 层优先兜底**：通过 `client_header_timeout / client_body_timeout / send_timeout` 等超时与连接限制，在 Lua 之前淘汰慢连接。
2. **Lua 层补充识别**：用 `ngx.var.connection` 统计窗口内的新连接数量（近似衡量连接风暴/慢速连接的开新连接压力），触发后优先 **POW** 或直接丢弃连接（444）。

#### 关键参数（default_config.json -> slow_ddos）

- `enabled`：是否启用慢速/连接风暴识别
- `connection_threshold`：窗口内“新连接数”阈值（触发后会挑战/限速/丢弃）
- `window`：统计窗口（秒）

> 说明：Lua 无法精确获取“并发连接数”，因此这里用“窗口内新连接数”作为近似指标；真正的并发连接限制建议同时在 Nginx 层配置 `limit_conn`。

### 源站回源保护（防 CF/CDN Bypass）

常见的 CF/CDN bypass 场景是：攻击者绕过 CDN，直接访问源站 IP（或通过 Host 伪造命中源站），导致 CDN 的清洗/速率限制失效。

SafeLine WAF 支持站点级的“仅允许可信代理回源”模式：

- 站点配置 `protection.origin_proxy_only_enabled: true` 时，只有当 `remote_addr` 属于 `trusted_proxies` 配置的网段才会放行。
- 配合 `trusted_proxies`（如 Cloudflare/自建LB 的 IP 段）即可实现“必须经由 CDN/LB 回源”。

> 注意：启用该功能前，请务必将 CDN/LB 的真实回源 IP 段写入 `trusted_proxies`，否则会误拦截正常用户。

### HTTP 多版本 / QUIC / WebSocket 支持

- **HTTP/1.1**：默认支持；反代也以 HTTP/1.1 为基础（便于 WebSocket/长连接）。
- **HTTP/2**：需要在站点 server 中启用 `listen 443 ssl http2;` 并配置证书。
- **HTTP/2 防护建议**：优先升级到包含 Rapid Reset（CVE-2023-44487）修复的版本；再结合 `http2_max_concurrent_streams/http2_max_header_size/http2_recv_timeout` 等指令（视版本支持情况）收紧资源上限。
- **HTTP/3 (QUIC)**：需要 Nginx/OpenResty 编译启用 QUIC/HTTP3（当前默认镜像可能不支持）。本项目的配置模板提供了注释示例，供你在更换/自编译镜像后启用。
- **WebSocket**：站点反代模板已加入 `Upgrade/Connection` 头与长超时，确保 WS 正常穿透；同时 WAF 在需要验证时不会对 WS 做 302 跳转（WS 握手无法跟随跳转）。

### 工作量证明 (POW) 机制

POW 是一种高效的防护机制，特别适用于防御大规模 DDoS 攻击。它要求客户端执行一定量的计算工作，这对普通用户几乎无感知，但会显著增加攻击者的成本。

#### 工作原理

1. **挑战生成**：服务器生成一个随机前缀和难度级别
2. **客户端计算**：客户端需要找到一个 nonce 值，使得 SHA-256(prefix + nonce) 的前 n 位为 0
3. **服务器验证**：服务器验证计算结果，验证通过后允许访问

#### 难度调整

系统会根据以下因素动态调整 POW 难度：

- **全局流量状况**：流量越大，难度越高
- **客户端历史行为**：可疑行为越多，难度越高
- **攻击强度**：检测到的攻击强度越大，难度越高

### 流量动态识别

流量动态识别功能通过实时分析流量模式，识别异常行为，是系统防御未知攻击的重要组成部分。

#### 识别维度

1. **请求频率**：分析请求的时间间隔和频率
2. **HTTP 方法分布**：分析 GET、POST 等方法的使用比例
3. **URL 分布**：分析访问的 URL 分布情况
4. **参数特征**：分析请求参数的特征和变化
5. **响应状态码**：分析响应状态码的分布
6. **客户端指纹**：分析客户端的特征指纹

#### 异常检测算法

系统使用多种算法进行异常检测：

1. **聚类分析**：将请求特征向量进行聚类，识别离群点
2. **时间序列分析**：分析请求时间序列的规律性
3. **熵值分析**：计算请求特征的熵值，识别异常分布
4. **行为模式匹配**：将客户端行为与已知攻击模式进行匹配

## 常见问题

### 1. WAF 影响网站性能吗？

SafeLine WAF 被设计为高性能防护系统，在正常情况下对性能影响很小（通常小于 5ms 的延迟）。系统使用多级缓存、共享内存和异步处理等技术来最小化性能影响。

### 2. 如何处理误判？

误判是所有 WAF 系统面临的挑战。我们通过以下方式减少误判：

- 多重验证机制，避免直接拒绝请求
- 基于用户行为的信誉系统
- 白名单机制
- 详细的日志，便于分析和调整

如果发现误判，可以：
1. 检查日志，找出触发规则
2. 调整相应规则的敏感度
3. 为特定 IP 或路径添加白名单

### 3. 如何配置 HTTPS？

要配置 HTTPS 支持，您需要：

1. 准备 SSL 证书文件
2. 将证书文件放入 `nginx/certs/` 目录
3. 在管理界面中为站点启用 HTTPS
4. 提供证书文件路径
5. 重启服务以应用更改

### 4. 系统日志在哪里？

日志文件位于以下位置：

- Nginx 访问日志：`logs/access.log`
- Nginx 错误日志：`logs/error.log`
- 应用日志：`logs/app.log`
- Docker 容器日志：使用 `docker logs safeline-waf-nginx` 查看

## 性能优化

### 硬件推荐

- **小型网站**：2 核 CPU, 4GB 内存
- **中型网站**：4 核 CPU, 8GB 内存
- **大型网站**：8+ 核 CPU, 16GB+ 内存

### Nginx 优化

编辑 `nginx/nginx.conf` 文件，调整以下参数：

```nginx
worker_processes auto;  # 设置为 CPU 核心数
worker_connections 10240;  # 增加连接数
worker_rlimit_nofile 65535;  # 增加文件描述符限制
```

### Redis 优化

编辑 `docker-compose.yml` 中的 Redis 配置，添加以下参数：

```yaml
command: redis-server --maxmemory 1gb --maxmemory-policy allkeys-lru
```

### Lua 脚本优化

- 使用共享内存缓存减少 Redis 查询
- 黑名单查询使用本地 LRU 缓存；可选启用 Bloom Filter（`default_config.json -> blacklist_bloom`）来减少“黑名单 miss”时的 Redis 访问
- 异步处理非阻塞操作
- 日志/统计写入 Redis 采用异步 timer（并受 `redis_logs_max_qps / redis_stats_max_qps` 限制），避免阻塞请求路径
- 减少不必要的计算

### 多核心自适应（新增）

`default_config.json` 新增 `adaptive_protection`：

- `enabled`：开启后在 Nginx init 阶段按 worker 数自动扩展 DDoS 阈值
- `cpu_cores_per_10k_rps`：容量估算参数（每 1 万 RPS 预估所需核心数）
- `verified_scrubbing_rps`：已完成验证用户在高压场景下的二次清洗限速（避免已验证流量拖垮后端）
- `global_hard_reverify_window`：`global_hard` 场景下的最短复验窗口
- `hard_drop_on_overload`：极限过载时优先 444 丢弃，保障集群稳定

运行时会写入：

- `runtime:worker_count`
- `runtime:ddos_url_threshold`
- `runtime:ddos_ip_threshold`
- `runtime:ddos_global_threshold`
- `runtime:ddos_global_hard_threshold`

这些 key 用于观察“多核心适配后”的实时阈值。

### 集群管理 / 主副部署（新增）

`default_config.json` 新增 `cluster`：

- `node_role`: `primary` 或 `secondary`
- `primary_api_url`: 从节点拉取主节点配置地址
- `nodes`: 节点列表（含 id / api_url / role / sync）
- `sync.config_interval`: 从节点拉取配置周期（秒）
- `sync.blacklist_interval`: 黑名单同步周期（预留）
- `sync.request_timeout_ms`: 节点间通信超时
- `sync.fanout_concurrency`: 主节点并发同步扇出（十几个节点推荐 4~8）
- `sync.retry_count`: 同步失败重试次数
- `sync.retry_backoff_ms`: 重试指数退避基准

### 十几个节点的推荐参数

当集群规模达到 10~20 节点时，建议：

- `sync.fanout_concurrency`: `6`
- `sync.request_timeout_ms`: `1500~2500`
- `sync.retry_count`: `2`
- `sync.retry_backoff_ms`: `200~400`

同步链路已支持：

- **并发扇出**：主节点并发向多个从节点下发
- **失败重试**：超时/网络波动自动重试
- **版本增量**：配置 hash 一致时从节点跳过重放（减少无效 reload）

主副建议：

1. 主节点 `node_role=primary`，维护统一配置并触发下发
2. 从节点 `node_role=secondary`，配置 `primary_api_url`
3. 开启 `cluster.enabled=true` 与 `cluster.sync.enabled=true`

管理后台新增“集群管理”页面，可查看节点健康、触发手动同步和查看多核心建议值。

## API 参考

SafeLine WAF 提供 RESTful API，便于与其他系统集成。

### 认证

所有 API 请求都需要通过 API 密钥进行认证：

```
Header: X-API-Key: your_api_key_here
```

### 主要 API 端点

- `GET /api/stats` - 获取统计数据
- `GET /api/sites` - 获取站点列表
- `PUT /api/sites/:domain` - 更新站点配置
- `GET /api/blacklist` - 获取黑名单
- `POST /api/blacklist` - 添加 IP 到黑名单
- `DELETE /api/blacklist/:ip` - 从黑名单中删除 IP
- `GET /api/logs` - 获取日志
- `GET /api/runtime/profile` - 获取多核心运行建议
- `GET /api/cluster/node` - 获取当前节点信息
- `GET /api/cluster/status` - 获取集群状态
- `POST /api/cluster/sync` - 主节点手动下发配置到从节点
- `POST /api/cluster/sync/config` - 从节点接收配置同步
- `POST /api/cluster/sync/blacklist` - 从节点接收黑名单同步

详细 API 文档请参考 `/docs/api.md`。

## 集群部署

SafeLine WAF 支持多节点集群部署，实现高可用和负载均衡。

### 集群架构

```
                    ┌─────────────┐
                    │   负载均衡   │
                    └──────┬──────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
   ┌─────────┐        ┌─────────┐       ┌─────────┐
   │ WAF节点1 │        │ WAF节点2 │       │ WAF节点3 │
   └────┬────┘        └────┬────┘       └────┬────┘
        │                  │                  │
        └──────────────────┼──────────────────┘
                           │
                    ┌──────▼──────┐
                    │    Redis    │
                    │  (共享存储)  │
                    └─────────────┘
```

### 集群特性

- **自动节点发现**：节点启动时自动注册到Redis
- **实时心跳监控**：30秒心跳间隔，90秒超时检测
- **配置实时同步**：通过Redis Pub/Sub广播配置变更
- **黑名单同步**：集群间自动同步IP黑名单
- **统一管理界面**：Web界面查看所有节点状态

### 部署步骤

#### 1. 准备共享Redis

所有节点必须连接到同一个Redis实例：

```bash
# 启动Redis（或使用现有Redis）
docker run -d \
  --name safeline-redis \
  -p 6379:6379 \
  redis:7-alpine \
  redis-server --requirepass your-redis-password
```

#### 2. 配置环境变量

在每个节点创建 `.env` 文件：

**节点1 (.env):**
```bash
# Redis配置（所有节点相同）
REDIS_PASSWORD=your-redis-password

# 集群配置
CLUSTER_ENABLED=true
NODE_ID=node-1
NODE_ROLE=worker
HEARTBEAT_INTERVAL=30

# 认证配置（所有节点相同）
JWT_SECRET=your-strong-jwt-secret-at-least-32-chars
ADMIN_PASSWORD_HASH=$2a$12$...
```

**节点2 (.env):**
```bash
# Redis配置（所有节点相同）
REDIS_PASSWORD=your-redis-password

# 集群配置（NODE_ID必须不同）
CLUSTER_ENABLED=true
NODE_ID=node-2
NODE_ROLE=worker
HEARTBEAT_INTERVAL=30

# 认证配置（所有节点相同）
JWT_SECRET=your-strong-jwt-secret-at-least-32-chars
ADMIN_PASSWORD_HASH=$2a$12$...
```

#### 3. 启动节点

在每个节点上执行：

```bash
docker-compose up -d
```

#### 4. 验证集群状态

访问任意节点的管理界面：`http://节点IP:8080`

进入"集群管理"页面，查看所有节点状态。

### 集群操作

#### 查看节点状态

在管理界面的"集群管理"页面可以看到：
- 节点ID和主机名
- 在线/离线状态
- 最后心跳时间
- 节点版本信息

#### 配置同步

当在任意节点修改配置后，点击"重载所有配置"按钮，配置会自动同步到所有节点。

#### 黑名单同步

在任意节点添加IP黑名单后，会自动同步到所有节点。

### 故障处理

#### 节点离线

- 节点离线超过90秒会被标记为离线状态
- 节点离线超过5分钟会被自动清理
- 节点恢复后会自动重新注册

#### Redis故障

- 节点会继续使用本地配置运行
- Redis恢复后，节点会自动重新连接
- 建议使用Redis哨兵或集群模式提高可用性

### 性能建议

- **节点数量**：根据流量规模部署3-10个节点
- **Redis配置**：建议使用Redis哨兵或集群模式
- **网络延迟**：节点与Redis之间延迟应小于10ms
- **负载均衡**：使用Nginx/HAProxy等进行流量分发

## 贡献指南

我们欢迎社区贡献，无论是功能开发、bug 修复还是文档改进。

### 贡献步骤

1. Fork 仓库
2. 创建特性分支：`git checkout -b my-new-feature`
3. 提交更改：`git commit -am 'Add some feature'`
4. 推送到分支：`git push origin my-new-feature`
5. 提交 Pull Request

### 代码风格

- Lua 代码遵循 [lua-style-guide](https://github.com/Olivine-Labs/lua-style-guide)
- JavaScript 代码遵循 ESLint 配置
- 所有新功能必须包含测试用例
- 所有 Pull Request 必须通过 CI 测试

---

## 许可证

SafeLine WAF 使用 MIT 许可证，详见 [LICENSE](LICENSE) 文件。
