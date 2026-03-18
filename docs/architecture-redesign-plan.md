# SafeLine WAF 架构重做计划

> 生成时间：$(date)
> Codex 会话：019cfa72-0104-7aa2-98d0-3a2bfe0a8229
> 策略：方案3 — 控制面/数据面分离，版本化快照，统一 challenge/telemetry

## 核心架构决策

| # | 决策 |
|---|------|
| D1 | 策略配置改为不可变快照，控制面只编译发布，数据面只读消费 |
| D2 | Nginx reload 只用于 TLS/upstream 拓扑变更，Lua 策略更新不依赖 reload |
| D3 | Challenge 改为服务端状态机，统一 challenge_id + redirect token + verification grant 三段模型 |
| D4 | 所有 DDoS/行为分析基于 RequestContext + RequestTelemetry，禁止模块自行重复 ngx.req.get_*() |
| D5 | Bloom filter 改为 base snapshot + realtime delta overlay + compaction |
| D6 | Redis 拆成 4 命名空间：快照(DB0)、挑战(DB1)、运行时索引(DB2)、遥测流(DB3) |

## 执行批次与依赖图

```
批次A（可立即并行）
  ├── A-1: 核心公共层 common + request_context + snapshot_store     [Task #2]
  ├── A-2: 统一 Challenge 服务层                                     [Task #4]
  └── A-3: 遥测层 + 运行时索引层                                     [Task #3]
         ↓ 全部完成后
批次B（A完成后并行）
  ├── B-1: 检测器层 detectors/*                                     [Task #5]
  └── B-2: 策略引擎 + 控制面快照编译器                               [Task #7]
         ↓ 全部完成后
批次C（B完成后并行）
  ├── C-1: access.lua 重写 + header/body filter 修复                [Task #6]
  ├── C-2: 旧模块迁移（薄包装层重构）                                [Task #9]
  ├── C-3: 基础设施加固（Docker + Redis + Nginx）                   [Task #10]
  └── C-4: init / init_worker 重写（定时器体系）                    [Task #8]
         ↓ 全部完成后
批次D（C完成后并行）
  ├── D-1: admin 后端/前端接入快照体系                               [Task #11]
  └── D-2: POW 客户端 JS 重写 + 验证页面优化                        [Task #12]
         ↓ 全部完成后
批次E
  └── E:   集成测试 + 回归验证                                       [Task #13]
```

## 新目录结构

```
nginx/lua/
├── core/
│   ├── common.lua              # 公共函数（原6处重复）
│   ├── request_context.lua     # 一次性采集请求数据
│   ├── snapshot_store.lua      # 只读访问版本化快照
│   └── policy_engine.lua       # 统一决策引擎
├── challenge/
│   ├── challenge_service.lua   # 统一 challenge 入口
│   └── providers/
│       ├── captcha_provider.lua
│       ├── pow_provider.lua
│       └── slider_provider.lua
├── detectors/
│   ├── protocol_detector.lua
│   ├── browser_detector.lua
│   ├── ddos_detector.lua
│   └── blacklist_detector.lua
├── telemetry/
│   ├── request_telemetry.lua
│   └── telemetry_flush.lua
├── runtime/
│   └── blacklist_index.lua     # Bloom base+delta overlay
├── static/
│   ├── verify.html             # POW Web Worker 重写
│   ├── pow-worker.js
│   └── sha256.min.js
└── [现有文件改为薄包装层]

admin/backend/
├── snapshot_compiler.js        # 新增
├── snapshot_publisher.js       # 新增
└── app.js                      # 接入快照体系
```

## 关键安全修复清单

| 项目 | 严重度 | 批次 |
|------|--------|------|
| 滑块位置硬编码可绕过 | P0 | A-2 |
| POW 多Tab覆盖 challenge | P0 | A-2 |
| POW JS HTTP 下 crypto.subtle 失效 | P0 | D-2 |
| 默认密码哈希暴露在仓库 | P0 | C-3 |
| Token 未绑定站点作用域 | P0 | A-2 |
| Bloom filter 新增IP漏拦窗口 | P0 | A-3 |
| Reload 期间防护空洞 | P0 | B-2 |
| body_filter 无限缓冲 | P1 | C-1 |
| 注入脚本破坏 CSP nonce | P1 | C-1 |
| 缺少 HSTS 注入 | P1 | C-1 |

## 回归测试矩阵（批次E）

- [ ] captcha/pow/slider 完整流程
- [ ] 快照原子切换无请求失败
- [ ] 实时拉黑 delta overlay 命中
- [ ] DDoS 检测准确性
- [ ] Token 站点绑定隔离
- [ ] 安全绕过防护（固定position、重放challenge_id）
- [ ] IPv6 请求处理
- [ ] 大页面（>10MB）body_filter 跳过注入
