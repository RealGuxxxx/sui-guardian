# Sui Guardian 架构说明 v0.2

## 1. 架构原则
- 先做可解释的安全规则，不先上黑盒模型
- 数据接入与规则引擎解耦，方便后续从 GraphQL 切到 gRPC
- 监控对象要显式配置：package、管理员地址、treasury、敏感函数
- 所有告警必须附带可回放的 on-chain 证据
- 告警不只“触发”，还要能进入事件化处置流

## 2. 当前架构

### 数据层
- 数据源：Sui GraphQL RPC
- 增量方式：按 checkpoint 顺序扫描
- 当前持久化：本地 JSON state 文件
- 当前持久化内容：
  - last checkpoint
  - package version snapshot
  - incident alerts
  - scan history
- 后续建议：Postgres + Redis
- 生产模式要求：默认只读取真实项目配置与真实状态文件，不加载任何 demo / generated 运行数据

### 计算层
- Checkpoint Poller
  - 读取最新 checkpoint
  - 拉取未处理 checkpoint 列表
  - 拉取 checkpoint 内交易并标准化
- Project Monitor
  - 按项目配置执行规则
  - 维护短周期窗口状态
- Rule Families
  - PackageUpgradeRule
  - AddressOutflowRule
  - FunctionGuardRule
  - TrafficSpikeRule
  - FailureSpikeRule
- Incident Aggregator
  - 将同类规则命中聚合成 incident
  - 支持 occurrence 计数
  - 支持 open / acknowledged / resolved

### 输出层
- 控制台输出
- Webhook 输出
- Fastify HTTP API
  - `GET /api/health`
  - `GET /api/state`
  - `GET /api/config`
  - `GET /api/metrics`
  - `GET /api/readiness`
  - `GET /api/alerts`
  - `GET /api/scans`
  - `POST /api/scan`
  - `PATCH /api/alerts/:id/status`
- 本地 Dashboard
  - 事件中心
  - 扫描历史
  - 配置摘要
  - 手动触发扫描
  - Overflow 提交就绪度
- 空态策略
  - 未配置真实项目时显示空态
  - 不在默认界面展示实验项目或演练样本数据

## 3. 数据模型
### 监控项目配置
一个项目至少包含：
- 关键 package 列表
- 关键资金地址列表
- 敏感函数 allowlist
- 热度突增阈值
- 失败交易突增阈值

### 标准化交易
系统将链上交易统一转换为：
- digest
- checkpoint
- timestamp
- sender / gas sponsor
- 调用链（package/module/function）
- balance changes
- object changes
- 执行状态与报错

这样规则层不关心底层来自 GraphQL 还是 gRPC。

### Incident Alert
每条告警事件当前包含：
- severity
- status
- fingerprint
- firstSeenAt / lastSeenAt
- occurrences
- summary / details
- 处置 note

这让系统具备“监控 -> 预警 -> 处置”的最小闭环。

### Submission Readiness
`GET /api/readiness` 根据当前配置与运行状态生成参赛提交检查摘要：
- DeFi & Payments / Agentic Web 赛道定位
- 真实项目配置、核心规则覆盖、主网路径、成功扫描证据
- 通知渠道、AI 规则生成、旧包漏洞调用监控等增强项
- README、架构文档、配置模板和 Overflow 提交说明的材料清单

## 4. 为什么 package version 检测很关键
在 Sui 生态里，攻击不一定总是“立即盗走资金”，还可能先表现为：
- 升级权限被异常使用
- 包版本在非维护窗口被更新
- 更新 sender 不在授权清单内

所以 package version monitor 应该始终存在，而且严重级别通常要高于一般资金异动。

## 5. 当前版本的局限
- 仍然依赖轮询，不是实时流式消费
- 仍然使用本地 JSON 状态文件，不适合正式多租户生产
- 告警 fingerprint 目前按 projectId + ruleId 聚合，后续需要更细粒度策略
- 还没有资金可视化、对象生命周期 diff、地址画像与基线学习

## 6. 下一阶段演进
### v0.3
- 切换 Postgres
- 增加 Telegram/Slack/企业微信模板
- 增加历史窗口基线
- 增加对象快照 diff

### v0.4
- 增加 gRPC 适配器
- 增加多租户
- 增加仪表盘权限控制
- 增加告警归并、抑制、升级

### v0.5
- 引入统计异常评分
- 引入地址画像、风险标签
- 引入回放沙箱与审计面板

## 7. 演练验证模块边界
- 演练验证模块保留，用于链路回归、数据完整性验证和规则效果验证
- 演练配置只能显式触发，不参与默认运行
- 默认 Dashboard 与 API 只展示真实项目配置对应的数据
