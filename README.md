# Sui Guardian

一个面向 Sui 项目方的链上异常监控 MVP，用于尽早发现潜在黑客事件或安全异常。

## 当前能力
- 按 checkpoint 增量扫描 Sui GraphQL RPC
- 监控 package 升级
- 监控关键地址大额异常流出
- 监控高危函数越权调用
- 监控关键包交易热度突增
- 监控失败交易突增
- 告警去重与事件化聚合（按规则聚合为 incident）
- 告警状态流转：open / acknowledged / resolved
- 控制台 / Webhook 输出
- 扫描历史记录与运行指标
- 本地 Web 控制台
- HTTP API 查询状态、告警与扫描记录
- Overflow 2026 提交就绪度检查
- AI 合约分析与动态规则启用
- Slack / Discord / 通用 Webhook 告警格式

## 为什么先用 GraphQL
Sui 官方文档已经明确建议逐步迁移到 gRPC / GraphQL RPC，并强调生产环境不要依赖公共 JSON-RPC。这个仓库先用 GraphQL 做 MVP，同时把数据接入层抽象出来，后续可以切换为 gRPC 或自建 indexer。

## Overflow 2026 定位
本项目参考 Sui Overflow 2026 Participant Handbook 完善，主赛道定位为 DeFi & Payments，副线能力为 Agentic Web。

提交叙事：
- 面向 Sui DeFi 项目方的实时安全监控产品
- 从 package、vault、treasury、oracle、admin function、异常资金路径到 incident response 的闭环
- AI 从 Move 代码与链上部署信息生成增量监控规则，降低项目方接入成本

手册强调 meaningful products、real-world applications、long-term ecosystem growth；因此最终演示应使用真实 mainnet/testnet 配置和一次成功扫描作为证据，而不是只展示离线规则。

## 本地运行
```bash
npm install
npm run scan:once
npm run test
npm run dev
```

生产式启动：
```bash
npm run build
npm start
```

推荐 Overflow 演示链路：
```bash
npm run demo:overflow
```

真实主网只读验证：
```bash
npm run mainnet:deepbook:scan
npm run build
npm run mainnet:deepbook
```

评委快速验证：
```bash
npm run build
npm run demo:overflow
```

可选告警通知闭环：
```bash
npm run webhook:sink
ALERT_WEBHOOK_URL=http://127.0.0.1:8787/webhook npm run demo:overflow
```

详见：
- `docs/judge-quickstart.md`
- `docs/mainnet-onboarding.md`
- `runbooks/overflow-demo.md`

单漏洞演练验证模块：
```bash
npm run lab:vuln-defi
```

说明：
- 演练验证模块保留，用于数据完整性验证、规则回归验证和链路演练
- 这些脚本和配置不参与默认运行，也不应作为生产界面的数据来源
- `lab:defi-range` 会在 Sui testnet 发布一个多漏洞 DeFi range，生成监控配置，触发攻击序列，并输出 dashboard URL 与 `runbooks/latest-defi-range.json`

默认配置：
- `config/default.yml`
- HTTP 地址：`http://0.0.0.0:3000`
- Dashboard：`http://127.0.0.1:3000/`
- 注意：默认配置不再内置任何示例/测试监控对象，必须由你显式填入真实项目配置后才会启用监控规则

## HTTP 接口
### 页面
- `GET /`
- `GET /dashboard`

### API
- `GET /api/health`
- `GET /api/state`
- `GET /api/config`
- `GET /api/metrics`
- `GET /api/readiness`
- `GET /api/alerts?status=&projectId=&severity=&limit=`
- `GET /api/scans?limit=`
- `GET /api/incidents?limit=`
- `GET /api/assets?projectId=`
- `GET /api/projects`
- `POST /api/scan`
- `POST /api/projects`
- `DELETE /api/projects/:id`
- `POST /api/analyze`
- `PATCH /api/alerts/:id/status`

兼容保留：
- `GET /health`
- `GET /state`
- `GET /config`
- `GET /alerts`
- `POST /scan`

## 自定义配置
复制一份示例模板并改成你的真实协议地址：
```bash
cp config/projects.example.yml config/my-project.yml
npm run scan:once -- --config config/my-project.yml
```

如果你直接使用默认 `config/default.yml`，系统会启动，但不会加载任何项目规则，也不会再使用示例数据。

建议至少填以下内容：
1. 关键 package
2. treasury / vault / admin 地址
3. 敏感函数 allowlist
4. 流量与失败阈值
5. 允许升级 sender

## AI 规则生成（Testnet）
这个模块用于：从本地 Move 源码 + testnet 链上行为样本自动生成 `projects[*]` 的增量规则片段，写入 `.data/generated/<projectId>/current.yml`，监控进程会在运行中自动热加载。

### 1) 发布到 Testnet 并生成 deployments manifest
```bash
npm run ai:deploy:testnet -- /Users/seem/Downloads/sui-defi-main interest-protocol
```

输出：
- `.data/deployments/interest-protocol.json`

### 2) 生成规则片段（写入本地 generated 目录）
```bash
OPENAI_API_KEY=... \
OPENAI_BASE_URL=https://ai.immortality.top \
OPENAI_MODEL=gpt-5.4 \
npm run ai:generate -- \
  --projectId interest-protocol \
  --projectName "Interest Protocol" \
  --sourceRoot /Users/seem/Downloads/sui-defi-main \
  --deploymentsPath .data/deployments/interest-protocol.json \
  --generatedDir .data/generated \
  --graphqlEndpoint https://graphql.testnet.sui.io/graphql
```

输出：
- `.data/generated/interest-protocol/current.yml`
- `.data/generated/interest-protocol/meta/current.json`

### 3) 在监控配置中开启热加载
在你的监控配置文件里加入：

```yml
aiRules:
  enabled: true
  generatedDir: .data/generated
  reloadIntervalMs: 60000
  shadow:
    enabled: true
    notify: false
    minMinutes: 60
  canary:
    enabled: true
    stage: shadow
    promotionMinMinutes: 60
```

然后正常启动监控即可：

```bash
npm run dev -- --config config/my-project.yml
```

## 目录
- `src/`：监控服务源码
- `scripts/run_vuln_defi_lab.py`：演练验证脚本，仅用于手动校验
- `config/`：默认配置、真实项目模板与演练配置
- `docs/research.md`：Sui 监控研究笔记
- `docs/overflow-submission.md`：Overflow 2026 参赛提交说明
- `docs/judge-quickstart.md`：评委两分钟验证流程
- `docs/mainnet-onboarding.md`：真实主网项目接入路径
- `docs/deepbook-mainnet-config.md`：DeepBook V3 mainnet 只读接入说明
- `docs/open-source-references.md`：可商用参考项目清单
- `docs/architecture.md`：当前架构设计
- `runbooks/overflow-demo.md`：推荐给评委看的 testnet 演示脚本
- `runbooks/`：实验记录与最新实验结果
- `.data/state.json`：本地状态、事件与扫描历史

## 生产模式说明
- 默认运行只读取真实配置和真实链上数据
- 若未配置真实项目，界面只显示空态，不展示任何 demo 或 generated 数据
- 演练配置必须显式传入，且不参与默认运行

## 当前更适合演示/商用交流的能力
- 项目方可以直接打开本地 Dashboard 看事件中心
- 同一条规则触发会被聚合成一个 incident，而不是刷屏式重复消息
- 告警支持人工确认和关闭，便于安全团队值班流转
- 扫描质量可视化，可用于给客户解释“最近跑了哪些链上数据”
- Dashboard 会显示 Overflow 提交就绪度，用于最后检查真实项目配置、主网路径、扫描证据、通知渠道和 AI 规则能力

## Overflow 提交前检查
```bash
npm run typecheck
npm run test
npm run scan:once -- --config config/my-project.yml
npm run dev -- --config config/my-project.yml
```

然后打开 `http://127.0.0.1:3000/`，确认：
1. `Overflow 提交就绪度` 没有 required failure
2. 至少有一次成功扫描记录
3. 配置摘要展示了真实 package / treasury / function guard
4. 告警处置流可以完成 acknowledge 或 resolve
5. 若展示 Agentic Web 能力，AI 分析面板可以生成并启用规则

## 下一步建议
- 接 Postgres / TimescaleDB
- 增加 Telegram / Email / 企业微信告警
- 增加 gRPC 数据源
- 增加多租户与权限系统
- 增加对象快照 diff、资金画像和动态阈值
- 增加误报标注、事件归并和 case management
