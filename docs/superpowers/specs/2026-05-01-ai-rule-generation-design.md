# AI 规则生成与热加载（Testnet）设计

## 背景

`sui-guardian` 当前采用“配置驱动 + 内置检测逻辑”的模式：YAML 配置描述监控对象与阈值，执行链路负责扫描交易、提取证据并产出告警。配置 schema 与归一化逻辑集中在 [config.ts](file:///Users/seem/Desktop/sui-guardian/src/config.ts#L26-L362)，项目级规则在 [types.ts](file:///Users/seem/Desktop/sui-guardian/src/types.ts#L4-L243) 中定义。

本设计在不改变“规则以 YAML 表达并由现有执行引擎消费”的前提下，引入云端大模型（OpenAI API）对项目 Move 源码与链上行为进行分析，自动生成可审计、可回滚、可热加载的监控规则。

目标网络为 Testnet。

## 目标

- 自动识别“值得监控”的函数、对象、地址，并生成可直接落地的 YAML 规则片段。
- 基于链上历史行为对阈值进行分层窗口校准，并支持每周重算与升级触发重算。
- 规则热加载：监控进程在不停机的情况下应用新规则，支持 shadow/canary 与自动回滚。
- 产物可解释、可审计：每条规则可追溯到静态依据与动态统计依据。

## 非目标

- 不让模型生成或执行代码插件（不生成 detector 代码、不动态执行任意脚本）。
- 不追求全网盲扫；仍然以“项目接入”维度运行。
- 不改变链上数据抓取方式（仍沿用现有 GraphQL 扫描与对象刷新机制）。

## 约束与原则

- 规则输出必须严格受 [AppConfig](file:///Users/seem/Desktop/sui-guardian/src/types.ts#L245-L260) 与相关配置结构约束；任何不符合 schema 的内容拒绝生效。
- 规则生成使用“结构化 JSON → 本地转换为 YAML”的方式，避免模型直接输出 YAML 引入语法/缩进/注释歧义。
- 不在仓库中存储任何 API Key；仅通过环境变量注入。

## 高层架构

### 组件

- Rule Generator（独立进程/任务）
  - 输入：Move 源码、部署 manifest、分层窗口链上历史样本、历史告警与抑制信息。
  - 输出：`generated/<projectId>/current.yml` 与 `generated/<projectId>/meta/current.json`（含版本与证据摘要），并保留版本历史。
- Monitor（现有 sui-guardian 进程）
  - 定期扫描链上数据并生成告警。
  - 新增：加载/合并 generated 规则片段、热更新 project monitors、shadow/canary/回滚。

### 数据流

1. 部署到 testnet，生成 deployments manifest（packageId、upgradeCap、创建对象等）。
2. Rule Generator 解析 Move 源码，生成静态 facts（函数入口、权限点、关键对象字段候选等）。
3. Rule Generator 拉取链上行为样本（7/30/90 天分层），计算统计特征（分位数阈值、失败率基线、资金净流分布等）。
4. Rule Generator 调用 OpenAI，要求输出严格 schema 的 JSON ruleset + 解释。
5. 本地校验 JSON ruleset → 转换为 YAML → 写入 generated 目录（带版本号）。
6. Monitor 发现 generated 更新 → 合并入运行时配置 → 进行 shadow/canary → 正式生效或自动回滚。

## 输入与对齐

### 源码输入

本地源码根路径：

- `/Users/seem/Downloads/sui-defi-main`

该仓库为多包结构，至少包含：

- `clamm/Move.toml`（示例：[Move.toml](file:///Users/seem/Downloads/sui-defi-main/clamm/Move.toml)）
- `airdrop/Move.toml`
- `launchpad/Move.toml`
- `i256/Move.toml`
- `library/Move.toml`（示例：[Move.toml](file:///Users/seem/Downloads/sui-defi-main/library/Move.toml)）

静态分析以 Move 源码为主，允许结合 `Move.toml` addresses 映射与依赖信息进行解析。

### 部署对齐（Testnet）

需要将每个要监控的 package 发布到 testnet，并把发布输出固化为一个 deployments manifest。manifest 作为“源码 ↔ 链上”的唯一对齐锚点。

建议路径：

- `.data/deployments/<projectId>.json`

建议结构：

```json
{
  "projectId": "interest-clamm",
  "network": "testnet",
  "publishedAt": "2026-05-01T00:00:00Z",
  "publisher": "0x...",
  "packages": [
    {
      "label": "clamm",
      "packageId": "0x...",
      "upgradeCapId": "0x...",
      "dependencies": ["0x2", "0x1"],
      "createdObjects": {
        "pool_factory": "0x...",
        "config": "0x..."
      }
    }
  ],
  "notes": ""
}
```

生成方式：通过 `sui client publish --json` 解析 `objectChanges` 中 `published` 与 `created` 项提取 packageId、UpgradeCap 与关键对象。

## 静态 facts 规范（供模型与审计使用）

Rule Generator 必须先产出一份可审计的事实表（facts），再将其作为模型输入的一部分：

```json
{
  "projectId": "interest-clamm",
  "packages": [
    {
      "label": "clamm",
      "packageId": "0x...",
      "modules": [
        {
          "name": "vault",
          "entryFunctions": [
            {
              "name": "withdraw",
              "params": ["&mut Vault", "Coin<SUI>", "..."],
              "writes": ["Vault.balance", "Vault.admin"],
              "transfersCoin": true,
              "capabilityGated": true,
              "riskTags": ["funds_outflow", "permissioned"]
            }
          ]
        }
      ],
      "capabilities": [
        {
          "name": "AdminCap",
          "creation": "init",
          "consumedBy": ["set_admin", "pause", "upgrade"],
          "notes": ""
        }
      ],
      "keyObjects": [
        {
          "label": "vault_config",
          "type": "0x...::vault::Config",
          "fieldCandidates": ["admin", "fee_bps", "paused", "treasury", "oracle_id"]
        }
      ]
    }
  ]
}
```

静态 facts 需要尽量来源可解释：来自源码 AST/编译信息、已知关键 API 使用模式、以及显式的 capability 检查逻辑。

## 动态统计（分层窗口）

动态侧以 testnet 链上行为为依据，分层窗口为：

- 7 天：用于 `trafficSpikes`、`failureSpikes` 的阈值拟合与冷却策略。
- 30 天：用于 `protectedAddresses` 资金净流出阈值拟合、sender 基线、对象字段变化频率。
- 90 天：用于 `priceModels` 与 `objectBaselines` 的长期基线。

统计输出必须结构化且可复现，建议落盘：

- `.data/generated/<projectId>/meta/stats.json`

核心统计项示例：

- 按函数（package/module/function）统计：txCount、uniqueSenders、失败率、分位数（p50/p90/p95/p99）。
- 按 protected 地址统计：净流出分布（按 coinType）、top senders、分位数阈值。
- 按关键对象字段统计：变化频率、maxDelta、min/max、关联 sender 分布。

## 模型调用（OpenAI）

### 输出协议

模型输出必须是 JSON，且满足本地 schema（与 AppConfig 对齐的子集）。

模型输出顶层结构建议：

```json
{
  "version": "2026-05-01T12:00:00Z",
  "projectId": "interest-clamm",
  "rules": {
    "packages": [],
    "protectedAddresses": [],
    "functionGuards": [],
    "trafficSpikes": [],
    "failureSpikes": [],
    "trackedObjects": [],
    "priceModels": [],
    "objectBaselines": [],
    "suspiciousTargets": [],
    "behaviorRules": {
      "enabled": true,
      "minRepeatedCalls": 2,
      "minProtectedOutflow": "1",
      "priceDeviationThresholdBps": 1500
    },
    "flowTracking": {
      "enabled": true,
      "minProtectedOutflow": "1",
      "attackerGainThreshold": "1",
      "shortWindowTxCount": 2
    },
    "suppression": {
      "enabled": true,
      "duplicateWindowSeconds": 600,
      "weakSignalScoreThreshold": 35,
      "maintenanceWindows": []
    }
  },
  "explanations": [
    {
      "ruleId": "functionGuard:withdraw",
      "summary": "…",
      "staticEvidence": ["…"],
      "dynamicEvidence": ["…"],
      "confidence": 0.78,
      "recommendedSeverity": "high"
    }
  ]
}
```

本地将 `rules` 转换为 YAML 片段，并将 `explanations` 写入 meta 文件。

### 提示词结构

输入建议包含以下区块：

- 系统约束：只能生成 JSON、只能使用允许字段、必须满足 schema、不得臆造地址。
- deployments manifest（链上对齐信息）。
- 静态 facts（函数/权限/对象候选）。
- 动态统计（分位数、失败率、净流出分布、对象字段变化分布）。
- 当前告警偏好：先中庸，先跑一周后自动调参。

### 安全与隐私

- 不上传私钥、助记词、完整本地文件内容。
- 源码输入原则上只上传“摘要 facts”，而非整个源码文件；必要时仅上传与高危入口相关的片段，并脱敏无关信息。

## generated 目录规范（本地规则存储）

根目录建议：

- `.data/generated/`

布局：

- `.data/generated/<projectId>/current.yml`
- `.data/generated/<projectId>/versions/<version>.yml`
- `.data/generated/<projectId>/meta/current.json`
- `.data/generated/<projectId>/meta/versions/<version>.json`
- `.data/generated/<projectId>/meta/stats.json`

写入必须满足原子性：先写临时文件，再 rename 覆盖 `current.yml` 与 `meta/current.json`，避免 Monitor 读到半成品。

## 配置合并与校验

### 合并策略

- 基础配置来自 `config/default.yml` 或用户指定 `--config`。
- generated 规则片段按 `projectId` 定位到目标 project：
  - 允许新增规则条目与覆盖阈值/白名单；
  - 不允许删除用户手工配置的关键项（例如手工指定的 protectedAddresses 与 allowedSenders）。

### 校验策略

- 合并后必须走与 [loadConfig](file:///Users/seem/Desktop/sui-guardian/src/config.ts#L348-L362) 同等强度的 zod 校验与地址规范化。
- 校验失败：
  - 不应用本次更新；
  - 标记为 failed 版本并记录原因；
  - 若是首次生成失败，维持仅手工配置运行。

## 热加载与运行态切换

### 检测变更

Monitor 以固定周期扫描 `.data/generated/**/current.yml` 的 mtime 或内容哈希，发现变更则进入更新流程。

### Shadow / Canary

- Shadow：新规则版本先进入“记录但不通知”模式；记录告警、风险评分、与上一版本的差异。
- Canary：通过 shadow 后，按规则类型逐步放量：
  - 第一阶段：traffic/failure
  - 第二阶段：trackedObjects/objectBaselines/priceModels
  - 第三阶段：protectedAddresses/functionGuards

### 自动回滚

触发条件（任一满足则回滚到上一稳定版本）：

- 单位时间告警量较 shadow 基线暴涨超过阈值。
- duplicate/suppression 后仍出现告警风暴。
- 校验失败或 generated 文件不可读。

回滚必须是原子切换：恢复上一版本的 merged config 与 project monitors。

## 重算策略

- 周期重算：每周固定运行一次（由外部调度或进程内定时器触发）。
- 升级触发：当监控检测到 package upgrade 或 package address 变更时，触发一次重算。
- 运行成本控制：重算任务与 Monitor 扫描解耦，避免影响扫描 tick。

## 评估指标

- 有效性：关键攻击/风险事件覆盖率（在测试场景与回放数据上度量）。
- 稳定性：告警速率、误报率代理指标（重复率、短期无后续风险证据占比）、回滚触发次数。
- 可解释性：每条 high/critical 告警是否具备静态与动态证据摘要。
- 性能：重算耗时、链上采样请求量、对 Monitor 扫描延迟的影响（应接近 0）。

## 测试计划

- 单元测试：
  - schema 校验（模型输出 JSON → 规则对象 → YAML）应覆盖边界与拒绝路径。
  - 合并策略（generated 覆盖/新增但不删除手工关键项）。
- 集成测试（testnet）：
  - 发布一个已知合约包，生成 deployments manifest。
  - 生成一份规则并在 Monitor 中热加载。
  - 人为制造流出/失败尖峰/敏感函数调用，验证规则命中与 shadow/canary/回滚逻辑。

## 风险与缓解

- 模型幻觉导致错误规则：严格 schema + 本地校验 + shadow/canary + 自动回滚。
- 规则漂移导致告警不稳定：分层窗口统计 + “先中庸后调参” + 抑制与冷却默认启用。
- 数据泄露：不上传密钥；源码尽量转换为 facts；必要片段脱敏。

