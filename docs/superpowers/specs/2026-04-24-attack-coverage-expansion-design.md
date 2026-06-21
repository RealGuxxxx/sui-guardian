# 攻击覆盖扩展设计

## 目标

在现有“证据评分引擎”基础上，新增一层系统化的攻击覆盖框架，使 `sui-guardian` 同时具备：

- 对已知主流 DeFi / 合约攻击族的高覆盖识别能力
- 对未知攻击、变种攻击和组合攻击的异常发现能力
- 对多笔交易攻击链的拼接和解释能力

本子工程优先目标不是承诺“识别所有攻击”，而是把平台升级成：

- 已知攻击可枚举覆盖
- 未知攻击可异常发现
- 高危事件可证据解释
- 新攻击族可持续扩展

## 非目标

- 不在本轮引入机器学习模型或外部风控平台
- 不承诺对未来所有零日攻击做绝对识别
- 不构建全链通用索引器，只围绕接入项目和其关联对象做定向分析
- 不重写已有风险评分、价格偏离、对象基线、资金路径和误报抑制模块

## 当前问题

当前平台已经有：

- 基础规则
- 行为规则
- 价格偏离
- 对象字段基线
- 资金路径图
- 误报抑制

但仍存在三个结构性缺口：

1. 已知攻击覆盖不完整，攻击族缺少统一矩阵和统一检测器接口
2. 未知攻击主要依赖少量异常信号，尚未形成“异常包”与“攻击链”输出
3. 多笔交易组合攻击、治理类攻击、桥消息类攻击、清算类攻击等没有单独建模

## 设计原则

### 1. 攻击族优先于单条规则

平台不再只新增若干零散规则，而是按攻击族建模。每个攻击族统一定义：

- 前置条件
- 关键行为
- 结果证据
- 误报抑制条件
- 告警模板

### 2. 已知攻击与未知攻击共用证据层

已知攻击检测器和未知攻击异常检测器都消费同一套底层证据：

- 调用链
- 价格偏离
- 对象字段基线
- 资金路径
- 地址画像
- 时间窗口行为

### 3. 交易级与攻击链级同时存在

检测结果分为两层：

- `transaction-level detection`
- `incident-chain detection`

即：单笔交易先产出证据和初判，多笔交易再聚合成攻击链。

### 4. 可扩展优先

每个新攻击族都应只新增一个检测器文件和对应测试，不需要改动整个引擎结构。

## 方案比较

### 方案 A：攻击矩阵 + 检测器注册表

做法：

- 为每类攻击建立独立 detector
- 由统一注册表调度所有 detector
- detector 输出标准化的 attack evidence

优点：

- 扩展性最好
- 测试边界清晰
- 最适合长期增加更多攻击族

缺点：

- 初始实现文件数会增加

### 方案 B：继续堆叠在 `behavior-rules.ts`

做法：

- 所有新增攻击继续写入 `runBehaviorRules()`

优点：

- 改动小

缺点：

- 极易膨胀
- 难维护
- 不利于攻击族统一建模

### 方案 C：单独做“异常检测器”而不是攻击检测器

做法：

- 不区分具体攻击族，只做异常打分和风险聚合

优点：

- 对未知攻击更友好

缺点：

- 对已知攻击可解释性不足
- 用户想看的“识别更多攻击类型”不够直观

## 结论

采用方案 A，并保留异常检测器作为其中一类 detector。

即：

- 已知攻击 detector 和未知攻击 detector 共用统一注册机制
- 所有 detector 输出统一证据结构
- `ProjectMonitor` 不再只编排“行为规则”，而是编排“攻击检测器 + 风险评分”

## 攻击覆盖矩阵

本轮先覆盖以下攻击族：

### A. 权限与控制类

- 非授权敏感调用
- 管理员替换 / owner takeover
- Package 升级 / 治理升级劫持
- 维护窗外高权限操作

### B. 价值操纵类

- 预言机价格操纵
- 抵押率 / 借贷参数操纵
- 清算阈值操纵
- 滑点缺失导致的异常成交

### C. 流动性与资金抽取类

- 金库异常流出
- 池子库存短时异常下跌
- 闪电贷闭环攻击
- 多步资金转移后的攻击者净获利

### D. 交互与执行类

- 任意外部目标调用
- 可疑 router / target 交互
- 重复敏感调用 / 重入式重复执行
- 失败探测后紧随成功抽取

### E. 组合与未知攻击类

- 多笔交易攻击链
- 同 sender / 同对象 / 同时间窗的异常升级
- 多信号共振但无法归类的未知高危异常

## 新架构

新增目录：

- `src/detectors/registry.ts`
- `src/detectors/types.ts`
- `src/detectors/known/`
- `src/detectors/anomaly/`
- `src/detectors/chain/`

建议文件拆分：

- `src/detectors/types.ts`
  - detector 上下文
  - detector 输出
  - attack category 类型
- `src/detectors/registry.ts`
  - 注册所有 detector
  - 按项目配置启用 detector
- `src/detectors/known/permission-detector.ts`
  - 权限接管、管理替换、非授权敏感操作
- `src/detectors/known/price-manipulation-detector.ts`
  - 预言机、价格、借贷参数操纵
- `src/detectors/known/liquidity-drain-detector.ts`
  - 金库抽取、库存异常下降、攻击者净获利
- `src/detectors/known/execution-abuse-detector.ts`
  - 重复执行、探测后抽取、任意目标调用
- `src/detectors/anomaly/unknown-attack-detector.ts`
  - 多证据共振但不匹配已知攻击模板的异常
- `src/detectors/chain/incident-chain-detector.ts`
  - 跨交易拼接攻击链

## 核心数据流

新的检测流为：

1. `GraphQL client` 拉取交易与对象快照
2. `ProjectMonitor` 构造底层证据
3. detector registry 运行所有启用 detector
4. detector 产出 `AttackFinding[]`
5. findings 进入风险评分器
6. 风险评分和抑制结果进入事件中心
7. `MonitorService` 聚合成 incident chain
8. Dashboard 展示攻击类型、证据链、画像偏移和资金路径

## 检测器接口

每个 detector 统一使用如下模型：

- 输入：
  - `project`
  - `tx`
  - `derived evidence`
  - `runtime profiles`
  - `recent alerts / incident context`
- 输出：
  - `attackType`
  - `category`
  - `summary`
  - `evidence`
  - `riskHints`
  - `chainHints`

原则：

- detector 不直接写最终 alert
- detector 只描述“发现了什么攻击迹象”
- severity 最终由风险评分和抑制层决定

## 已知攻击 detector 设计

### 1. Permission Detector

识别：

- 非授权敏感函数调用
- 管理员字段变化
- 非维护窗内高权限操作
- Package / capability 控制变更

核心证据：

- function guard 命中
- baseline 中权限字段突变
- sender 不在授权集
- suppression 不命中或只部分命中

### 2. Price Manipulation Detector

识别：

- 预言机价格突变
- 价格突变后紧随借贷 / 提取 / 清算
- 价格突变与异常资金流相互印证

核心证据：

- `priceEvidence`
- `valueExtractionDetected`
- `flowEvidence`
- `baselineEvidence` 中价格字段异常

### 3. Liquidity Drain Detector

识别：

- 保护地址大额净流出
- 库存类字段短时异常下降
- 攻击者净获利
- 多步提取闭环

核心证据：

- `flowEvidence.netProtectedOutflow`
- `flowEvidence.netAttackerGain`
- `baselineEvidence` 中 inventory drop

### 4. Execution Abuse Detector

识别：

- 同一交易或短窗口重复敏感调用
- 失败探测后成功提取
- 可疑 target / router 调用
- 类重入的重复执行模式

核心证据：

- `sameSensitiveCallRepeats`
- failure spike
- suspicious targets
- 时间窗内相似 digests / sender / object 模式

## 未知攻击 detector 设计

### Unknown Attack Detector

目标：

- 当攻击不属于任何已知模板，但多个异常信号共振时，仍然给出高质量异常事件

触发条件示例：

- 价格偏离 + 权限变化 + 资金路径异常，但未命中已知模板
- 多个关键对象在短窗内同时异常
- sender 首次出现却完成高风险价值提取
- 多笔交易形成“探测 -> 操纵 -> 提取”的升级序列

输出：

- `attackType: unknown-coordinated-anomaly`
- 保留所有 evidence summary
- severity 由风险评分决定

## 攻击链检测

### Incident Chain Detector

目标：

- 将单笔 findings 拼成更完整的攻击过程

拼接维度：

- sender
- 受影响对象
- 资金接收地址
- 时间窗口
- attack hints

输出：

- `chainStage`
  - `probe`
  - `manipulation`
  - `takeover`
  - `extraction`
- `attackChainId`
- `chainConfidence`

Dashboard 最终应能展示：

- 本事件属于哪个攻击链
- 当前处于哪一阶段
- 由哪些交易组成

## 配置设计

`MonitoringProjectConfig` 继续扩展一层：

- `attackDetectors`

内容包括：

- `enabledAttackFamilies`
- `unknownAttackDetectionEnabled`
- `incidentChainEnabled`
- 各 detector 的阈值覆盖项

兼容性要求：

- 如果没有配置 `attackDetectors`
- 则默认启用与当前项目能力兼容的一组 detector

## Alert / Incident 展示扩展

每条事件新增或强化展示：

- `attackType`
- `attackCategory`
- `riskScore`
- `chainStage`
- `chainId`
- `evidenceSummary`
- `suppressionReasons`

资产视图继续展示：

- 对象当前快照
- 价格画像
- 字段基线

时间线继续强化：

- 交易级告警
- 事件级攻击链

## 测试策略

测试拆成六层：

1. detector 单元测试
2. detector registry 集成测试
3. `ProjectMonitor` findings 集成测试
4. `MonitorService` 攻击链聚合测试
5. API 返回结构测试
6. Dashboard 渲染测试

必须覆盖：

- 已知攻击族逐类命中
- 多 detector 同时命中时正确聚合
- 未知攻击异常正确升级
- 攻击链在多笔交易中正确拼接
- 授权维护操作被抑制
- 缺失部分对象快照时系统不崩

## 风险与缓解

- 风险：detector 数量增长后性能下降
  - 缓解：registry 做按项目配置启用；按攻击族短路；优先轻量 detector

- 风险：多 detector 同时命中导致重复告警
  - 缓解：先产生 findings，再统一评分与聚合，不让 detector 直接产 alert

- 风险：未知攻击 detector 误报偏高
  - 缓解：要求多证据共振，并受 suppression 约束

- 风险：攻击链拼接错误
  - 缓解：只对高置信度 sender / object / flow 交集做聚合

## 实施范围

预计涉及：

- `src/project-monitor.ts`
- `src/behavior-rules.ts`
- `src/monitor-service.ts`
- `src/server.ts`
- `src/dashboard.ts`
- `src/types.ts`
- `src/config.ts`
- 新增 `src/detectors/`
- `tests/`
- 靶场配置文件

## 范围边界

这是一个单独子工程，目标是“攻击覆盖扩展”。

后续仍建议拆出两个后续子工程：

- `异常检测增强`
- `跨项目攻击画像 / 学习闭环`

本轮不把三者一次性混做，避免范围失控。

## 自检结论

- 无 `TBD` / `TODO`
- 范围聚焦于攻击覆盖扩展
- 与现有证据评分引擎兼容
- 可直接进入实现计划阶段
