# 检测引擎重型增强设计

## 目标

将 `sui-guardian` 从“以规则命中为主的监控器”升级为“以多源证据和风险评分为核心的链上事态感知引擎”。

本次改造聚焦四项重型能力：

- 真实价格偏离计算
- 对象字段基线
- 资金路径图
- 误报抑制

本轮优先目标是“更准”，即优先降低误报和漏报，而不是优先追求最小改动或最低检测时延。

## 非目标

- 不在本轮引入新的外部数据库；继续使用现有状态文件持久化
- 不把系统改造成全量链上索引器；只围绕已配置项目和其关联对象做定向画像
- 不在本轮引入机器学习模型；误报抑制仍采用可审计的显式策略
- 不替换现有 API 和 Dashboard 主体结构；以增量扩展证据与评分字段为主

## 当前问题

现有行为检测能力已经能发现部分攻击闭环，但核心判定仍偏启发式，主要问题如下：

1. `priceDeviationBps` 仍是阈值占位，不是来自真实状态或真实参考价格
2. “闪电贷式攻击”主要依赖函数名关键词，不是基于真实资金注入、状态操纵、价值提取的路径闭环
3. 对关键对象只检测“发生变化”，未建立“正常基线”与“异常偏离”之间的差异模型
4. 告警抑制只有简单 cooldown，缺少地址画像、维护窗口、重复事件去噪和证据置信度控制

这些问题导致系统更像规则监控器，而不是能解释“为什么异常、异常程度多高、为什么不是误报”的事态感知引擎。

## 方案比较

### 方案 A：证据评分引擎

做法：

- 为每笔交易提取多类独立证据
- 将证据送入统一风险评分器
- 由评分器决定告警等级、置信度和抑制结果

优点：

- 最适合“更准”的目标
- 便于持续增加新证据类型
- 每条告警都能保留完整解释链

缺点：

- 类型、状态和测试面会显著扩展
- 初次实现复杂度高于规则树方案

### 方案 B：增强规则树

做法：

- 保持 `buildDerivedSignals()` + `runBehaviorRules()` 结构
- 把四项能力继续以条件判断方式堆叠进去

优点：

- 改动小
- 现有代码接入速度快

缺点：

- 难以维护
- 难以统一解释与抑制
- 后续仍会继续膨胀

### 方案 C：双阶段检测

做法：

- 第一阶段实时粗检
- 第二阶段异步补证与复核

优点：

- 兼顾实时和复杂计算

缺点：

- 系统时序更复杂
- 当前轮的首要目标是“更准”，不值得先引入异步二阶段复杂度

## 结论

采用方案 A。

即：

- 将“价格偏离、对象基线、资金路径、误报抑制”都视为一等证据
- 由统一风险评分器综合多个证据后输出最终风险结论
- 现有规则引擎继续保留，但降级为“消费证据”的上层策略，而不是唯一判断来源

## 目标架构

检测链路升级为五层：

1. `Normalizer`
2. `Signal Extractors`
3. `Evidence Store`
4. `Risk Scorer`
5. `Incident Builder`

### 1. Normalizer

沿用现有 GraphQL 拉取和交易标准化逻辑，继续输出：

- `calls`
- `balanceChanges`
- `objectChanges`
- `status`
- `executionError`

同时增加为后续证据层准备的补充信息：

- 交易内的对象地址集合
- 可参与资金路径图构建的 owner 和 coin 关系
- 与 tracked object 的关联映射

### 2. Signal Extractors

新增四类提取器：

- `price-deviation extractor`
- `object-baseline extractor`
- `fund-flow-graph extractor`
- `false-positive-suppression extractor`

每个提取器只负责输出本领域证据，不直接决定最终 severity。

### 3. Evidence Store

在现有运行时状态之上新增以下持久化画像：

- 对象字段基线
- 地址画像
- 资金边历史
- 价格参考基线
- 抑制策略状态

这些数据继续保存在状态文件中，以项目为边界隔离。

### 4. Risk Scorer

统一接收所有证据并输出：

- `riskScore`
- `confidence`
- `severityRecommendation`
- `suppressionDecision`
- `evidenceSummary`

风险评分器负责：

- 证据加权
- 证据冲突处理
- 误报降级
- 最终告警升级与抑制

### 5. Incident Builder

将评分结果映射到现有：

- `Alert`
- `IncidentAlert`
- incident timeline
- asset / field / fund flow evidence

Dashboard 不再只展示“命中了什么规则”，而是同时展示：

- 为什么判定为异常
- 证据来自哪里
- 哪些证据提升了风险
- 哪些上下文抑制了误报

## 模块拆分

建议新增目录：

- `src/detection/price-deviation.ts`
- `src/detection/object-baseline.ts`
- `src/detection/fund-flow-graph.ts`
- `src/detection/false-positive-suppression.ts`
- `src/detection/risk-scorer.ts`

建议改造现有文件职责：

- `src/project-monitor.ts`
  - 从“规则执行器”变为“检测编排器”
  - 调用 extractor、risk scorer 和现有基础规则
- `src/behavior-rules.ts`
  - 从“独立做启发式判断”调整为“消费评分结果和证据”
- `src/monitor-service.ts`
  - 管理增强后的状态持久化
  - 对外暴露更多证据字段
- `src/dashboard.ts`
  - 展示价格偏离依据、对象基线偏离、资金路径、抑制原因
- `src/types.ts`
  - 扩展证据、画像、评分和抑制相关类型

## 四项能力设计

### 1. 真实价格偏离计算

目标：

- 不再用固定阈值占位
- 对“对象内价格字段”和“交易内价值提取行为”建立真实关联

设计：

- 为每个项目增加价格参考定义，可来自：
  - tracked object 的字段值
  - 同项目内指定对象字段组合
  - 可选的人工配置参考区间
- 在每次扫描中读取相关对象快照，形成：
  - `observedPrice`
  - `referencePrice`
  - `deviationBps`
  - `priceSource`
- 当同一交易引起价格字段突变，且随后出现提取行为、借贷行为或核心地址净流出时，将该偏离视为高风险证据

判定逻辑：

- 若有实时参考值，则以实时参考值为准
- 若无外部参考值，则使用对象历史滑动中位数和最近稳定窗口作为内部参考
- 当偏离超过阈值但没有配套价值提取，只记录异常，不直接升级为 critical
- 当偏离超过阈值且出现价值提取、异常资金路径或对象权限变化时，显著提升评分

输出证据：

- `priceEvidence.observedPrice`
- `priceEvidence.referencePrice`
- `priceEvidence.deviationBps`
- `priceEvidence.referenceKind`
- `priceEvidence.extractionCoupled`

### 2. 对象字段基线

目标：

- 让系统知道“这个对象平时应该怎样变化”
- 区分“正常业务更新”与“异常状态漂移”

设计：

- 对每个 tracked object 建立字段级 baseline profile
- baseline 不是单值，而是字段行为画像，包含：
  - 最近稳定值
  - 历史最小值 / 最大值
  - 变化频率
  - 最近变化方向
  - 允许变更 sender 集
- 区分字段类型：
  - 权限字段：如 `admin`, `owner`, `cap`
  - 价格字段：如 `price`, `rate`
  - 库存字段：如 `vault`, `liquidity`, `reserves`
  - 状态字段：如 `paused`, `mode`

判定逻辑：

- 权限字段变更默认高权重
- 库存类字段若单次下降超过基线容忍区间，记为流失异常
- 状态字段若在短窗口内频繁翻转，记为控制异常
- 允许 sender 白名单命中时降低权重，但保留证据

输出证据：

- `baselineEvidence.field`
- `baselineEvidence.previousValue`
- `baselineEvidence.currentValue`
- `baselineEvidence.expectedRange`
- `baselineEvidence.anomalyKind`
- `baselineEvidence.senderAuthorized`

### 3. 资金路径图

目标：

- 把“关键词像闪电贷”升级为“真实价值如何进入、流经、流出”

设计：

- 从单笔交易的 `balanceChanges` 构建 directed flow graph
- 节点包括：
  - sender
  - gas sponsor
  - protected addresses
  - tracked object related addresses
  - 其他 owner
- 边包括：
  - `from`
  - `to`
  - `coinType`
  - `amount`
  - `role`

其中 `role` 取值包括：

- `temporary_funding`
- `manipulation_target`
- `protected_outflow`
- `attacker_receipt`
- `intermediate_hop`

判定逻辑：

- 若交易内或短窗口内出现“临时注资 -> 关键对象状态/价格变化 -> 受保护地址流出 -> 攻击者获益”的闭环，则形成高权重攻击路径证据
- 若只是简单资金流出但无状态操纵和异常受益，不自动判定为攻击闭环
- 资金路径与对象基线、价格偏离交叉验证时提升置信度

输出证据：

- `flowEvidence.nodes`
- `flowEvidence.edges`
- `flowEvidence.attackPathFound`
- `flowEvidence.pathRoles`
- `flowEvidence.netProtectedOutflow`
- `flowEvidence.netAttackerGain`

### 4. 误报抑制

目标：

- 不让“合法运维”“常规再平衡”“受控升级”“重复扫描同一事件”被过度升级

设计：

- 引入显式抑制器，不删除原始证据，只调整最终风险输出
- 抑制来源包括：
  - sender 画像
  - 维护窗口
  - 历史重复事件
  - 已知授权路径
  - 多证据冲突

抑制策略：

- `authorized_sender_suppression`
- `maintenance_window_suppression`
- `duplicate_incident_suppression`
- `expected_rebalance_suppression`
- `weak_single_signal_suppression`

判定逻辑：

- 单一弱证据且无资金获利闭环时，优先降级而非报警
- 已授权 sender 即使触发权限类字段变化，也保留 medium/high 的审计告警，而不是直接 critical
- 同一时间窗口、同一对象、同一 sender、同一 anomaly kind 的重复事件合并计数，不重复升级

输出证据：

- `suppression.applied`
- `suppression.reasons`
- `suppression.originalSeverity`
- `suppression.finalSeverity`
- `suppression.confidencePenalty`

## 数据模型变更

`src/types.ts` 预计新增以下核心类型：

- `DerivedEvidence`
- `PriceDeviationEvidence`
- `ObjectBaselineEvidence`
- `FundFlowGraph`
- `FundFlowEdge`
- `SuppressionDecision`
- `RiskScore`
- `ObjectBaselineProfile`
- `AddressBehaviorProfile`
- `PriceReferenceProfile`

`MonitoringProjectConfig` 预计新增以下配置块：

- `priceModels`
- `objectBaselines`
- `flowTracking`
- `suppression`

原则：

- 配置只声明项目关注点和阈值
- 运行时画像和历史基线不放入静态配置，而放入状态文件

## 运行时状态变更

`RuntimeState` 预计新增：

- `objectBaselineProfiles`
- `addressBehaviorProfiles`
- `priceReferenceProfiles`
- `flowHistory`
- `suppressedAlertCache`

要求：

- 以项目维度隔离
- 能在重启后恢复基线
- 对历史窗口做裁剪，避免状态无限增长

## 风险评分设计

评分器采用显式加权，不使用黑箱模型。

建议输出：

- `riskScore`: 0 到 100
- `confidence`: 0 到 1
- `recommendedSeverity`: `info | low | medium | high | critical`

建议加权思路：

- 价格偏离且伴随价值提取：高权重
- 权限字段突变：高权重
- 资金攻击闭环成立：高权重
- 单一对象轻微偏移：低到中权重
- 被抑制命中：降低评分和置信度，但保留审计痕迹

严重度建议：

- `0-19`: 不报警，仅更新画像
- `20-39`: `info/low`
- `40-59`: `medium`
- `60-79`: `high`
- `80-100`: `critical`

## 告警与可解释性

每条高等级告警必须能回答四个问题：

1. 发生了什么
2. 为什么异常
3. 资金如何流动
4. 为什么不是普通业务行为

因此 alert details 需要扩展：

- 价格偏离摘要
- 关键字段偏离摘要
- 资金路径摘要
- 抑制与未抑制原因
- 风险分数与置信度

Dashboard 新增或强化展示：

- 价格偏离依据
- 对象字段基线偏离
- 攻击路径 / 资金路径
- 抑制原因
- 评分结果

## 错误处理

- 缺失对象快照时，不中断整笔交易处理；将相关证据标记为 `incomplete`
- 参考价格缺失时，回退到历史内部基线，不直接抛弃价格模块
- 资金路径无法完整还原时，只输出部分 flow evidence，不强行推断攻击闭环
- 状态文件中的画像损坏或缺失时，允许重新冷启动学习，但要降低对应证据置信度

## 测试策略

测试分五层：

1. extractor 单元测试
2. risk scorer 单元测试
3. `ProjectMonitor` 集成测试
4. `MonitorService` 状态持久化回归测试
5. Dashboard / API 证据渲染测试

必须覆盖的重点场景：

- 真实价格偏离但无提取，不应直接 critical
- 价格偏离 + 价值提取 + 资金闭环，应升级为 high/critical
- 授权 sender 修改权限字段，应保留审计但降低严重度
- 非授权 sender 修改权限字段，应高权重命中
- 同类重复事件应被聚合和抑制
- 缺失部分 GraphQL 数据时，检测链路不崩溃

## 分阶段实施建议

建议按以下顺序实现：

1. 扩展类型、配置和状态模型
2. 实现对象字段基线与价格偏离 extractor
3. 实现资金路径图 extractor
4. 实现误报抑制器和统一评分器
5. 改造 `ProjectMonitor` 和 `behavior-rules.ts`
6. 扩展 `MonitorService`、API 和 Dashboard
7. 补齐回归测试与真实靶场验证

这样可以先让“真实证据”落地，再把最终评分和展示串起来。

## 风险与缓解

- 风险：状态模型增长过快导致状态文件膨胀
  - 缓解：对画像、边历史和抑制缓存设置窗口和裁剪策略

- 风险：配置复杂度上升，项目接入门槛变高
  - 缓解：为新增配置提供默认值，并保持向后兼容

- 风险：评分器阈值不合理导致前期噪声偏高
  - 缓解：保留原始证据，先做保守权重并通过靶场回归校准

- 风险：路径图还原不完整时误推断攻击闭环
  - 缓解：将“不完整图”与“已证实闭环”明确分开编码

## 实施范围

预计涉及：

- `src/types.ts`
- `src/config.ts`
- `src/project-monitor.ts`
- `src/behavior-rules.ts`
- `src/monitor-service.ts`
- `src/dashboard.ts`
- `src/server.ts`
- `tests/`
- 新增 `src/detection/`

## 自检结论

- 无占位符、无 TBD
- 架构、数据模型、评分、抑制和测试边界一致
- 范围适合拆成单次实现计划，但实现时应按阶段推进
