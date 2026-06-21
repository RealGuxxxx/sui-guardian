# 可参考的开源项目与组件

以下清单按“可商业参考价值”筛选，优先选择 Apache-2.0 / MIT 等宽松许可。

## 1. MystenLabs/sui
- 仓库：https://github.com/MystenLabs/sui
- 许可：Apache-2.0
- 价值：Sui 官方核心仓库，包含 full node、gRPC、GraphQL、indexer、checkpoint 相关实现。
- 你应该重点看：
  - `crates/sui-indexer-alt-framework`
  - `crates/sui-rpc-api/src/grpc`
  - `crates/sui-indexer-alt-graphql`
- 适合借鉴的层：数据摄取、checkpoint 驱动处理、官方字段语义。
- 不建议直接照搬的层：整套基础设施复杂度较高，MVP 阶段没必要直接上 Rust 全栈。

## 2. amnn/sui-sender-indexer
- 仓库：https://github.com/amnn/sui-sender-indexer
- 许可：Apache-2.0
- 价值：基于 `sui-indexer-alt-framework` 的最小可运行样例。
- 适合借鉴的层：
  - 如何围绕 checkpoint 做索引
  - 如何把链上结果写入数据库
- 对当前项目的意义：后续从 Node MVP 升级到 Rust 高吞吐 indexer 时，这个 repo 很适合作为过渡模板。

## 3. FrankC01/pysui
- 仓库：https://github.com/FrankC01/pysui
- 许可：Apache-2.0
- 价值：成熟的 Python Sui SDK。
- 适合借鉴的层：Python 侧数据采集、脚本化安全巡检、批量地址/对象检查。
- 对当前项目的意义：如果后续要做安全研究脚本、离线回放分析、规则实验，Python 生态会很方便。

## 4. forta-network/forta-bot-sdk
- 仓库：https://github.com/forta-network/forta-bot-sdk
- 许可：MIT
- 价值：虽然主要面向 EVM，但其“检测机器人 -> 发现 -> 告警”架构非常值得借鉴。
- 适合借鉴的层：
  - 检测规则封装
  - Finding/Alert 数据结构
  - 告警去重、严重性分级、机器人健康检查
- 对当前项目的意义：我们可以借它的产品架构思想，而不是链路实现。

## 5. bytewax/bytewax
- 仓库：https://github.com/bytewax/bytewax
- 许可：Apache-2.0
- 价值：流式处理框架。
- 适合借鉴的层：
  - 高频数据流规则计算
  - 滚动窗口 / 状态计算
  - 后续异常评分与行为画像
- 对当前项目的意义：当规则从几十条扩展到上百条、且需要复杂窗口统计时，可以考虑引入。

## 6. @mysten/sui（npm 包）
- 来源：https://www.npmjs.com/package/@mysten/sui
- 包元数据许可：Apache-2.0
- 价值：官方 TypeScript API。
- 备注：目前 Sui 官方文档强调应迁移到 gRPC/GraphQL RPC，因此商业产品最好把 SDK 作为可替换适配层，而不要把架构锁死在旧式 JSON-RPC 上。

## 商业化使用建议
### 推荐直接吸收
- MystenLabs/sui 的接口定义与索引范式
- Forta 的告警建模思想
- Bytewax 的窗口计算思路

### 生产边界要求
- 演练配置不得进入默认展示链路
- 默认 Dashboard 与 API 只应展示真实项目配置对应的数据
- 演练脚本只能作为手动验证工具，不应成为生产页面的数据来源

### 推荐谨慎吸收
- 任意 GPL/AGPL 的监控项目实现
- 未声明 license 的 Sui 第三方 indexer 仓库
- 直接复制协议业务逻辑代码

### 结论
如果目标是“尽快做一个可商用的 Sui 安全异常预警产品”，最现实的技术路线是：
1. 先用 GraphQL / checkpoint 做 Node.js MVP
2. 再补 Postgres、前端与告警中心
3. 最后把高吞吐采集层切换为 gRPC 或 Rust 自定义 indexer
