# Sui Testnet 漏洞 DeFi 监控实验记录

## 1. 实验目标
在 Sui testnet 上：
1. 部署一个故意脆弱的 DeFi 风格合约
2. 用 Sui Guardian 监控该合约的高危函数调用
3. 用非授权攻击地址发起攻击
4. 验证监控系统是否能产生告警

## 2. 链上实验对象
### 管理员地址
- `0xee4fefc8f5705100b4aebc51c96d62224b7f8281a77ab9c8a73bea4b34dd5c08`

### 攻击者地址
- `0xe437071484a9ab02e0ebf4f5f14bf113387baf5005a9170b4cf4683e3689e844`

### 脆弱 DeFi 包
- package: `0x16455ec38988402ec3db6646c6d3142fea96e673f1f08157841d5bd343d1add3`
- module: `insecure_lending`
- shared pool: `0x10e829908f3b74b805ce297c2de7b1af62ec1e2fbaff360bcb54ff0582ca7c8f`

## 3. 漏洞说明
合约中暴露了一个本应属于管理员的高危函数：
- `emergency_withdraw_all(pool, recipient)`

故意留下的漏洞：
- 没有任何 admin 权限校验
- 任意地址都可以把池子里的全部 SUI 转走

## 4. 关键交易
### 发布合约
- digest: `8KLm7EmsLxkGuG6AneXJMZm8bcJCchBBo4M6Uk8zZZip`

### 管理员注资 2 SUI
- digest: `AV2Q561K8KyNRatBATVQHXBZkJan6YGff7cdefFJWMc7`

### 攻击者盗走 2 SUI
- digest: `5sC96GcoxAk4EQXqPbvtEUrS5wTrt3NYTbhBCgRm5G8x`

## 5. 监控配置
监控配置文件：
- `/Users/seem/Desktop/sui-guardian/config/testnet-vuln-defi.yml`

监控规则：
- 关键包：`0x16455ec38988402ec3db6646c6d3142fea96e673f1f08157841d5bd343d1add3`
- 敏感函数守卫：`insecure_lending::emergency_withdraw_all`
- 允许调用者：仅管理员地址
- 告警级别：`critical`

监控面板：
- `http://127.0.0.1:3001/`

## 6. 结果
监控系统成功捕捉到了攻击，并生成 critical 级别 incident：
- rule: `高危函数越权调用检测`
- summary: `检测到非授权地址调用敏感函数 insecure_lending::emergency_withdraw_all`
- alert fingerprint: `26ff44a8c24cb70e23cf7520`

## 7. 实验中的重要发现
第一次直接跑时，监控没有立刻命中攻击。
原因不是规则写错，而是：
- GraphQL 索引数据存在延迟
- 扫描器使用严格的 lastCheckpoint 前进方式时，可能会跳过“checkpoint 已出现但交易详情稍后才可读”的窗口

为此已经修复：
- 增加 `checkpointOverlap`
- 增加 `recentTransactionDigests` 去重
- 让扫描器在每轮扫描时回看最近若干 checkpoint，从而降低索引延迟导致的漏报风险

这次实验说明：
- 用真实 testnet 对抗实验是有价值的
- 它暴露了单纯 paper design 看不到的采集层漏报问题

## 8. 相关源码
### 漏洞合约
- `/Users/seem/Desktop/sui-guardian/contracts/vuln-defi/Move.toml`
- `/Users/seem/Desktop/sui-guardian/contracts/vuln-defi/sources/insecure_lending.move`

### 监控系统
- `/Users/seem/Desktop/sui-guardian/src/monitor-service.ts`
- `/Users/seem/Desktop/sui-guardian/src/project-monitor.ts`
- `/Users/seem/Desktop/sui-guardian/src/graphql-client.ts`

## 9. 下一步建议
1. 增加 shared object 资金流失专项规则
2. 增加对象级别的资产快照 diff
3. 增加 testnet/devnet 一键实验脚本
4. 增加更多漏洞场景：
   - package upgrade 劫持
   - 假管理员参数注入
   - 预言机价格异常
   - 失败探测交易 burst
