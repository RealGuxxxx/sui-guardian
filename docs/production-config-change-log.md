# 配置变更记录

## 默认运行模式

- 默认入口仍使用 `config/default.yml`
- `config/default.yml` 保持 `projects: []`
- 未配置真实项目时不再展示任何 generated / demo 数据

## 已隔离的演练配置

以下配置保留，但仅用于手动触发：

- `config/generated-defi-range.yml`
- `config/generated-vuln-defi-lab.yml`
- `config/testnet-vuln-defi.yml`

## 模板配置更新

- `config/projects.example.yml` 已明确标注为真实项目配置模板
- 模板已增加说明：不应直接用于演练配置

## 数据文件变更

已删除：

- `.data/generated-defi-range-state.json`
- `.data/generated-vuln-defi-lab-state.json`
- `.data/generated-defi-range-monitor.log`
- `.data/generated-vuln-defi-lab-monitor.log`

保留：

- `.data/state.json`
- 其他非 generated 的状态文件

## 前端空态变更

已统一切换为真实数据模式空态：

- `尚未配置真实监控项目`
- `暂无真实攻击事件`
- `暂无真实攻击时间线`
- `暂无真实关键对象数据`
- `当前筛选条件下暂无真实告警事件`

## 运维建议

- 生产环境只使用真实项目配置文件启动
- 演练时显式传入 lab/generated 配置
- 演练完成后清理对应 state 文件，避免误读历史结果
