# 数据清理报告

## 清理目标

将默认展示链路切换到真实业务数据模式，移除仓库中会污染默认运行结果的 demo / generated 运行数据，同时保留演练验证模块代码与脚本。

## 清理范围

- `.data/` 下的 generated 状态文件和运行日志
- 默认运行说明中的实验性展示导向
- Dashboard 空态文案中的非生产化表述
- 配置模板与参考文档中的生产/演练边界说明

## 已完成清理

### 1. 运行时数据残留

已删除以下默认展示残留文件：

- `.data/generated-defi-range-state.json`
- `.data/generated-vuln-defi-lab-state.json`
- `.data/generated-defi-range-monitor.log`
- `.data/generated-vuln-defi-lab-monitor.log`

### 2. 文档与默认运行说明

已更新：

- `README.md`
- `docs/architecture.md`
- `docs/open-source-references.md`
- `config/projects.example.yml`

更新后默认说明明确：

- 默认运行只读取真实项目配置
- 演练验证模块保留
- 演练配置不参与默认运行

### 3. 前端展示链路

Dashboard 空态已切换为真实数据模式：

- `尚未配置真实监控项目`
- `暂无真实攻击事件`
- `暂无真实攻击时间线`
- `暂无真实关键对象数据`
- `当前筛选条件下暂无真实告警事件`

## 数据流验证

### 后端到前端链路

1. 前端调用 `/api/config`、`/api/metrics`、`/api/incidents`、`/api/assets`、`/api/alerts`
2. `server.ts` 直接转发到 `MonitorService`
3. `MonitorService` 仅返回当前配置和当前状态文件中的真实结果
4. 当没有真实项目或没有真实数据时，返回空数组或空态结果
5. 前端显示真实空态，而不是示例数据

### 验证结论

- 默认仓库状态下已不再保留 generated 展示数据
- 接口聚合结果在空配置下返回真实空态
- 页面不再以 demo 文案伪装“有数据”

## 保留内容

以下内容保留，作为生产环境中的验证与回归组件：

- `scripts/run_vuln_defi_lab.py`
- `scripts/run_defi_range_lab.py`
- `config/generated-vuln-defi-lab.yml`
- `config/generated-defi-range.yml`

这些内容仅用于手动演练、链路回归和数据完整性验证。

## 风险提示

- 如果后续再次用 generated 配置启动服务，对应状态文件仍会重新生成
- 这不属于默认展示链路污染，但需要在运维流程中避免误用演练配置作为生产配置

## 最终结论

当前项目默认运行模式已经切换为生产优先：

- 默认展示只面向真实项目
- 默认数据链路不再使用 generated 运行结果
- 演练验证模块保留但已与默认展示链路隔离
