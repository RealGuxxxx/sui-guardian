# Sui Behavior Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 `Sui Guardian` 增加一套首版攻击行为识别规则库，并把规则结果接入现有监控、配置和测试体系。

**Architecture:** 在现有 `ProjectMonitor` 基础上增加“派生信号 + 行为规则”两层。`ProjectMonitor` 继续负责基础规则，新增 `behavior-rules.ts` 负责更高层的攻击行为判断，规则依赖配置中的敏感函数、可疑目标和对象态势字段。

**Tech Stack:** TypeScript, Fastify, Vitest, Zod, YAML

---

### Task 1: 扩展类型与配置模型

**Files:**
- Modify: `/Users/seem/Desktop/sui-guardian/src/types.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/src/config.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/config.spec.ts`

- [ ] **Step 1: 写失败测试，覆盖新增配置字段**

```ts
import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';

describe('config behavior rules', () => {
  it('loads behavior rule settings', async () => {
    const config = await loadConfig('/tmp/behavior-config.yml');
    expect(config.projects[0]?.behaviorRules?.enabled).toBe(true);
    expect(config.projects[0]?.behaviorRules?.priceDeviationThresholdBps).toBe(1500);
    expect(config.projects[0]?.suspiciousTargets).toHaveLength(1);
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `npm test -- --run tests/config.spec.ts`
Expected: FAIL，报错提示 `behaviorRules` 或 `suspiciousTargets` 字段不存在，或测试文件不存在。

- [ ] **Step 3: 最小实现类型与配置解析**

```ts
export interface BehaviorRuleConfig {
  enabled: boolean;
  minRepeatedCalls: number;
  minProtectedOutflow: string;
  priceDeviationThresholdBps: number;
}
```

```ts
const behaviorRuleSchema = z.object({
  enabled: z.boolean().default(true),
  minRepeatedCalls: z.number().int().positive().default(2),
  minProtectedOutflow: z.string().default('1'),
  priceDeviationThresholdBps: z.number().int().positive().default(1500),
});
```

- [ ] **Step 4: 再跑测试确认通过**

Run: `npm test -- --run tests/config.spec.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/types.ts src/config.ts tests/config.spec.ts
git commit -m "feat: add behavior rule config model"
```

### Task 2: 增加行为规则引擎

**Files:**
- Create: `/Users/seem/Desktop/sui-guardian/src/behavior-rules.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/src/project-monitor.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/behavior-rules.spec.ts`

- [ ] **Step 1: 写失败测试，覆盖越权调用、重复消耗、价格操纵、可疑目标**

```ts
import { describe, expect, it } from 'vitest';
import { runBehaviorRules } from '../src/behavior-rules.js';

describe('behavior rules', () => {
  it('detects unauthorized sensitive calls', () => {
    const alerts = runBehaviorRules({
      projectId: 'demo',
      projectName: 'Demo',
      tx: {
        digest: 'tx-1',
        checkpoint: 1,
        timestamp: '2026-04-24T00:00:00.000Z',
        sender: '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        status: 'SUCCESS',
        calls: [{ package: '0x1111111111111111111111111111111111111111111111111111111111111111', module: 'vault', function: 'emergency_withdraw' }],
        balanceChanges: [],
        objectChanges: [],
      },
      protectedAddresses: [],
      sensitiveCalls: [{
        label: 'emergency-withdraw',
        package: '0x1111111111111111111111111111111111111111111111111111111111111111',
        module: 'vault',
        function: 'emergency_withdraw',
        allowedSenders: ['0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
        severity: 'critical',
      }],
      derived: {},
    });
    expect(alerts).toHaveLength(1);
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `npm test -- --run tests/behavior-rules.spec.ts`
Expected: FAIL，报错提示找不到 `behavior-rules.ts` 或 `runBehaviorRules`。

- [ ] **Step 3: 编写最小行为规则实现并接入 ProjectMonitor**

```ts
export function runBehaviorRules(ctx: RuleContext): Alert[] {
  return [
    ...detectUnauthorizedSensitiveCall(ctx),
    ...detectRepeatedDrainPattern(ctx),
    ...detectFlashLoanLikeAttack(ctx),
    ...detectPriceManipulation(ctx),
    ...detectSuspiciousTargetCalls(ctx),
  ];
}
```

```ts
const behaviorAlerts = runBehaviorRules({
  projectId: this.project.id,
  projectName: this.project.name,
  tx,
  protectedAddresses: this.project.protectedAddresses.map((item) => item.address),
  sensitiveCalls: this.project.functionGuards.map((guard) => ({
    label: guard.label,
    package: guard.package,
    module: guard.module,
    function: guard.function,
    allowedSenders: guard.allowedSenders,
    severity: guard.severity,
  })),
  derived: this.buildDerivedSignals(tx),
});
```

- [ ] **Step 4: 运行测试确认通过**

Run: `npm test -- --run tests/behavior-rules.spec.ts tests/project-monitor.spec.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/behavior-rules.ts src/project-monitor.ts tests/behavior-rules.spec.ts tests/project-monitor.spec.ts
git commit -m "feat: add behavior detection rules"
```

### Task 3: 扩展项目配置摘要与规则可视化

**Files:**
- Modify: `/Users/seem/Desktop/sui-guardian/src/monitor-service.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/src/dashboard.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/monitor-service.spec.ts`

- [ ] **Step 1: 写失败测试，覆盖配置摘要中的行为规则字段**

```ts
import { describe, expect, it } from 'vitest';

describe('monitor service config summary', () => {
  it('includes behavior rule summary', () => {
    const summary = service.getConfigSummary();
    expect(summary.projects[0]?.behaviorRules?.enabled).toBe(true);
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `npm test -- --run tests/monitor-service.spec.ts`
Expected: FAIL，摘要中缺少 `behaviorRules` 字段或测试文件不存在。

- [ ] **Step 3: 增加配置摘要输出与 Dashboard 渲染**

```ts
behaviorRules: {
  enabled: project.behaviorRules.enabled,
  minRepeatedCalls: project.behaviorRules.minRepeatedCalls,
  minProtectedOutflow: project.behaviorRules.minProtectedOutflow,
  priceDeviationThresholdBps: project.behaviorRules.priceDeviationThresholdBps,
},
```

```ts
'<div style="margin-top: 6px;">行为规则：' +
escapeHtml(project.behaviorRules.enabled ? '已启用' : '未启用') +
'，重复调用阈值 ' + escapeHtml(String(project.behaviorRules.minRepeatedCalls)) +
'，价格偏离阈值 ' + escapeHtml(String(project.behaviorRules.priceDeviationThresholdBps)) + ' bps</div>'
```

- [ ] **Step 4: 运行测试确认通过**

Run: `npm test -- --run tests/monitor-service.spec.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/monitor-service.ts src/dashboard.ts tests/monitor-service.spec.ts
git commit -m "feat: expose behavior rule summaries"
```

### Task 4: 回归验证与类型检查

**Files:**
- Modify: `/Users/seem/Desktop/sui-guardian/tests/project-monitor.spec.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/tests/behavior-rules.spec.ts`

- [ ] **Step 1: 增加组合场景测试**

```ts
it('aggregates base alerts and behavior alerts for a drain attack', () => {
  const alerts = monitor.processTransaction(buildTx({
    sender: ATTACKER,
    calls: [
      { package: PACKAGE, module: 'vault', function: 'emergency_withdraw' },
      { package: PACKAGE, module: 'vault', function: 'withdraw' },
      { package: PACKAGE, module: 'vault', function: 'withdraw' },
    ],
    balanceChanges: [{ owner: TREASURY, coinType: '0x2::sui::SUI', amount: '-200' }],
  }));
  expect(alerts.length).toBeGreaterThanOrEqual(2);
});
```

- [ ] **Step 2: 跑单测**

Run: `npm test`
Expected: PASS

- [ ] **Step 3: 跑类型检查**

Run: `npm run typecheck`
Expected: PASS

- [ ] **Step 4: 取最近改动文件诊断**

Run: VS Code diagnostics for `src/types.ts`, `src/config.ts`, `src/project-monitor.ts`, `src/behavior-rules.ts`, `src/monitor-service.ts`, `src/dashboard.ts`
Expected: 无新增错误

- [ ] **Step 5: 提交**

```bash
git add tests/project-monitor.spec.ts tests/behavior-rules.spec.ts
git commit -m "test: cover behavior rule scenarios"
```
