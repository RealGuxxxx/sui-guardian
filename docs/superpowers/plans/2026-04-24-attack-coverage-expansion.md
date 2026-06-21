# Attack Coverage Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 `sui-guardian` 增加统一攻击检测器注册表、已知攻击 detector、未知攻击 detector 和攻击链聚合能力，显著提升攻击覆盖率与可解释性。

**Architecture:** 在现有 `DerivedEvidence + risk scorer` 之上新增 `src/detectors/`，由 registry 统一调度 detector 并产出标准化 `AttackFinding`。`ProjectMonitor` 负责交易级 detector 编排，`MonitorService` 负责事件级攻击链聚合，`Dashboard/API` 负责展示 `attackType / attackCategory / chainStage / chainId` 等新证据。

**Tech Stack:** TypeScript, Fastify, Vitest, Zod

---

## File Structure

- Create: `/Users/seem/Desktop/sui-guardian/src/detectors/types.ts`
  - 定义 `AttackFinding`、`AttackDetectorContext`、`AttackFamily`、`AttackChainSummary`
- Create: `/Users/seem/Desktop/sui-guardian/src/detectors/registry.ts`
  - 注册和运行 detector
- Create: `/Users/seem/Desktop/sui-guardian/src/detectors/known/permission-detector.ts`
  - 处理权限接管、非授权敏感调用
- Create: `/Users/seem/Desktop/sui-guardian/src/detectors/known/price-manipulation-detector.ts`
  - 处理预言机/价格操纵
- Create: `/Users/seem/Desktop/sui-guardian/src/detectors/known/liquidity-drain-detector.ts`
  - 处理库存抽干、保护地址异常流出、攻击者净获利
- Create: `/Users/seem/Desktop/sui-guardian/src/detectors/known/execution-abuse-detector.ts`
  - 处理探测后抽取、重复敏感调用、可疑目标调用
- Create: `/Users/seem/Desktop/sui-guardian/src/detectors/anomaly/unknown-attack-detector.ts`
  - 处理多证据共振但未命中已知模板的异常
- Modify: `/Users/seem/Desktop/sui-guardian/src/types.ts`
  - 扩展 `DerivedEvidence`、`RuntimeState`、config summary 类型
- Modify: `/Users/seem/Desktop/sui-guardian/src/project-monitor.ts`
  - 运行 registry，向告警 details 注入 findings
- Modify: `/Users/seem/Desktop/sui-guardian/src/behavior-rules.ts`
  - 逐步转为消费 detector findings
- Modify: `/Users/seem/Desktop/sui-guardian/src/monitor-service.ts`
  - 聚合 findings 为攻击链
- Modify: `/Users/seem/Desktop/sui-guardian/src/server.ts`
  - 透出新的攻击链字段
- Modify: `/Users/seem/Desktop/sui-guardian/src/dashboard.ts`
  - 展示攻击类型、链阶段、未知攻击异常
- Test: `/Users/seem/Desktop/sui-guardian/tests/detector-registry.spec.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/permission-detector.spec.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/price-manipulation-detector.spec.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/liquidity-drain-detector.spec.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/execution-abuse-detector.spec.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/unknown-attack-detector.spec.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/project-monitor.spec.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/monitor-service.spec.ts`

### Task 1: 定义 Detector 类型与注册表

**Files:**
- Create: `/Users/seem/Desktop/sui-guardian/src/detectors/types.ts`
- Create: `/Users/seem/Desktop/sui-guardian/src/detectors/registry.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/src/types.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/detector-registry.spec.ts`

- [ ] **Step 1: 写失败测试**

```ts
import { describe, expect, it } from 'vitest';

import { runAttackDetectors } from '../src/detectors/registry.js';

describe('runAttackDetectors', () => {
  it('returns standardized findings from enabled detectors', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(Array.isArray(findings)).toBe(true);
    expect(findings[0]).toHaveProperty('attackType');
    expect(findings[0]).toHaveProperty('category');
    expect(findings[0]).toHaveProperty('summary');
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `npm test -- --run tests/detector-registry.spec.ts`
Expected: FAIL，提示 `runAttackDetectors` 或 detector 类型不存在。

- [ ] **Step 3: 写最小实现**

```ts
// src/detectors/types.ts
import type { DerivedEvidence, MonitoringProjectConfig, ObservedTransaction } from '../types.js';

export type AttackCategory = 'permission' | 'price-manipulation' | 'liquidity-drain' | 'execution-abuse' | 'unknown';

export interface AttackFinding {
  attackType: string;
  category: AttackCategory;
  summary: string;
  evidence: Record<string, unknown>;
  riskHints?: {
    scoreDelta?: number;
    severityFloor?: 'info' | 'low' | 'medium' | 'high' | 'critical';
  };
  chainHints?: {
    stage?: 'probe' | 'manipulation' | 'takeover' | 'extraction';
  };
}

export interface AttackDetectorContext {
  project: MonitoringProjectConfig;
  tx: ObservedTransaction;
  derived: DerivedEvidence;
  runtime: {
    recentAlerts: Array<{ ruleId: string; details: Record<string, unknown> }>;
  };
}
```

```ts
// src/detectors/registry.ts
import type { AttackDetectorContext, AttackFinding } from './types.js';

export function runAttackDetectors(_ctx: AttackDetectorContext): AttackFinding[] {
  return [{
    attackType: 'bootstrap-detector',
    category: 'unknown',
    summary: 'bootstrap detector finding',
    evidence: {},
  }];
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `npm test -- --run tests/detector-registry.spec.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/detectors/types.ts src/detectors/registry.ts src/types.ts tests/detector-registry.spec.ts
git commit -m "feat: add attack detector registry foundation"
```

### Task 2: 实现 Permission Detector

**Files:**
- Create: `/Users/seem/Desktop/sui-guardian/src/detectors/known/permission-detector.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/src/detectors/registry.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/permission-detector.spec.ts`

- [ ] **Step 1: 写失败测试**

```ts
import { describe, expect, it } from 'vitest';

import { detectPermissionAttacks } from '../src/detectors/known/permission-detector.js';

describe('detectPermissionAttacks', () => {
  it('emits admin takeover finding for unauthorized permission change', () => {
    const findings = detectPermissionAttacks({
      project: buildProject(),
      tx: buildTx({ sender: ATTACKER }),
      derived: {
        baselineEvidence: [{
          objectLabel: 'admin-vault',
          field: 'admin',
          anomalyKind: 'permission_change',
          senderAuthorized: false,
        }],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('admin-takeover');
    expect(findings[0]?.category).toBe('permission');
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `npm test -- --run tests/permission-detector.spec.ts`
Expected: FAIL，提示 `detectPermissionAttacks` 不存在。

- [ ] **Step 3: 写最小实现**

```ts
import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectPermissionAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const permissionChange = (ctx.derived.baselineEvidence ?? []).find(
    (item) => item.anomalyKind === 'permission_change' && !item.senderAuthorized,
  );

  if (!permissionChange) {
    return [];
  }

  return [{
    attackType: 'admin-takeover',
    category: 'permission',
    summary: `${permissionChange.objectLabel}.${permissionChange.field} 出现未授权权限变更`,
    evidence: {
      objectLabel: permissionChange.objectLabel,
      field: permissionChange.field,
      sender: ctx.tx.sender,
    },
    riskHints: {
      scoreDelta: 30,
      severityFloor: 'high',
    },
    chainHints: {
      stage: 'takeover',
    },
  }];
}
```

- [ ] **Step 4: 接入 registry**

```ts
import { detectPermissionAttacks } from './known/permission-detector.js';

export function runAttackDetectors(ctx: AttackDetectorContext): AttackFinding[] {
  return [
    ...detectPermissionAttacks(ctx),
  ];
}
```

- [ ] **Step 5: 运行测试确认通过**

Run: `npm test -- --run tests/permission-detector.spec.ts tests/detector-registry.spec.ts`
Expected: PASS

- [ ] **Step 6: 提交**

```bash
git add src/detectors/known/permission-detector.ts src/detectors/registry.ts tests/permission-detector.spec.ts
git commit -m "feat: add permission attack detector"
```

### Task 3: 实现 Price Manipulation 与 Liquidity Drain Detector

**Files:**
- Create: `/Users/seem/Desktop/sui-guardian/src/detectors/known/price-manipulation-detector.ts`
- Create: `/Users/seem/Desktop/sui-guardian/src/detectors/known/liquidity-drain-detector.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/src/detectors/registry.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/price-manipulation-detector.spec.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/liquidity-drain-detector.spec.ts`

- [ ] **Step 1: 写价格操纵失败测试**

```ts
import { describe, expect, it } from 'vitest';

import { detectPriceManipulationAttacks } from '../src/detectors/known/price-manipulation-detector.js';

describe('detectPriceManipulationAttacks', () => {
  it('emits price manipulation finding when deviation and extraction align', () => {
    const findings = detectPriceManipulationAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        valueExtractionDetected: true,
        priceEvidence: [{
          label: 'oracle-price',
          deviationBps: 40000,
          referenceKind: 'rolling_median',
          extractionCoupled: true,
        }],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('oracle-price-manipulation');
  });
});
```

- [ ] **Step 2: 写流动性抽干失败测试**

```ts
import { describe, expect, it } from 'vitest';

import { detectLiquidityDrainAttacks } from '../src/detectors/known/liquidity-drain-detector.js';

describe('detectLiquidityDrainAttacks', () => {
  it('emits liquidity drain finding when protected outflow and attacker gain align', () => {
    const findings = detectLiquidityDrainAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '1500',
          netAttackerGain: '1500',
        },
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('liquidity-drain');
  });
});
```

- [ ] **Step 3: 运行测试确认失败**

Run: `npm test -- --run tests/price-manipulation-detector.spec.ts tests/liquidity-drain-detector.spec.ts`
Expected: FAIL

- [ ] **Step 4: 写最小实现**

```ts
// price-manipulation-detector.ts
import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectPriceManipulationAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const matched = (ctx.derived.priceEvidence ?? []).find(
    (item) => (item.deviationBps ?? 0) >= 1500 && item.extractionCoupled,
  );
  if (!matched || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  return [{
    attackType: 'oracle-price-manipulation',
    category: 'price-manipulation',
    summary: `检测到价格偏离 ${matched.deviationBps} bps 且伴随价值提取`,
    evidence: matched,
    riskHints: { scoreDelta: 35, severityFloor: 'high' },
    chainHints: { stage: 'manipulation' },
  }];
}
```

```ts
// liquidity-drain-detector.ts
import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectLiquidityDrainAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const flow = ctx.derived.flowEvidence;
  if (!flow?.attackPathFound) {
    return [];
  }

  return [{
    attackType: 'liquidity-drain',
    category: 'liquidity-drain',
    summary: '检测到受保护资金外流并伴随攻击者净获利',
    evidence: flow,
    riskHints: { scoreDelta: 35, severityFloor: 'high' },
    chainHints: { stage: 'extraction' },
  }];
}
```

- [ ] **Step 5: 接入 registry**

```ts
import { detectLiquidityDrainAttacks } from './known/liquidity-drain-detector.js';
import { detectPriceManipulationAttacks } from './known/price-manipulation-detector.js';

export function runAttackDetectors(ctx: AttackDetectorContext): AttackFinding[] {
  return [
    ...detectPermissionAttacks(ctx),
    ...detectPriceManipulationAttacks(ctx),
    ...detectLiquidityDrainAttacks(ctx),
  ];
}
```

- [ ] **Step 6: 运行测试确认通过**

Run: `npm test -- --run tests/price-manipulation-detector.spec.ts tests/liquidity-drain-detector.spec.ts tests/detector-registry.spec.ts`
Expected: PASS

- [ ] **Step 7: 提交**

```bash
git add src/detectors/known/price-manipulation-detector.ts src/detectors/known/liquidity-drain-detector.ts src/detectors/registry.ts tests/price-manipulation-detector.spec.ts tests/liquidity-drain-detector.spec.ts
git commit -m "feat: add price and liquidity attack detectors"
```

### Task 4: 实现 Execution Abuse 与 Unknown Attack Detector

**Files:**
- Create: `/Users/seem/Desktop/sui-guardian/src/detectors/known/execution-abuse-detector.ts`
- Create: `/Users/seem/Desktop/sui-guardian/src/detectors/anomaly/unknown-attack-detector.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/src/detectors/registry.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/execution-abuse-detector.spec.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/unknown-attack-detector.spec.ts`

- [ ] **Step 1: 写执行滥用失败测试**

```ts
import { describe, expect, it } from 'vitest';

import { detectExecutionAbuseAttacks } from '../src/detectors/known/execution-abuse-detector.js';

describe('detectExecutionAbuseAttacks', () => {
  it('emits execution abuse finding for repeated sensitive calls and suspicious targets', () => {
    const findings = detectExecutionAbuseAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        sameSensitiveCallRepeats: { 'arena::emergency_withdraw_all': 3 },
        suspiciousTargets: ['0x111'],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('execution-abuse');
  });
});
```

- [ ] **Step 2: 写未知攻击失败测试**

```ts
import { describe, expect, it } from 'vitest';

import { detectUnknownCoordinatedAttack } from '../src/detectors/anomaly/unknown-attack-detector.js';

describe('detectUnknownCoordinatedAttack', () => {
  it('emits unknown coordinated anomaly when multiple signals resonate', () => {
    const findings = detectUnknownCoordinatedAttack({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        priceEvidence: [{ label: 'oracle-price', deviationBps: 2200, referenceKind: 'rolling_median', extractionCoupled: false }],
        baselineEvidence: [{ objectLabel: 'vault', field: 'admin', anomalyKind: 'permission_change', senderAuthorized: false }],
        flowEvidence: { nodes: [], edges: [], attackPathFound: false, pathRoles: [], netProtectedOutflow: '0', netAttackerGain: '0' },
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('unknown-coordinated-anomaly');
  });
});
```

- [ ] **Step 3: 运行测试确认失败**

Run: `npm test -- --run tests/execution-abuse-detector.spec.ts tests/unknown-attack-detector.spec.ts`
Expected: FAIL

- [ ] **Step 4: 写最小实现**

```ts
// execution-abuse-detector.ts
import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectExecutionAbuseAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const repeated = Object.entries(ctx.derived.sameSensitiveCallRepeats ?? {}).find(([, count]) => count >= 2);
  if (!repeated && !(ctx.derived.suspiciousTargets?.length)) {
    return [];
  }

  return [{
    attackType: 'execution-abuse',
    category: 'execution-abuse',
    summary: '检测到重复敏感执行或可疑目标交互',
    evidence: {
      repeated,
      suspiciousTargets: ctx.derived.suspiciousTargets ?? [],
    },
    riskHints: { scoreDelta: 20, severityFloor: 'medium' },
    chainHints: { stage: 'probe' },
  }];
}
```

```ts
// unknown-attack-detector.ts
import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectUnknownCoordinatedAttack(ctx: AttackDetectorContext): AttackFinding[] {
  const signalCount = [
    (ctx.derived.priceEvidence ?? []).length > 0,
    (ctx.derived.baselineEvidence ?? []).length > 0,
    Boolean(ctx.derived.flowEvidence),
  ].filter(Boolean).length;

  if (signalCount < 2) {
    return [];
  }

  return [{
    attackType: 'unknown-coordinated-anomaly',
    category: 'unknown',
    summary: '检测到多证据共振但未归类的高危异常',
    evidence: {
      signalCount,
      evidenceSummary: ctx.derived.evidenceSummary ?? [],
    },
    riskHints: { scoreDelta: 25, severityFloor: 'medium' },
    chainHints: { stage: 'manipulation' },
  }];
}
```

- [ ] **Step 5: 接入 registry**

```ts
import { detectExecutionAbuseAttacks } from './known/execution-abuse-detector.js';
import { detectUnknownCoordinatedAttack } from './anomaly/unknown-attack-detector.js';

export function runAttackDetectors(ctx: AttackDetectorContext): AttackFinding[] {
  return [
    ...detectPermissionAttacks(ctx),
    ...detectPriceManipulationAttacks(ctx),
    ...detectLiquidityDrainAttacks(ctx),
    ...detectExecutionAbuseAttacks(ctx),
    ...detectUnknownCoordinatedAttack(ctx),
  ];
}
```

- [ ] **Step 6: 运行测试确认通过**

Run: `npm test -- --run tests/execution-abuse-detector.spec.ts tests/unknown-attack-detector.spec.ts tests/detector-registry.spec.ts`
Expected: PASS

- [ ] **Step 7: 提交**

```bash
git add src/detectors/known/execution-abuse-detector.ts src/detectors/anomaly/unknown-attack-detector.ts src/detectors/registry.ts tests/execution-abuse-detector.spec.ts tests/unknown-attack-detector.spec.ts
git commit -m "feat: add execution abuse and unknown attack detectors"
```

### Task 5: 接入 ProjectMonitor 与告警详情

**Files:**
- Modify: `/Users/seem/Desktop/sui-guardian/src/project-monitor.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/src/types.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/project-monitor.spec.ts`

- [ ] **Step 1: 写失败测试**

```ts
it('includes attack findings in alert details', () => {
  const monitor = new ProjectMonitor(buildProject());
  const alerts = monitor.processTransaction(buildAttackTx());

  expect(alerts.some((alert) => Array.isArray(alert.details.attackFindings))).toBe(true);
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `npm test -- --run tests/project-monitor.spec.ts`
Expected: FAIL，提示 `attackFindings` 不存在。

- [ ] **Step 3: 写最小实现**

```ts
import { runAttackDetectors } from './detectors/registry.js';

const attackFindings = runAttackDetectors({
  project: this.project,
  tx,
  derived,
  runtime: {
    recentAlerts: [],
  },
});

derived.attackFindings = attackFindings;
derived.evidenceSummary = [
  ...(derived.evidenceSummary ?? []),
  ...attackFindings.map((finding) => `attack:${finding.attackType}`),
];
```

```ts
export interface DerivedEvidence {
  // existing fields...
  attackFindings?: AttackFinding[];
}
```

- [ ] **Step 4: 在行为告警 details 中注入 findings**

```ts
details: {
  // existing fields...
  attackFindings: ctx.derived?.attackFindings ?? [],
}
```

- [ ] **Step 5: 运行测试确认通过**

Run: `npm test -- --run tests/project-monitor.spec.ts tests/behavior-rules.spec.ts`
Expected: PASS

- [ ] **Step 6: 提交**

```bash
git add src/project-monitor.ts src/types.ts src/behavior-rules.ts tests/project-monitor.spec.ts tests/behavior-rules.spec.ts
git commit -m "feat: attach attack findings to monitor alerts"
```

### Task 6: 聚合攻击链并暴露到 API / Dashboard

**Files:**
- Modify: `/Users/seem/Desktop/sui-guardian/src/monitor-service.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/src/server.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/src/dashboard.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/monitor-service.spec.ts`

- [ ] **Step 1: 写失败测试**

```ts
it('groups attack findings into incident chains', () => {
  const timeline = service.getIncidentTimeline();
  expect(timeline[0]).toHaveProperty('attackTypes');
  expect(timeline[0]).toHaveProperty('chainStages');
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `npm test -- --run tests/monitor-service.spec.ts`
Expected: FAIL，提示 `attackTypes` 或 `chainStages` 不存在。

- [ ] **Step 3: 写最小实现**

```ts
const attackFindings = extractAttackFindings(alert.details);

existing.attackTypes = new Set([...(existing.attackTypes ?? []), ...attackFindings.map((item) => item.attackType)]);
existing.chainStages = new Set([...(existing.chainStages ?? []), ...attackFindings.map((item) => item.chainHints?.stage).filter(Boolean)]);
```

```ts
return service.getIncidentTimeline(limit).map((incident) => ({
  ...incident,
  attackTypes: incident.attackTypes ?? [],
  chainStages: incident.chainStages ?? [],
}));
```

```ts
'<div class="meta" style="margin-top: 6px;">攻击类型：' + escapeHtml((item.attackTypes || []).join(', ') || '-') + '</div>' +
'<div class="meta" style="margin-top: 6px;">攻击阶段：' + escapeHtml((item.chainStages || []).join(' -> ') || '-') + '</div>' +
```

- [ ] **Step 4: 运行测试确认通过**

Run: `npm test -- --run tests/monitor-service.spec.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/monitor-service.ts src/server.ts src/dashboard.ts tests/monitor-service.spec.ts
git commit -m "feat: expose attack chains in incidents"
```

### Task 7: 全量回归

**Files:**
- Modify: `/Users/seem/Desktop/sui-guardian/tests/detector-registry.spec.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/tests/project-monitor.spec.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/tests/monitor-service.spec.ts`

- [ ] **Step 1: 增加组合攻击回归测试**

```ts
it('produces multiple detector findings for a coordinated attack', () => {
  const alerts = monitor.processTransaction(buildCoordinatedAttackTx());
  const findings = alerts.flatMap((alert) => (alert.details.attackFindings as Array<{ attackType: string }> | undefined) ?? []);

  expect(findings.some((item) => item.attackType === 'admin-takeover')).toBe(true);
  expect(findings.some((item) => item.attackType === 'oracle-price-manipulation')).toBe(true);
  expect(findings.some((item) => item.attackType === 'liquidity-drain')).toBe(true);
});
```

- [ ] **Step 2: 跑全部测试**

Run: `npm test`
Expected: PASS

- [ ] **Step 3: 跑类型检查**

Run: `npm run typecheck`
Expected: PASS

- [ ] **Step 4: 获取诊断**

Run: VS Code diagnostics for `src/detectors/**/*.ts`, `src/project-monitor.ts`, `src/monitor-service.ts`, `src/dashboard.ts`
Expected: 无新增错误

- [ ] **Step 5: 提交**

```bash
git add src tests
git commit -m "test: cover attack coverage expansion"
```

## Self-Review

- Spec coverage:
  - detector registry: Task 1
  - 已知攻击 detector: Tasks 2-4
  - 未知攻击 detector: Task 4
  - 攻击链聚合: Task 6
  - API / Dashboard 展示: Task 6
  - 全量回归: Task 7
- Placeholder scan:
  - 未使用 `TODO/TBD/implement later`
- Type consistency:
  - 统一使用 `AttackFinding`、`AttackDetectorContext`、`attackFindings`
