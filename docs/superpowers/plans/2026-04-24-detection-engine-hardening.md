# Detection Engine Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 `sui-guardian` 增加真实价格偏离、对象字段基线、资金路径图和误报抑制四项重型检测能力，并将其接入统一风险评分与告警展示链路。

**Architecture:** 在现有 `ProjectMonitor` 之上新增 `src/detection/` 目录承载四类证据提取器和评分器。`ProjectMonitor` 负责编排基础规则、证据提取和评分结果，`MonitorService` 负责持久化画像与向 API/Dashboard 暴露证据，`behavior-rules.ts` 从直接启发式判断调整为消费增强后的派生证据和风险评分。

**Tech Stack:** TypeScript, Zod, Fastify, Vitest

---

### Task 1: 扩展类型与配置模型

**Files:**
- Modify: `/Users/seem/Desktop/sui-guardian/src/types.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/src/config.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/config.spec.ts`

- [ ] **Step 1: 写失败测试，覆盖新增检测配置块**

```ts
import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';

describe('hardening config', () => {
  it('loads price models, object baselines, flow tracking and suppression config', async () => {
    const config = await loadConfig('/tmp/hardening-config.yml');
    const project = config.projects[0];

    expect(project?.priceModels?.[0]?.label).toBe('oracle-price');
    expect(project?.objectBaselines?.[0]?.fields?.[0]?.path).toBe('admin');
    expect(project?.flowTracking?.enabled).toBe(true);
    expect(project?.suppression?.maintenanceWindows?.[0]?.label).toBe('ops-window');
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `npm test -- --run tests/config.spec.ts`
Expected: FAIL，提示 `priceModels`、`objectBaselines`、`flowTracking` 或 `suppression` 字段不存在或未被解析。

- [ ] **Step 3: 在 `src/types.ts` 增加配置与证据类型**

```ts
export interface PriceModelConfig {
  label: string;
  trackedObjectLabel: string;
  observedFieldPath: string;
  referenceMode: 'tracked_field' | 'rolling_median' | 'fixed_range';
  referenceObjectLabel?: string;
  referenceFieldPath?: string;
  fixedLowerBound?: string;
  fixedUpperBound?: string;
  deviationThresholdBps: number;
}

export interface ObjectBaselineFieldConfig {
  path: string;
  kind: 'permission' | 'price' | 'inventory' | 'state';
  allowedSenders?: string[];
  maxDeltaBps?: number;
  maxAbsoluteDecrease?: string;
}

export interface ObjectBaselineConfig {
  label: string;
  trackedObjectLabel: string;
  fields: ObjectBaselineFieldConfig[];
}

export interface FlowTrackingConfig {
  enabled: boolean;
  minProtectedOutflow: string;
  attackerGainThreshold: string;
  shortWindowTxCount: number;
}

export interface MaintenanceWindowConfig {
  label: string;
  allowedSenders: string[];
  startHourUtc: number;
  endHourUtc: number;
}

export interface SuppressionConfig {
  enabled: boolean;
  duplicateWindowSeconds: number;
  weakSignalScoreThreshold: number;
  maintenanceWindows: MaintenanceWindowConfig[];
}
```

- [ ] **Step 4: 在 `MonitoringProjectConfig` 中接入新配置块**

```ts
export interface MonitoringProjectConfig {
  id: string;
  name: string;
  packages: PackageWatchConfig[];
  protectedAddresses: ProtectedAddressConfig[];
  functionGuards: FunctionGuardConfig[];
  trafficSpikes: TrafficSpikeConfig[];
  failureSpikes: FailureSpikeConfig[];
  trackedObjects: TrackedObjectConfig[];
  suspiciousTargets: SuspiciousTargetConfig[];
  behaviorRules: BehaviorRuleConfig;
  priceModels: PriceModelConfig[];
  objectBaselines: ObjectBaselineConfig[];
  flowTracking: FlowTrackingConfig;
  suppression: SuppressionConfig;
}
```

- [ ] **Step 5: 在 `src/config.ts` 增加对应 Zod schema 与默认值**

```ts
const priceModelSchema = z.object({
  label: z.string().min(1),
  trackedObjectLabel: z.string().min(1),
  observedFieldPath: z.string().min(1),
  referenceMode: z.enum(['tracked_field', 'rolling_median', 'fixed_range']).default('rolling_median'),
  referenceObjectLabel: z.string().optional(),
  referenceFieldPath: z.string().optional(),
  fixedLowerBound: z.string().optional(),
  fixedUpperBound: z.string().optional(),
  deviationThresholdBps: z.number().int().positive().default(1500),
});

const objectBaselineFieldSchema = z.object({
  path: z.string().min(1),
  kind: z.enum(['permission', 'price', 'inventory', 'state']),
  allowedSenders: z.array(z.string()).default([]),
  maxDeltaBps: z.number().int().nonnegative().optional(),
  maxAbsoluteDecrease: z.string().optional(),
});

const objectBaselineSchema = z.object({
  label: z.string().min(1),
  trackedObjectLabel: z.string().min(1),
  fields: z.array(objectBaselineFieldSchema).default([]),
});

const flowTrackingSchema = z.object({
  enabled: z.boolean().default(true),
  minProtectedOutflow: z.string().default('1'),
  attackerGainThreshold: z.string().default('1'),
  shortWindowTxCount: z.number().int().positive().default(2),
});

const maintenanceWindowSchema = z.object({
  label: z.string().min(1),
  allowedSenders: z.array(z.string()).default([]),
  startHourUtc: z.number().int().min(0).max(23),
  endHourUtc: z.number().int().min(0).max(23),
});

const suppressionSchema = z.object({
  enabled: z.boolean().default(true),
  duplicateWindowSeconds: z.number().int().positive().default(600),
  weakSignalScoreThreshold: z.number().int().nonnegative().default(35),
  maintenanceWindows: z.array(maintenanceWindowSchema).default([]),
});
```

- [ ] **Step 6: 运行测试确认通过**

Run: `npm test -- --run tests/config.spec.ts`
Expected: PASS

- [ ] **Step 7: 提交**

```bash
git add src/types.ts src/config.ts tests/config.spec.ts
git commit -m "feat: add hardening config model"
```

### Task 2: 建立证据与画像基础类型

**Files:**
- Modify: `/Users/seem/Desktop/sui-guardian/src/types.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/project-monitor.spec.ts`

- [ ] **Step 1: 写失败测试，声明增强结果中应包含证据和评分**

```ts
import { describe, expect, it } from 'vitest';
import { ProjectMonitor } from '../src/project-monitor.js';

describe('project monitor hardening types', () => {
  it('returns alerts with risk scoring evidence in details', () => {
    const monitor = new ProjectMonitor(buildProjectConfig());
    const alerts = monitor.processTransaction(buildTx());

    expect(alerts[0]?.details).toHaveProperty('riskScore');
    expect(alerts[0]?.details).toHaveProperty('confidence');
    expect(alerts[0]?.details).toHaveProperty('evidenceSummary');
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `npm test -- --run tests/project-monitor.spec.ts`
Expected: FAIL，提示告警详情中没有 `riskScore`、`confidence` 或 `evidenceSummary`。

- [ ] **Step 3: 在 `src/types.ts` 增加证据、评分和画像类型**

```ts
export interface PriceDeviationEvidence {
  label: string;
  observedPrice?: string;
  referencePrice?: string;
  deviationBps?: number;
  referenceKind: 'tracked_field' | 'rolling_median' | 'fixed_range';
  extractionCoupled: boolean;
  incomplete?: boolean;
}

export interface ObjectBaselineEvidence {
  objectLabel: string;
  field: string;
  previousValue?: string;
  currentValue?: string;
  expectedRange?: string;
  anomalyKind: 'permission_change' | 'price_shift' | 'inventory_drop' | 'state_flip';
  senderAuthorized: boolean;
}

export interface FundFlowNode {
  address: string;
  role: 'sender' | 'gas_sponsor' | 'protected' | 'attacker' | 'intermediate';
}

export interface FundFlowEdge {
  from: string;
  to: string;
  coinType: string;
  amount: string;
  role: 'temporary_funding' | 'manipulation_target' | 'protected_outflow' | 'attacker_receipt' | 'intermediate_hop';
}

export interface FundFlowGraph {
  nodes: FundFlowNode[];
  edges: FundFlowEdge[];
  attackPathFound: boolean;
  pathRoles: string[];
  netProtectedOutflow: string;
  netAttackerGain: string;
}

export interface SuppressionDecision {
  applied: boolean;
  reasons: string[];
  originalSeverity: Severity;
  finalSeverity: Severity;
  confidencePenalty: number;
}

export interface RiskScore {
  riskScore: number;
  confidence: number;
  recommendedSeverity: Severity;
}

export interface DerivedEvidence {
  flashLikeFundingDetected?: boolean;
  priceDeviationBps?: number;
  suspiciousTargets?: string[];
  sameSensitiveCallRepeats?: Record<string, number>;
  valueExtractionDetected?: boolean;
  priceEvidence?: PriceDeviationEvidence[];
  baselineEvidence?: ObjectBaselineEvidence[];
  flowEvidence?: FundFlowGraph;
  suppression?: SuppressionDecision;
  risk?: RiskScore;
  evidenceSummary?: string[];
}
```

- [ ] **Step 4: 扩展运行时画像类型，为后续状态持久化留接口**

```ts
export interface ObjectBaselineProfile {
  projectId: string;
  objectLabel: string;
  fields: Record<string, {
    lastValue?: string;
    minValue?: string;
    maxValue?: string;
    lastSender?: string;
    lastUpdatedAt?: string;
  }>;
}

export interface PriceReferenceProfile {
  projectId: string;
  label: string;
  recentObservedPrices: string[];
  medianPrice?: string;
  updatedAt: string;
}

export interface AddressBehaviorProfile {
  projectId: string;
  address: string;
  lastSeenAt: string;
  recentIncidentFingerprints: string[];
}
```

- [ ] **Step 5: 运行测试确认通过**

Run: `npm test -- --run tests/project-monitor.spec.ts`
Expected: PASS 或至少进入下一个行为失败点，而不再因缺少类型/字段失败。

- [ ] **Step 6: 提交**

```bash
git add src/types.ts tests/project-monitor.spec.ts
git commit -m "feat: add evidence and profile types"
```

### Task 3: 实现价格偏离与对象基线提取器

**Files:**
- Create: `/Users/seem/Desktop/sui-guardian/src/detection/price-deviation.ts`
- Create: `/Users/seem/Desktop/sui-guardian/src/detection/object-baseline.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/src/project-monitor.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/price-deviation.spec.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/object-baseline.spec.ts`

- [ ] **Step 1: 写价格偏离失败测试**

```ts
import { describe, expect, it } from 'vitest';
import { detectPriceDeviation } from '../src/detection/price-deviation.js';

describe('detectPriceDeviation', () => {
  it('computes deviation using rolling median when no external reference exists', () => {
    const result = detectPriceDeviation({
      tx: buildTx(),
      project: buildProjectConfig(),
      trackedSnapshots: {
        'oracle-feed': { price: 5000 },
      },
      priceProfiles: {
        'oracle-price': {
          projectId: 'demo',
          label: 'oracle-price',
          recentObservedPrices: ['1000', '1020', '980'],
          medianPrice: '1000',
          updatedAt: '2026-04-24T00:00:00.000Z',
        },
      },
    });

    expect(result[0]?.deviationBps).toBe(40000);
    expect(result[0]?.referenceKind).toBe('rolling_median');
  });
});
```

- [ ] **Step 2: 写对象基线失败测试**

```ts
import { describe, expect, it } from 'vitest';
import { detectObjectBaselineAnomalies } from '../src/detection/object-baseline.js';

describe('detectObjectBaselineAnomalies', () => {
  it('flags unauthorized permission field changes', () => {
    const result = detectObjectBaselineAnomalies({
      tx: buildTx({ sender: ATTACKER }),
      project: buildProjectConfig(),
      previousSnapshots: {
        'admin-vault': { admin: ADMIN, vault: '1000' },
      },
      currentSnapshots: {
        'admin-vault': { admin: ATTACKER, vault: '1000' },
      },
    });

    expect(result[0]?.anomalyKind).toBe('permission_change');
    expect(result[0]?.senderAuthorized).toBe(false);
  });
});
```

- [ ] **Step 3: 运行测试确认失败**

Run: `npm test -- --run tests/price-deviation.spec.ts tests/object-baseline.spec.ts`
Expected: FAIL，提示找不到 `detectPriceDeviation` 或 `detectObjectBaselineAnomalies`。

- [ ] **Step 4: 实现价格偏离提取器最小代码**

```ts
import type { MonitoringProjectConfig, PriceDeviationEvidence, PriceReferenceProfile } from '../types.js';

interface PriceDeviationContext {
  tx: { balanceChanges: Array<{ amount: string }> };
  project: MonitoringProjectConfig;
  trackedSnapshots: Record<string, Record<string, unknown>>;
  priceProfiles: Record<string, PriceReferenceProfile>;
}

export function detectPriceDeviation(ctx: PriceDeviationContext): PriceDeviationEvidence[] {
  return ctx.project.priceModels.flatMap((model) => {
    const snapshot = ctx.trackedSnapshots[model.trackedObjectLabel] ?? {};
    const observedRaw = snapshot[model.observedFieldPath];
    if (observedRaw === undefined) {
      return [{
        label: model.label,
        referenceKind: model.referenceMode,
        extractionCoupled: false,
        incomplete: true,
      }];
    }

    const observed = Number(observedRaw);
    const profile = ctx.priceProfiles[model.label];
    const reference = model.referenceMode === 'rolling_median'
      ? Number(profile?.medianPrice ?? observedRaw)
      : Number(observedRaw);
    const deviationBps = reference === 0 ? 0 : Math.round((Math.abs(observed - reference) / reference) * 10_000);

    return [{
      label: model.label,
      observedPrice: String(observedRaw),
      referencePrice: String(reference),
      deviationBps,
      referenceKind: model.referenceMode,
      extractionCoupled: ctx.tx.balanceChanges.some((item) => item.amount.startsWith('-')),
    }];
  });
}
```

- [ ] **Step 5: 实现对象基线提取器最小代码**

```ts
import type { MonitoringProjectConfig, ObjectBaselineEvidence } from '../types.js';

interface ObjectBaselineContext {
  tx: { sender?: string };
  project: MonitoringProjectConfig;
  previousSnapshots: Record<string, Record<string, unknown>>;
  currentSnapshots: Record<string, Record<string, unknown>>;
}

export function detectObjectBaselineAnomalies(ctx: ObjectBaselineContext): ObjectBaselineEvidence[] {
  return ctx.project.objectBaselines.flatMap((baseline) =>
    baseline.fields.flatMap((field) => {
      const previous = ctx.previousSnapshots[baseline.trackedObjectLabel] ?? {};
      const current = ctx.currentSnapshots[baseline.trackedObjectLabel] ?? {};
      const previousValue = previous[field.path];
      const currentValue = current[field.path];

      if (previousValue === currentValue) {
        return [];
      }

      const senderAuthorized = (field.allowedSenders ?? []).some((sender) => sender.toLowerCase() === ctx.tx.sender?.toLowerCase());
      const anomalyKind =
        field.kind === 'permission' ? 'permission_change' :
        field.kind === 'price' ? 'price_shift' :
        field.kind === 'inventory' ? 'inventory_drop' :
        'state_flip';

      return [{
        objectLabel: baseline.trackedObjectLabel,
        field: field.path,
        previousValue: previousValue === undefined ? undefined : String(previousValue),
        currentValue: currentValue === undefined ? undefined : String(currentValue),
        anomalyKind,
        senderAuthorized,
        expectedRange: field.maxDeltaBps !== undefined ? `delta_bps<=${field.maxDeltaBps}` : undefined,
      }];
    }),
  );
}
```

- [ ] **Step 6: 在 `src/project-monitor.ts` 中先接入两个 extractor，合并到 `derived`**

```ts
const derived = this.buildDerivedSignals(tx);
derived.priceEvidence = detectPriceDeviation({
  tx,
  project: this.project,
  trackedSnapshots: this.getTrackedSnapshotContents(),
  priceProfiles: this.priceProfiles,
});
derived.baselineEvidence = detectObjectBaselineAnomalies({
  tx,
  project: this.project,
  previousSnapshots: this.previousTrackedSnapshotContents,
  currentSnapshots: this.getTrackedSnapshotContents(),
});
```

- [ ] **Step 7: 运行测试确认通过**

Run: `npm test -- --run tests/price-deviation.spec.ts tests/object-baseline.spec.ts tests/project-monitor.spec.ts`
Expected: PASS

- [ ] **Step 8: 提交**

```bash
git add src/detection/price-deviation.ts src/detection/object-baseline.ts src/project-monitor.ts tests/price-deviation.spec.ts tests/object-baseline.spec.ts tests/project-monitor.spec.ts
git commit -m "feat: add price and baseline evidence extractors"
```

### Task 4: 实现资金路径图与风险评分器

**Files:**
- Create: `/Users/seem/Desktop/sui-guardian/src/detection/fund-flow-graph.ts`
- Create: `/Users/seem/Desktop/sui-guardian/src/detection/risk-scorer.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/src/project-monitor.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/fund-flow-graph.spec.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/risk-scorer.spec.ts`

- [ ] **Step 1: 写资金路径图失败测试**

```ts
import { describe, expect, it } from 'vitest';
import { buildFundFlowGraph } from '../src/detection/fund-flow-graph.js';

describe('buildFundFlowGraph', () => {
  it('detects protected outflow and attacker receipt path', () => {
    const graph = buildFundFlowGraph({
      tx: buildTx({
        sender: ATTACKER,
        balanceChanges: [
          { owner: TREASURY, coinType: SUI, amount: '-1000' },
          { owner: ATTACKER, coinType: SUI, amount: '1000' },
        ],
      }),
      protectedAddresses: [TREASURY],
      attackerAddresses: [ATTACKER],
    });

    expect(graph.attackPathFound).toBe(true);
    expect(graph.netProtectedOutflow).toBe('1000');
    expect(graph.netAttackerGain).toBe('1000');
  });
});
```

- [ ] **Step 2: 写评分器失败测试**

```ts
import { describe, expect, it } from 'vitest';
import { scoreRisk } from '../src/detection/risk-scorer.js';

describe('scoreRisk', () => {
  it('elevates severity when price deviation, baseline anomaly and attack path align', () => {
    const risk = scoreRisk({
      priceEvidence: [{ label: 'oracle-price', deviationBps: 40000, referenceKind: 'rolling_median', extractionCoupled: true }],
      baselineEvidence: [{ objectLabel: 'admin-vault', field: 'admin', anomalyKind: 'permission_change', senderAuthorized: false }],
      flowEvidence: { nodes: [], edges: [], attackPathFound: true, pathRoles: ['protected_outflow', 'attacker_receipt'], netProtectedOutflow: '1000', netAttackerGain: '1000' },
    });

    expect(risk.riskScore).toBeGreaterThanOrEqual(80);
    expect(risk.recommendedSeverity).toBe('critical');
  });
});
```

- [ ] **Step 3: 运行测试确认失败**

Run: `npm test -- --run tests/fund-flow-graph.spec.ts tests/risk-scorer.spec.ts`
Expected: FAIL，提示找不到 `buildFundFlowGraph` 或 `scoreRisk`。

- [ ] **Step 4: 实现资金路径图最小代码**

```ts
import type { FundFlowGraph, ObservedTransaction } from '../types.js';

interface FundFlowGraphContext {
  tx: ObservedTransaction;
  protectedAddresses: string[];
  attackerAddresses: string[];
}

export function buildFundFlowGraph(ctx: FundFlowGraphContext): FundFlowGraph {
  let netProtectedOutflow = 0n;
  let netAttackerGain = 0n;

  for (const change of ctx.tx.balanceChanges) {
    const amount = BigInt(change.amount);
    if (change.owner && ctx.protectedAddresses.some((item) => item.toLowerCase() === change.owner?.toLowerCase()) && amount < 0n) {
      netProtectedOutflow += amount * -1n;
    }
    if (change.owner && ctx.attackerAddresses.some((item) => item.toLowerCase() === change.owner?.toLowerCase()) && amount > 0n) {
      netAttackerGain += amount;
    }
  }

  return {
    nodes: [],
    edges: [],
    attackPathFound: netProtectedOutflow > 0n && netAttackerGain > 0n,
    pathRoles: netProtectedOutflow > 0n && netAttackerGain > 0n ? ['protected_outflow', 'attacker_receipt'] : [],
    netProtectedOutflow: netProtectedOutflow.toString(),
    netAttackerGain: netAttackerGain.toString(),
  };
}
```

- [ ] **Step 5: 实现风险评分器最小代码**

```ts
import type { DerivedEvidence, RiskScore } from '../types.js';

export function scoreRisk(input: Pick<DerivedEvidence, 'priceEvidence' | 'baselineEvidence' | 'flowEvidence'>): RiskScore {
  let score = 0;

  const highDeviation = (input.priceEvidence ?? []).some((item) => (item.deviationBps ?? 0) >= 1500 && item.extractionCoupled);
  const permissionChange = (input.baselineEvidence ?? []).some((item) => item.anomalyKind === 'permission_change' && !item.senderAuthorized);
  const attackPath = input.flowEvidence?.attackPathFound ?? false;

  if (highDeviation) score += 35;
  if (permissionChange) score += 30;
  if (attackPath) score += 35;

  const recommendedSeverity =
    score >= 80 ? 'critical' :
    score >= 60 ? 'high' :
    score >= 40 ? 'medium' :
    score >= 20 ? 'low' :
    'info';

  return {
    riskScore: score,
    confidence: Math.min(1, score / 100),
    recommendedSeverity,
  };
}
```

- [ ] **Step 6: 在 `src/project-monitor.ts` 中接入资金图与评分结果**

```ts
derived.flowEvidence = buildFundFlowGraph({
  tx,
  protectedAddresses: this.project.protectedAddresses.map((item) => item.address),
  attackerAddresses: tx.sender ? [tx.sender] : [],
});
derived.risk = scoreRisk({
  priceEvidence: derived.priceEvidence,
  baselineEvidence: derived.baselineEvidence,
  flowEvidence: derived.flowEvidence,
});
derived.evidenceSummary = [
  ...(derived.priceEvidence ?? []).map((item) => `price:${item.label}:${item.deviationBps ?? 'na'}`),
  ...(derived.baselineEvidence ?? []).map((item) => `baseline:${item.objectLabel}.${item.field}:${item.anomalyKind}`),
  derived.flowEvidence?.attackPathFound ? 'flow:attack_path' : 'flow:no_attack_path',
];
```

- [ ] **Step 7: 运行测试确认通过**

Run: `npm test -- --run tests/fund-flow-graph.spec.ts tests/risk-scorer.spec.ts tests/project-monitor.spec.ts`
Expected: PASS

- [ ] **Step 8: 提交**

```bash
git add src/detection/fund-flow-graph.ts src/detection/risk-scorer.ts src/project-monitor.ts tests/fund-flow-graph.spec.ts tests/risk-scorer.spec.ts tests/project-monitor.spec.ts
git commit -m "feat: add flow graph and risk scoring"
```

### Task 5: 实现误报抑制并改造行为规则消费评分结果

**Files:**
- Create: `/Users/seem/Desktop/sui-guardian/src/detection/false-positive-suppression.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/src/behavior-rules.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/src/project-monitor.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/false-positive-suppression.spec.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/behavior-rules.spec.ts`

- [ ] **Step 1: 写误报抑制失败测试**

```ts
import { describe, expect, it } from 'vitest';
import { applyFalsePositiveSuppression } from '../src/detection/false-positive-suppression.js';

describe('applyFalsePositiveSuppression', () => {
  it('downgrades weak single signal events during maintenance window', () => {
    const decision = applyFalsePositiveSuppression({
      tx: buildTx({ sender: ADMIN, timestamp: '2026-04-24T02:30:00.000Z' }),
      project: buildProjectConfig(),
      risk: { riskScore: 30, confidence: 0.3, recommendedSeverity: 'medium' },
      evidenceSummary: ['baseline:oracle-feed.mode:state_flip'],
      senderAuthorized: true,
    });

    expect(decision.applied).toBe(true);
    expect(decision.finalSeverity).toBe('low');
  });
});
```

- [ ] **Step 2: 写行为规则失败测试，确认其消费评分结果**

```ts
import { describe, expect, it } from 'vitest';
import { runBehaviorRules } from '../src/behavior-rules.js';

describe('behavior rules with risk evidence', () => {
  it('emits price manipulation alert from evidence-backed critical score', () => {
    const alerts = runBehaviorRules({
      projectId: 'demo',
      projectName: 'Demo',
      tx: buildTx(),
      protectedAddresses: [TREASURY],
      sensitiveCalls: [],
      derived: {
        valueExtractionDetected: true,
        priceEvidence: [{ label: 'oracle-price', deviationBps: 40000, referenceKind: 'rolling_median', extractionCoupled: true }],
        risk: { riskScore: 90, confidence: 0.9, recommendedSeverity: 'critical' },
        evidenceSummary: ['price:oracle-price:40000'],
      },
    });

    expect(alerts.some((alert) => alert.ruleId === 'behavior:price-manipulation')).toBe(true);
  });
});
```

- [ ] **Step 3: 运行测试确认失败**

Run: `npm test -- --run tests/false-positive-suppression.spec.ts tests/behavior-rules.spec.ts`
Expected: FAIL，提示找不到 `applyFalsePositiveSuppression` 或行为规则未使用风险证据。

- [ ] **Step 4: 实现误报抑制器最小代码**

```ts
import type { MonitoringProjectConfig, RiskScore, SuppressionDecision } from '../types.js';

interface SuppressionContext {
  tx: { sender?: string; timestamp: string };
  project: MonitoringProjectConfig;
  risk: RiskScore;
  evidenceSummary: string[];
  senderAuthorized: boolean;
}

export function applyFalsePositiveSuppression(ctx: SuppressionContext): SuppressionDecision {
  let finalSeverity = ctx.risk.recommendedSeverity;
  let confidencePenalty = 0;
  const reasons: string[] = [];

  const hour = new Date(ctx.tx.timestamp).getUTCHours();
  const inMaintenanceWindow = ctx.project.suppression.maintenanceWindows.some((window) =>
    window.allowedSenders.some((sender) => sender.toLowerCase() === ctx.tx.sender?.toLowerCase()) &&
    hour >= window.startHourUtc &&
    hour <= window.endHourUtc,
  );

  const weakSingleSignal = ctx.evidenceSummary.length <= 1 && ctx.risk.riskScore <= ctx.project.suppression.weakSignalScoreThreshold;

  if (inMaintenanceWindow) {
    reasons.push('maintenance_window_suppression');
    confidencePenalty += 0.2;
  }

  if (ctx.senderAuthorized && weakSingleSignal) {
    reasons.push('authorized_sender_suppression');
    confidencePenalty += 0.2;
  }

  if (finalSeverity === 'medium' && reasons.length > 0) {
    finalSeverity = 'low';
  } else if (finalSeverity === 'high' && reasons.length > 0) {
    finalSeverity = 'medium';
  } else if (finalSeverity === 'critical' && reasons.length > 0) {
    finalSeverity = 'high';
  }

  return {
    applied: reasons.length > 0,
    reasons,
    originalSeverity: ctx.risk.recommendedSeverity,
    finalSeverity,
    confidencePenalty,
  };
}
```

- [ ] **Step 5: 改造 `src/behavior-rules.ts` 让价格操纵规则消费增强证据**

```ts
function detectPriceManipulation(ctx: RuleContext): Alert[] {
  const matched = (ctx.derived?.priceEvidence ?? []).find((item) => (item.deviationBps ?? 0) >= 1500 && item.extractionCoupled);
  if (!matched || (ctx.derived?.risk?.recommendedSeverity ?? 'info') === 'info') {
    return [];
  }

  return [
    createAlert({
      projectId: ctx.projectId,
      projectName: ctx.projectName,
      ruleId: 'behavior:price-manipulation',
      ruleName: '行为规则 / 价格操纵后价值提取',
      severity: ctx.derived?.suppression?.finalSeverity ?? ctx.derived?.risk?.recommendedSeverity ?? 'critical',
      summary: `价格偏离 ${matched.deviationBps} bps，且同交易发生价值提取动作`,
      details: {
        digest: ctx.tx.digest,
        checkpoint: ctx.tx.checkpoint,
        sender: ctx.tx.sender,
        priceDeviationBps: matched.deviationBps,
        riskScore: ctx.derived?.risk?.riskScore,
        confidence: ctx.derived?.risk?.confidence,
        evidenceSummary: ctx.derived?.evidenceSummary,
      },
    }),
  ];
}
```

- [ ] **Step 6: 在 `src/project-monitor.ts` 中接入 suppression，并把评分结果注入 alert details**

```ts
derived.suppression = applyFalsePositiveSuppression({
  tx,
  project: this.project,
  risk: derived.risk ?? { riskScore: 0, confidence: 0, recommendedSeverity: 'info' },
  evidenceSummary: derived.evidenceSummary ?? [],
  senderAuthorized: this.isKnownAuthorizedSender(tx.sender),
});
```

- [ ] **Step 7: 运行测试确认通过**

Run: `npm test -- --run tests/false-positive-suppression.spec.ts tests/behavior-rules.spec.ts tests/project-monitor.spec.ts`
Expected: PASS

- [ ] **Step 8: 提交**

```bash
git add src/detection/false-positive-suppression.ts src/behavior-rules.ts src/project-monitor.ts tests/false-positive-suppression.spec.ts tests/behavior-rules.spec.ts tests/project-monitor.spec.ts
git commit -m "feat: add false positive suppression"
```

### Task 6: 扩展状态持久化、API 与 Dashboard 展示

**Files:**
- Modify: `/Users/seem/Desktop/sui-guardian/src/monitor-service.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/src/dashboard.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/src/server.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/monitor-service.spec.ts`

- [ ] **Step 1: 写失败测试，确认 incident 证据包含评分、路径和抑制信息**

```ts
import { describe, expect, it } from 'vitest';

describe('monitor service hardening evidence', () => {
  it('exposes risk scoring, flow evidence and suppression details', () => {
    const incidents = service.getIncidentTimeline();
    const first = incidents[0];

    expect(first).toHaveProperty('riskScore');
    expect(first).toHaveProperty('fundFlows');
    expect(first).toHaveProperty('suppressionReasons');
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `npm test -- --run tests/monitor-service.spec.ts`
Expected: FAIL，提示 `riskScore`、`suppressionReasons` 或增强 `fundFlows` 字段不存在。

- [ ] **Step 3: 在 `src/monitor-service.ts` 中扩展状态与时间线聚合**

```ts
const riskScore = typeof alert.details.riskScore === 'number' ? alert.details.riskScore : undefined;
const suppressionReasons = Array.isArray(alert.details.suppressionReasons)
  ? alert.details.suppressionReasons.map(String)
  : [];

grouped.push({
  projectId: alert.projectId,
  projectName: alert.projectName,
  category,
  startedAt: alert.firstSeenAt,
  updatedAt: alert.lastSeenAt,
  alerts: [alert],
  digests,
  senders: Array.from(senders),
  addresses: Array.from(addresses),
  fieldChanges,
  fundFlows,
  riskScore,
  suppressionReasons,
});
```

- [ ] **Step 4: 在 `src/server.ts` 中透传增强字段**

```ts
app.get('/api/incidents', async () => ({
  incidents: monitorService.getIncidentTimeline().map((incident) => ({
    ...incident,
    riskScore: incident.riskScore ?? null,
    suppressionReasons: incident.suppressionReasons ?? [],
  })),
}));
```

- [ ] **Step 5: 在 `src/dashboard.ts` 中增加评分、价格依据和抑制信息展示**

```ts
'<div style="margin-top:8px;color:#9fb0c8;">风险评分：' +
escapeHtml(String(alert.riskScore ?? 'n/a')) +
'；抑制原因：' +
escapeHtml((alert.suppressionReasons ?? []).join(', ') || '无') +
'</div>'
```

- [ ] **Step 6: 运行测试确认通过**

Run: `npm test -- --run tests/monitor-service.spec.ts`
Expected: PASS

- [ ] **Step 7: 提交**

```bash
git add src/monitor-service.ts src/server.ts src/dashboard.ts tests/monitor-service.spec.ts
git commit -m "feat: expose hardening evidence in api and dashboard"
```

### Task 7: 全量回归、类型检查与诊断

**Files:**
- Modify: `/Users/seem/Desktop/sui-guardian/tests/project-monitor.spec.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/tests/behavior-rules.spec.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/tests/monitor-service.spec.ts`

- [ ] **Step 1: 增加组合场景回归测试**

```ts
it('produces critical incident when price deviation, permission takeover and protected outflow align', () => {
  const alerts = monitor.processTransaction(buildTx({
    sender: ATTACKER,
    calls: [
      { package: PACKAGE, module: 'oracle', function: 'update_price' },
      { package: PACKAGE, module: 'vault', function: 'emergency_withdraw' },
    ],
    balanceChanges: [
      { owner: TREASURY, coinType: SUI, amount: '-1500' },
      { owner: ATTACKER, coinType: SUI, amount: '1500' },
    ],
  }));

  expect(alerts.some((alert) => alert.severity === 'critical')).toBe(true);
  expect(alerts.some((alert) => alert.details.riskScore === 100 || Number(alert.details.riskScore) >= 80)).toBe(true);
});
```

- [ ] **Step 2: 跑全部单测**

Run: `npm test`
Expected: PASS

- [ ] **Step 3: 跑类型检查**

Run: `npm run typecheck`
Expected: PASS

- [ ] **Step 4: 获取最近改动文件的诊断**

Run: VS Code diagnostics for `src/types.ts`, `src/config.ts`, `src/project-monitor.ts`, `src/behavior-rules.ts`, `src/monitor-service.ts`, `src/dashboard.ts`, `src/server.ts`, `src/detection/*.ts`
Expected: 无新增错误

- [ ] **Step 5: 提交**

```bash
git add tests/project-monitor.spec.ts tests/behavior-rules.spec.ts tests/monitor-service.spec.ts src
git commit -m "test: cover detection hardening scenarios"
```
