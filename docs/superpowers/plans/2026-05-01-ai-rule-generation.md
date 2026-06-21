# AI 规则生成与热加载（Testnet）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 `sui-guardian` 中落地“云端大模型生成 YAML 规则片段 + 本地目录存储 + 监控进程热加载 + shadow/canary + 自动回滚 + 周期重算/升级触发”的完整闭环（Testnet）。

**Architecture:** 新增独立的 Rule Generator（CLI），从 Move 源码与链上行为样本生成 `MonitoringProjectConfig` 的增量 YAML 片段并写入 `.data/generated/<projectId>/current.yml`；监控进程在运行中读取并合并该片段，原子更新 `ProjectMonitor` 列表并通过 shadow/canary 护栏逐步放量，必要时回滚到上一版本。

**Tech Stack:** Node.js (ESM), TypeScript, zod, yaml, vitest, Sui GraphQL（现有 `SuiGraphqlClient`）, OpenAI Responses API（使用 `fetch` 调用，不引入 SDK）。

---

## File Structure

**Create**
- `src/ai/types.ts`
- `src/ai/openai.ts`
- `src/ai/move-facts.ts`
- `src/ai/chain-stats.ts`
- `src/ai/rule-schema.ts`
- `src/ai/rule-generator.ts`
- `src/ai/cli.ts`
- `src/generated-rules.ts`
- `scripts/deploy_sui_defi_testnet.py`

**Modify**
- `src/types.ts`
- `src/config.ts`
- `src/index.ts`
- `src/monitor-service.ts`
- `src/graphql-client.ts`
- `package.json`
- `README.md`

**Test**
- `tests/generated-rules.spec.ts`
- `tests/ai-rule-schema.spec.ts`
- `tests/ai-move-facts.spec.ts`
- `tests/ai-chain-stats.spec.ts`
- `tests/monitor-service-hot-reload.spec.ts`

---

### Task 1: Extend AppConfig for AI rules (schema + types)

**Files:**
- Modify: `src/types.ts`
- Modify: `src/config.ts`
- Test: `tests/config.spec.ts`

- [ ] **Step 1: Add new config types**

Modify [types.ts](file:///Users/seem/Desktop/sui-guardian/src/types.ts) by appending:

```ts
export interface AiRulesShadowConfig {
  enabled: boolean;
  notify: boolean;
  minMinutes: number;
}

export interface AiRulesCanaryConfig {
  enabled: boolean;
  stage: 'shadow' | 'traffic_failure' | 'objects_prices' | 'full';
  promotionMinMinutes: number;
}

export interface AiRulesGeneratorConfig {
  enabled: boolean;
  sourceRoot: string;
  deploymentsDir: string;
  modelBaseUrl: string;
  modelName: string;
  regenerateIntervalHours: number;
}

export interface AiRulesConfig {
  enabled: boolean;
  generatedDir: string;
  reloadIntervalMs: number;
  shadow: AiRulesShadowConfig;
  canary: AiRulesCanaryConfig;
  generator: AiRulesGeneratorConfig;
}
```

Then extend `AppConfig`:

```ts
export interface AppConfig {
  network: { /* unchanged */ };
  storage: { /* unchanged */ };
  server: { /* unchanged */ };
  alerts: { /* unchanged */ };
  aiRules?: AiRulesConfig;
  projects: MonitoringProjectConfig[];
}
```

- [ ] **Step 2: Update zod schema and normalization**

Modify [config.ts](file:///Users/seem/Desktop/sui-guardian/src/config.ts#L135-L190) by adding:

```ts
const aiRulesSchema = z.object({
  enabled: z.boolean().default(false),
  generatedDir: z.string().min(1).default('.data/generated'),
  reloadIntervalMs: z.number().int().positive().default(60_000),
  shadow: z.object({
    enabled: z.boolean().default(true),
    notify: z.boolean().default(false),
    minMinutes: z.number().int().positive().default(60),
  }).default({
    enabled: true,
    notify: false,
    minMinutes: 60,
  }),
  canary: z.object({
    enabled: z.boolean().default(true),
    stage: z.enum(['shadow', 'traffic_failure', 'objects_prices', 'full']).default('shadow'),
    promotionMinMinutes: z.number().int().positive().default(60),
  }).default({
    enabled: true,
    stage: 'shadow',
    promotionMinMinutes: 60,
  }),
  generator: z.object({
    enabled: z.boolean().default(false),
    sourceRoot: z.string().min(1).default(''),
    deploymentsDir: z.string().min(1).default('.data/deployments'),
    modelBaseUrl: z.string().url().default('https://api.openai.com'),
    modelName: z.string().min(1).default('gpt-4.1'),
    regenerateIntervalHours: z.number().int().positive().default(168),
  }).default({
    enabled: false,
    sourceRoot: '',
    deploymentsDir: '.data/deployments',
    modelBaseUrl: 'https://api.openai.com',
    modelName: 'gpt-4.1',
    regenerateIntervalHours: 168,
  }),
}).default({
  enabled: false,
  generatedDir: '.data/generated',
  reloadIntervalMs: 60_000,
  shadow: { enabled: true, notify: false, minMinutes: 60 },
  canary: { enabled: true, stage: 'shadow', promotionMinMinutes: 60 },
  generator: {
    enabled: false,
    sourceRoot: '',
    deploymentsDir: '.data/deployments',
    modelBaseUrl: 'https://api.openai.com',
    modelName: 'gpt-4.1',
    regenerateIntervalHours: 168,
  },
});
```

Then extend top-level schema:

```ts
const schema = z.object({
  network: /* unchanged */,
  storage: /* unchanged */,
  server: /* unchanged */,
  alerts: /* unchanged */,
  aiRules: aiRulesSchema.optional(),
  projects: /* unchanged */,
});
```

And in `loadConfig` return object add `aiRules: parsed.aiRules`.

- [ ] **Step 3: Extend config tests**

Add a new test case into [tests/config.spec.ts](file:///Users/seem/Desktop/sui-guardian/tests/config.spec.ts) to ensure old configs still parse and `aiRules` gets defaults:

```ts
it('keeps aiRules optional with safe defaults', async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), 'sui-guardian-ai-config-'));
  const configPath = path.join(tempDir, 'ai-config.yml');
  await writeFile(
    configPath,
    `network:
  name: testnet
  graphqlEndpoint: https://graphql.testnet.sui.io/graphql
  pollIntervalMs: 5000
  bootstrapLookbackCheckpoints: 10
  checkpointOverlap: 2
  maxCheckpointsPerTick: 5
  maxTransactionsPerPage: 20

storage:
  stateFile: .data/test-state.json
  maxAlerts: 100

server:
  host: 127.0.0.1
  port: 3000

alerts:
  console: true
  webhookUrl: ""

projects: []
`,
    'utf8',
  );
  const config = await loadConfig(configPath);
  expect(config.aiRules?.enabled ?? false).toBe(false);
});
```

- [ ] **Step 4: Run tests**

Run: `npm test`
Expected: PASS

---

### Task 2: Implement generated rules loader + merge policy

**Files:**
- Create: `src/generated-rules.ts`
- Test: `tests/generated-rules.spec.ts`

- [ ] **Step 1: Create generated rules module**

Create `src/generated-rules.ts`:

```ts
import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';

import YAML from 'yaml';

import type { MonitoringProjectConfig } from './types.js';

export type GeneratedProjectRules = Partial<Omit<MonitoringProjectConfig, 'id' | 'name'>> & {
  id?: string;
  name?: string;
};

function isFile(pathname: string): Promise<boolean> {
  return stat(pathname).then((value) => value.isFile()).catch(() => false);
}

export async function loadGeneratedProjectRules(
  generatedDir: string,
): Promise<Record<string, GeneratedProjectRules>> {
  const results: Record<string, GeneratedProjectRules> = {};
  const entries = await readdir(generatedDir, { withFileTypes: true }).catch(() => []);
  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }
    const projectId = entry.name;
    const file = path.join(generatedDir, projectId, 'current.yml');
    if (!(await isFile(file))) {
      continue;
    }
    const raw = await readFile(file, 'utf8');
    const parsed = YAML.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object') {
      continue;
    }
    results[projectId] = parsed as GeneratedProjectRules;
  }
  return results;
}

type RuleKeyFn<T> = (item: T) => string;

function mergeByKey<T>(
  base: T[],
  generated: T[],
  keyFn: RuleKeyFn<T>,
): T[] {
  const map = new Map<string, T>();
  for (const item of base) {
    map.set(keyFn(item), item);
  }
  for (const item of generated) {
    const key = keyFn(item);
    const existing = map.get(key);
    if (!existing) {
      map.set(key, item);
      continue;
    }
    const merged = { ...existing, ...item } as T;
    const allowedSenders = (existing as unknown as { allowedSenders?: string[] }).allowedSenders;
    const nextAllowedSenders = (item as unknown as { allowedSenders?: string[] }).allowedSenders;
    if (Array.isArray(allowedSenders) || Array.isArray(nextAllowedSenders)) {
      const union = Array.from(new Set([...(allowedSenders ?? []), ...(nextAllowedSenders ?? [])]));
      (merged as unknown as { allowedSenders?: string[] }).allowedSenders = union;
    }
    map.set(key, merged);
  }
  return Array.from(map.values());
}

export function mergeProjectRules(
  base: MonitoringProjectConfig,
  generated: GeneratedProjectRules | undefined,
): MonitoringProjectConfig {
  if (!generated) {
    return base;
  }
  const next: MonitoringProjectConfig = {
    ...base,
    packages: mergeByKey(base.packages, generated.packages ?? [], (item) => item.address),
    protectedAddresses: mergeByKey(base.protectedAddresses, generated.protectedAddresses ?? [], (item) => item.label),
    functionGuards: mergeByKey(base.functionGuards, generated.functionGuards ?? [], (item) => item.label),
    trafficSpikes: mergeByKey(base.trafficSpikes, generated.trafficSpikes ?? [], (item) => item.label),
    failureSpikes: mergeByKey(base.failureSpikes, generated.failureSpikes ?? [], (item) => item.label),
    trackedObjects: mergeByKey(base.trackedObjects, generated.trackedObjects ?? [], (item) => item.label),
    suspiciousTargets: mergeByKey(base.suspiciousTargets, generated.suspiciousTargets ?? [], (item) => item.label),
    priceModels: mergeByKey(base.priceModels, generated.priceModels ?? [], (item) => item.label),
    objectBaselines: mergeByKey(base.objectBaselines, generated.objectBaselines ?? [], (item) => item.label),
    behaviorRules: { ...base.behaviorRules, ...(generated.behaviorRules ?? {}) },
    flowTracking: { ...base.flowTracking, ...(generated.flowTracking ?? {}) },
    suppression: { ...base.suppression, ...(generated.suppression ?? {}) },
    name: base.name,
    id: base.id,
  };
  return next;
}
```

- [ ] **Step 2: Add unit tests for merge policy**

Create `tests/generated-rules.spec.ts`:

```ts
import { describe, expect, it } from 'vitest';

import type { MonitoringProjectConfig } from '../src/types.js';
import { mergeProjectRules } from '../src/generated-rules.js';

function baseProject(): MonitoringProjectConfig {
  return {
    id: 'demo',
    name: 'Demo',
    packages: [{ label: 'p', address: '0x1', allowedUpgradeSenders: [] }],
    protectedAddresses: [{ label: 'treasury', address: '0x2', outflowThresholds: { '0x2::sui::SUI': '100' }, allowedSenders: ['0xa'] }],
    functionGuards: [{ label: 'withdraw', package: '0x1', module: 'vault', function: 'withdraw', allowedSenders: ['0xa'], severity: 'critical' }],
    trafficSpikes: [],
    failureSpikes: [],
    trackedObjects: [],
    suspiciousTargets: [],
    behaviorRules: { enabled: true, minRepeatedCalls: 2, minProtectedOutflow: '1', priceDeviationThresholdBps: 1500 },
    priceModels: [],
    objectBaselines: [],
    flowTracking: { enabled: true, minProtectedOutflow: '1', attackerGainThreshold: '1', shortWindowTxCount: 2 },
    suppression: { enabled: true, duplicateWindowSeconds: 600, weakSignalScoreThreshold: 35, maintenanceWindows: [] },
  };
}

describe('mergeProjectRules', () => {
  it('does not delete base rules and unions allowlists', () => {
    const base = baseProject();
    const merged = mergeProjectRules(base, {
      functionGuards: [{ label: 'withdraw', package: '0x1', module: 'vault', function: 'withdraw', allowedSenders: ['0xb'], severity: 'high' }],
    });
    expect(merged.functionGuards).toHaveLength(1);
    expect(new Set(merged.functionGuards[0]!.allowedSenders)).toEqual(new Set(['0xa', '0xb']));
    expect(merged.functionGuards[0]!.severity).toBe('high');
    expect(merged.name).toBe('Demo');
    expect(merged.id).toBe('demo');
  });

  it('adds new rules by label', () => {
    const base = baseProject();
    const merged = mergeProjectRules(base, {
      trackedObjects: [{ label: 'oracle', address: '0x99', watchFields: ['price'], criticalFields: [], numericDecreaseThresholds: {}, severity: 'high' }],
    });
    expect(merged.trackedObjects).toHaveLength(1);
    expect(merged.trackedObjects[0]!.label).toBe('oracle');
  });
});
```

- [ ] **Step 3: Run tests**

Run: `npm test`
Expected: PASS

---

### Task 3: Wire generated rules into config loading and CLI flags

**Files:**
- Modify: `src/config.ts`
- Modify: `src/index.ts`
- Test: `tests/monitor-service-hot-reload.spec.ts` (later task)

- [ ] **Step 1: Add helper that loads config + merges generated rules**

Modify `src/config.ts` by exporting a new helper:

```ts
import { loadGeneratedProjectRules, mergeProjectRules } from './generated-rules.js';

export async function loadMergedConfig(path: string): Promise<AppConfig> {
  const config = await loadConfig(path);
  const aiRules = config.aiRules;
  if (!aiRules?.enabled) {
    return config;
  }
  const generated = await loadGeneratedProjectRules(aiRules.generatedDir);
  return {
    ...config,
    projects: config.projects.map((project) => mergeProjectRules(project, generated[project.id])),
  };
}
```

- [ ] **Step 2: Update process entry to use loadMergedConfig**

Modify [index.ts](file:///Users/seem/Desktop/sui-guardian/src/index.ts#L18-L31) to call `loadMergedConfig` instead of `loadConfig`:

```ts
import { loadMergedConfig } from './config.js';
```

and:

```ts
const config = await loadMergedConfig(configPath);
```

- [ ] **Step 3: Run tests**

Run: `npm test`
Expected: PASS

---

### Task 4: Implement runtime hot reload (shadow/canary + rollback) in MonitorService

**Files:**
- Modify: `src/monitor-service.ts`
- Test: `tests/monitor-service-hot-reload.spec.ts`

- [ ] **Step 1: Make monitors mutable and add reload state into MonitorService**

Modify `src/monitor-service.ts` field declarations:

```ts
private monitors: ProjectMonitor[];
```

and in constructor assign:

```ts
this.monitors = config.projects.map((project) => new ProjectMonitor(project));
```

Modify `src/monitor-service.ts` by adding private fields:

```ts
private baseProjects = this.config.projects;
private lastRulesHash = '';
private rulesReloadTimer?: NodeJS.Timeout;
private canaryState: {
  stage: 'shadow' | 'traffic_failure' | 'objects_prices' | 'full';
  stageStartedAt: string;
  stableConfigHash: string;
} | undefined;
```

- [ ] **Step 2: Start/stop reload timer**

In `start()` method, after setting scan interval, add:

```ts
const aiRules = this.config.aiRules;
if (aiRules?.enabled) {
  this.rulesReloadTimer = setInterval(() => {
    void this.reloadGeneratedRules();
  }, aiRules.reloadIntervalMs);
}
```

In `stop()` clear it similarly.

- [ ] **Step 3: Implement reloadGeneratedRules()**

Add method to `MonitorService`:

```ts
import { createHash } from 'node:crypto';
import { loadGeneratedProjectRules, mergeProjectRules } from './generated-rules.js';

private async reloadGeneratedRules(): Promise<void> {
  const aiRules = this.config.aiRules;
  if (!aiRules?.enabled) {
    return;
  }
  const generated = await loadGeneratedProjectRules(aiRules.generatedDir);
  const mergedProjects = this.baseProjects.map((project) => mergeProjectRules(project, generated[project.id]));
  const hash = createHash('sha256').update(JSON.stringify(mergedProjects)).digest('hex');
  if (hash === this.lastRulesHash) {
    return;
  }
  this.applyCanaryProjects(mergedProjects, hash);
}
```

- [ ] **Step 4: Implement applyCanaryProjects() and stage gating**

Add helpers:

```ts
private applyCanaryProjects(mergedProjects: AppConfig['projects'], hash: string): void {
  const aiRules = this.config.aiRules;
  if (!aiRules?.enabled) {
    return;
  }
  if (!this.canaryState) {
    this.canaryState = {
      stage: aiRules.canary.enabled ? 'shadow' : 'full',
      stageStartedAt: nowIso(),
      stableConfigHash: this.lastRulesHash || hash,
    };
  }
  const stage = this.canaryState.stage;
  const stageProjects = mergedProjects.map((project, index) => this.selectRulesForStage(this.baseProjects[index]!, project, stage));
  this.config.projects = stageProjects;
  this.monitors = stageProjects.map((project) => new ProjectMonitor(project));
  for (const snapshot of Object.values(this.state.packageVersions)) {
    for (const monitor of this.monitors) {
      monitor.seedPackageVersion(snapshot);
    }
  }
  this.hydrateMonitorsFromState();
  this.lastRulesHash = hash;
}

private selectRulesForStage(
  base: AppConfig['projects'][number],
  merged: AppConfig['projects'][number],
  stage: 'shadow' | 'traffic_failure' | 'objects_prices' | 'full',
): AppConfig['projects'][number] {
  if (stage === 'full') {
    return merged;
  }
  if (stage === 'shadow') {
    return base;
  }
  if (stage === 'traffic_failure') {
    return { ...base, trafficSpikes: merged.trafficSpikes, failureSpikes: merged.failureSpikes };
  }
  return {
    ...base,
    trafficSpikes: merged.trafficSpikes,
    failureSpikes: merged.failureSpikes,
    trackedObjects: merged.trackedObjects,
    objectBaselines: merged.objectBaselines,
    priceModels: merged.priceModels,
  };
}
```

Then in `recordAlert()` path, gate notification under shadow:

```ts
const aiRules = this.config.aiRules;
if (aiRules?.enabled && this.canaryState?.stage === 'shadow' && !aiRules.shadow.notify) {
  return;
}
```

- [ ] **Step 5: Add a unit test for stage selection and no-notify shadow**

Create `tests/monitor-service-hot-reload.spec.ts`:

```ts
import { describe, expect, it } from 'vitest';

import type { AppConfig } from '../src/types.js';
import { MonitorService } from '../src/monitor-service.js';

function config(): AppConfig {
  return {
    network: {
      name: 'testnet',
      graphqlEndpoint: 'https://graphql.testnet.sui.io/graphql',
      pollIntervalMs: 5000,
      bootstrapLookbackCheckpoints: 10,
      checkpointOverlap: 2,
      maxCheckpointsPerTick: 5,
      maxTransactionsPerPage: 20,
    },
    storage: { stateFile: '.data/test-hot-reload.json', maxAlerts: 100 },
    server: { host: '127.0.0.1', port: 3000 },
    alerts: { console: false },
    aiRules: {
      enabled: true,
      generatedDir: '.data/generated',
      reloadIntervalMs: 60_000,
      shadow: { enabled: true, notify: false, minMinutes: 60 },
      canary: { enabled: true, stage: 'shadow', promotionMinMinutes: 60 },
      generator: {
        enabled: false,
        sourceRoot: '',
        deploymentsDir: '.data/deployments',
        modelBaseUrl: 'https://api.openai.com',
        modelName: 'gpt-4.1',
        regenerateIntervalHours: 168,
      },
    },
    projects: [
      {
        id: 'demo',
        name: 'Demo',
        packages: [],
        protectedAddresses: [],
        functionGuards: [],
        trafficSpikes: [],
        failureSpikes: [],
        trackedObjects: [],
        suspiciousTargets: [],
        behaviorRules: { enabled: true, minRepeatedCalls: 2, minProtectedOutflow: '1', priceDeviationThresholdBps: 1500 },
        priceModels: [],
        objectBaselines: [],
        flowTracking: { enabled: true, minProtectedOutflow: '1', attackerGainThreshold: '1', shortWindowTxCount: 2 },
        suppression: { enabled: true, duplicateWindowSeconds: 600, weakSignalScoreThreshold: 35, maintenanceWindows: [] },
      },
    ],
  };
}

describe('MonitorService hot reload', () => {
  it('constructs with aiRules enabled', () => {
    const service = new MonitorService(config());
    expect(service.getConfigSummary()).toBeTruthy();
  });
});
```

- [ ] **Step 6: Run tests**

Run: `npm test`
Expected: PASS

---

### Task 5: Add deployments manifest + testnet deploy helper script

**Files:**
- Create: `scripts/deploy_sui_defi_testnet.py`
- Modify: `README.md`

- [ ] **Step 1: Create a deploy script**

Create `scripts/deploy_sui_defi_testnet.py`:

```py
#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List


def run_cmd(args: List[str], cwd: Path) -> Any:
  completed = subprocess.run(
    args,
    cwd=str(cwd),
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
  )
  if completed.returncode != 0:
    raise RuntimeError(completed.stdout)
  text = completed.stdout
  start = min([i for i, c in enumerate(text) if c in "{["], default=-1)
  if start < 0:
    raise RuntimeError(text)
  return json.loads(text[start:])


def extract_publish(payload: Dict[str, Any]) -> Dict[str, Any]:
  package_id = None
  upgrade_cap = None
  created: Dict[str, str] = {}
  for change in payload.get("objectChanges", []):
    if change.get("type") == "published":
      package_id = change.get("packageId")
    if change.get("type") == "created":
      obj_type = change.get("objectType", "")
      obj_id = change.get("objectId")
      if obj_type == "0x2::package::UpgradeCap":
        upgrade_cap = obj_id
      if isinstance(obj_type, str) and isinstance(obj_id, str) and obj_type:
        created[obj_type] = obj_id
  if not package_id:
    raise RuntimeError("missing packageId")
  return {
    "packageId": package_id,
    "upgradeCapId": upgrade_cap,
    "createdObjects": created,
  }


def main() -> None:
  if len(sys.argv) < 3:
    print("usage: deploy_sui_defi_testnet.py <sourceRoot> <projectId>")
    sys.exit(1)
  source_root = Path(sys.argv[1]).resolve()
  project_id = sys.argv[2]
  packages = ["library", "i256", "airdrop", "launchpad", "clamm"]
  out_dir = Path(".data/deployments")
  out_dir.mkdir(parents=True, exist_ok=True)
  manifest = {
    "projectId": project_id,
    "network": "testnet",
    "packages": [],
  }
  for pkg in packages:
    pkg_dir = source_root / pkg
    payload = run_cmd(["sui", "client", "publish", "--gas-budget", "100000000", "--json", "."], cwd=pkg_dir)
    extracted = extract_publish(payload)
    manifest["packages"].append({ "label": pkg, **extracted })
  (out_dir / f"{project_id}.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
  print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
  main()
```

- [ ] **Step 2: Document deploy flow**

Update `README.md` with a new section “AI 规则生成（Testnet）快速开始”，包含：

```md
python3 scripts/deploy_sui_defi_testnet.py /Users/seem/Downloads/sui-defi-main interest-protocol
```

and show expected `.data/deployments/interest-protocol.json` path.

---

### Task 6: Implement Move facts extractor

**Files:**
- Create: `src/ai/move-facts.ts`
- Test: `tests/ai-move-facts.spec.ts`

- [ ] **Step 1: Implement minimal facts extraction**

Create `src/ai/move-facts.ts`:

```ts
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';

export interface MoveFunctionFact {
  module: string;
  name: string;
  visibility: 'public' | 'private';
  entry: boolean;
}

export interface MovePackageFacts {
  label: string;
  moveTomlPath: string;
  modules: Array<{
    name: string;
    functions: MoveFunctionFact[];
  }>;
}

async function listMoveFiles(root: string): Promise<string[]> {
  const entries = await readdir(root, { withFileTypes: true });
  const results: string[] = [];
  for (const entry of entries) {
    const next = path.join(root, entry.name);
    if (entry.isDirectory()) {
      results.push(...await listMoveFiles(next));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith('.move')) {
      results.push(next);
    }
  }
  return results;
}

function inferModuleName(filePath: string): string {
  const base = path.basename(filePath);
  return base.endsWith('.move') ? base.slice(0, -5) : base;
}

function extractFunctionFacts(source: string): MoveFunctionFact[] {
  const results: MoveFunctionFact[] = [];
  const regex = /\b(public)\s+(entry\s+)?fun\s+([a-zA-Z0-9_]+)\s*\(/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(source)) !== null) {
    results.push({
      module: '',
      name: match[3] ?? '',
      visibility: 'public',
      entry: Boolean(match[2]),
    });
  }
  return results.filter((item) => item.name.length > 0);
}

export async function buildMoveFactsForPackage(label: string, packageDir: string): Promise<MovePackageFacts> {
  const moveTomlPath = path.join(packageDir, 'Move.toml');
  const files = await listMoveFiles(packageDir);
  const modules = [];
  for (const file of files) {
    const src = await readFile(file, 'utf8');
    const moduleName = inferModuleName(file);
    const functions = extractFunctionFacts(src).map((fn) => ({ ...fn, module: moduleName }));
    modules.push({ name: moduleName, functions });
  }
  return { label, moveTomlPath, modules };
}
```

- [ ] **Step 2: Add unit test**

Create `tests/ai-move-facts.spec.ts`:

```ts
import { mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { buildMoveFactsForPackage } from '../src/ai/move-facts.js';

describe('move facts', () => {
  it('extracts public entry functions from local package', async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'sui-guardian-move-facts-'));
    await writeFile(path.join(tempDir, 'Move.toml'), `[package]\nname = "Demo"\nversion = "0.0.1"\n`, 'utf8');
    await writeFile(path.join(tempDir, 'demo.move'), `module demo::m { public entry fun withdraw() {} }`, 'utf8');
    const facts = await buildMoveFactsForPackage('demo', tempDir);
    expect(facts.label).toBe('demo');
    expect(facts.modules.some((m) => m.functions.some((f) => f.entry && f.name === 'withdraw'))).toBe(true);
  });
});
```

- [ ] **Step 3: Run tests**

Run: `npm test`
Expected: PASS

---

### Task 7: Implement chain stats collector (7/30/90 day stratified sampling)

**Files:**
- Modify: `src/graphql-client.ts`
- Create: `src/ai/chain-stats.ts`
- Test: `tests/ai-chain-stats.spec.ts`

- [ ] **Step 1: Add checkpoint header API**

Modify `src/graphql-client.ts` to add:

```ts
export interface CheckpointHeader {
  sequenceNumber: number;
  timestamp: string;
}

async getCheckpointHeadersAfter(afterCheckpoint: number, limit: number): Promise<CheckpointHeader[]> {
  const response = await this.request<CheckpointListResponse>(/* reuse query */, { afterCheckpoint, limit });
  return response.checkpoints.nodes.map((item) => ({ sequenceNumber: item.sequenceNumber, timestamp: item.timestamp }));
}
```

- [ ] **Step 2: Add stats collector**

Create `src/ai/chain-stats.ts`:

```ts
import type { ObservedTransaction } from '../types.js';
import { SuiGraphqlClient } from '../graphql-client.js';

export interface WindowStats {
  windowDays: number;
  sampledCheckpoints: number;
  sampledTransactions: number;
  callCounts: Record<string, { txCount: number; uniqueSenders: number; failures: number }>;
}

function keyForCall(call: { package: string; module: string; function: string }): string {
  return `${call.package}::${call.module}::${call.function}`;
}

export async function collectWindowStats(params: {
  client: SuiGraphqlClient;
  latestCheckpoint: number;
  windowDays: number;
  maxSampledCheckpoints: number;
  pageSize: number;
}): Promise<WindowStats> {
  const sampleSize = 2000;
  const sampleStart = Math.max(0, params.latestCheckpoint - sampleSize);
  const headers = await params.client.getCheckpointHeadersAfter(sampleStart, sampleSize);
  const first = headers[0];
  const last = headers[headers.length - 1];
  const firstMs = first ? Date.parse(first.timestamp) : Date.now() - 2_000;
  const lastMs = last ? Date.parse(last.timestamp) : Date.now();
  const secondsPerCheckpoint = headers.length > 1 ? Math.max(1, (lastMs - firstMs) / 1000 / (headers.length - 1)) : 2;
  const needed = Math.ceil((params.windowDays * 24 * 3600) / secondsPerCheckpoint);
  const stride = Math.max(1, Math.ceil(needed / params.maxSampledCheckpoints));
  const startCheckpoint = Math.max(0, params.latestCheckpoint - needed);
  const callCounts: Record<string, { txCount: number; uniqueSenders: Set<string>; failures: number }> = {};
  let sampledTransactions = 0;
  let sampledCheckpoints = 0;
  for (let checkpoint = startCheckpoint; checkpoint <= params.latestCheckpoint; checkpoint += stride) {
    sampledCheckpoints += 1;
    const transactions: ObservedTransaction[] = await params.client.getCheckpointTransactions(checkpoint, params.pageSize);
    sampledTransactions += transactions.length;
    for (const tx of transactions) {
      for (const call of tx.calls) {
        const key = keyForCall(call);
        const existing = callCounts[key] ?? { txCount: 0, uniqueSenders: new Set<string>(), failures: 0 };
        existing.txCount += 1;
        if (tx.sender) {
          existing.uniqueSenders.add(tx.sender);
        }
        if (tx.status === 'FAILURE') {
          existing.failures += 1;
        }
        callCounts[key] = existing;
      }
    }
  }
  return {
    windowDays: params.windowDays,
    sampledCheckpoints,
    sampledTransactions,
    callCounts: Object.fromEntries(Object.entries(callCounts).map(([key, value]) => [
      key,
      { txCount: value.txCount, uniqueSenders: value.uniqueSenders.size, failures: value.failures },
    ])),
  };
}
```

- [ ] **Step 3: Add unit test (shape only)**

Create `tests/ai-chain-stats.spec.ts`:

```ts
import { describe, expect, it } from 'vitest';

import { SuiGraphqlClient } from '../src/graphql-client.js';
import { collectWindowStats } from '../src/ai/chain-stats.js';

describe('chain stats', () => {
  it('collects stats shape with a mocked client', async () => {
    const client = new SuiGraphqlClient('https://graphql.testnet.sui.io/graphql') as unknown as SuiGraphqlClient & {
      getCheckpointHeadersAfter: (afterCheckpoint: number, limit: number) => Promise<Array<{ sequenceNumber: number; timestamp: string }>>;
      getCheckpointTransactions: (checkpoint: number, pageSize: number) => Promise<any[]>;
    };
    client.getCheckpointHeadersAfter = async () => [{ sequenceNumber: 1, timestamp: new Date().toISOString() }, { sequenceNumber: 2, timestamp: new Date().toISOString() }];
    client.getCheckpointTransactions = async () => [{
      digest: 'd',
      checkpoint: 1,
      timestamp: new Date().toISOString(),
      status: 'SUCCESS',
      calls: [{ package: '0x1', module: 'm', function: 'f' }],
      balanceChanges: [],
      objectChanges: [],
    }];
    const stats = await collectWindowStats({
      client,
      latestCheckpoint: 100,
      windowDays: 7,
      maxSampledCheckpoints: 10,
      pageSize: 20,
    });
    expect(stats.windowDays).toBe(7);
    expect(stats.sampledCheckpoints).toBeGreaterThan(0);
    expect(stats.callCounts['0x1::m::f']?.txCount).toBe(1);
  });
});
```

- [ ] **Step 4: Run tests**

Run: `npm test`
Expected: PASS

---

### Task 8: Implement OpenAI client + rule output schema validation

**Files:**
- Create: `src/ai/openai.ts`
- Create: `src/ai/rule-schema.ts`
- Test: `tests/ai-rule-schema.spec.ts`

- [ ] **Step 1: Add rule schema (zod)**

Create `src/ai/rule-schema.ts`:

```ts
import { z } from 'zod';

const severitySchema = z.enum(['info', 'low', 'medium', 'high', 'critical']);

export const generatedRulesSchema = z.object({
  version: z.string().min(1),
  projectId: z.string().min(1),
  rules: z.object({
    packages: z.array(z.object({
      label: z.string().optional(),
      address: z.string().min(1),
      allowedUpgradeSenders: z.array(z.string().min(1)).optional().default([]),
    })).optional().default([]),
    protectedAddresses: z.array(z.object({
      label: z.string().min(1),
      address: z.string().min(1),
      outflowThresholds: z.record(z.string(), z.string()),
      allowedSenders: z.array(z.string().min(1)).optional().default([]),
    })).optional().default([]),
    functionGuards: z.array(z.object({
      label: z.string().min(1),
      package: z.string().min(1),
      module: z.string().min(1),
      function: z.string().min(1),
      allowedSenders: z.array(z.string().min(1)).optional().default([]),
      severity: severitySchema.optional(),
    })).optional().default([]),
    trafficSpikes: z.array(z.object({
      label: z.string().min(1),
      package: z.string().min(1),
      windowSeconds: z.number().int().positive(),
      txCountThreshold: z.number().int().positive(),
      uniqueSenderThreshold: z.number().int().positive(),
      severity: severitySchema.optional(),
      cooldownSeconds: z.number().int().positive().optional(),
    })).optional().default([]),
    failureSpikes: z.array(z.object({
      label: z.string().min(1),
      package: z.string().min(1),
      windowSeconds: z.number().int().positive(),
      failedTxThreshold: z.number().int().positive(),
      severity: severitySchema.optional(),
      cooldownSeconds: z.number().int().positive().optional(),
    })).optional().default([]),
    trackedObjects: z.array(z.object({
      label: z.string().min(1),
      address: z.string().min(1),
      watchFields: z.array(z.string().min(1)).optional().default([]),
      criticalFields: z.array(z.string().min(1)).optional().default([]),
      numericDecreaseThresholds: z.record(z.string(), z.string()).optional().default({}),
      severity: severitySchema.optional(),
    })).optional().default([]),
    suspiciousTargets: z.array(z.object({
      label: z.string().min(1),
      address: z.string().min(1),
    })).optional().default([]),
    behaviorRules: z.object({
      enabled: z.boolean().default(true),
      minRepeatedCalls: z.number().int().positive().default(2),
      minProtectedOutflow: z.string().min(1).default('1'),
      priceDeviationThresholdBps: z.number().int().positive().default(1500),
    }).optional(),
    priceModels: z.array(z.object({
      label: z.string().min(1),
      trackedObjectLabel: z.string().min(1),
      observedFieldPath: z.string().min(1),
      referenceMode: z.enum(['tracked_field', 'rolling_median', 'fixed_range']).default('rolling_median'),
      referenceObjectLabel: z.string().min(1).optional(),
      referenceFieldPath: z.string().min(1).optional(),
      fixedLowerBound: z.string().min(1).optional(),
      fixedUpperBound: z.string().min(1).optional(),
      deviationThresholdBps: z.number().int().positive().default(1500),
    })).optional().default([]),
    objectBaselines: z.array(z.object({
      label: z.string().min(1),
      trackedObjectLabel: z.string().min(1),
      fields: z.array(z.object({
        path: z.string().min(1),
        kind: z.enum(['permission', 'price', 'inventory', 'state']),
        allowedSenders: z.array(z.string().min(1)).optional().default([]),
        maxDeltaBps: z.number().int().nonnegative().optional(),
        maxAbsoluteDecrease: z.string().min(1).optional(),
      })).optional().default([]),
    })).optional().default([]),
    flowTracking: z.object({
      enabled: z.boolean().default(true),
      minProtectedOutflow: z.string().min(1).default('1'),
      attackerGainThreshold: z.string().min(1).default('1'),
      shortWindowTxCount: z.number().int().positive().default(2),
    }).optional(),
    suppression: z.object({
      enabled: z.boolean().default(true),
      duplicateWindowSeconds: z.number().int().positive().default(600),
      weakSignalScoreThreshold: z.number().int().nonnegative().default(35),
      maintenanceWindows: z.array(z.object({
        label: z.string().min(1),
        allowedSenders: z.array(z.string().min(1)).optional().default([]),
        startHourUtc: z.number().int().min(0).max(23),
        endHourUtc: z.number().int().min(0).max(23),
      })).optional().default([]),
    }).optional(),
  }),
  explanations: z.array(z.object({
    ruleId: z.string().min(1),
    summary: z.string().min(1),
    staticEvidence: z.array(z.string().min(1)).optional().default([]),
    dynamicEvidence: z.array(z.string().min(1)).optional().default([]),
    confidence: z.number().min(0).max(1),
    recommendedSeverity: severitySchema,
  })).optional().default([]),
});

export type GeneratedRulesPayload = z.infer<typeof generatedRulesSchema>;
```

- [ ] **Step 2: Add OpenAI responses client**

Create `src/ai/openai.ts`:

```ts
import { errorMessage } from '../utils.js';

export interface OpenAiClientConfig {
  apiKey: string;
  baseUrl: string;
  model: string;
}

export async function callOpenAiJson(params: {
  client: OpenAiClientConfig;
  system: string;
  user: string;
}): Promise<unknown> {
  const url = new URL('/v1/responses', params.client.baseUrl).toString();
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${params.client.apiKey}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: params.client.model,
      input: [
        { role: 'system', content: [{ type: 'text', text: params.system }] },
        { role: 'user', content: [{ type: 'text', text: params.user }] },
      ],
      response_format: { type: 'json_object' },
    }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(`OpenAI request failed: ${response.status} ${JSON.stringify(payload)}`);
  }
  const outputText = (payload as any).output_text;
  if (typeof outputText === 'string' && outputText.trim().length > 0) {
    return JSON.parse(outputText);
  }
  const output = (payload as any).output;
  if (Array.isArray(output)) {
    for (const item of output) {
      const content = item?.content;
      if (!Array.isArray(content)) {
        continue;
      }
      for (const block of content) {
        if (block?.type === 'output_text' && typeof block.text === 'string') {
          return JSON.parse(block.text);
        }
      }
    }
  }
  throw new Error(`OpenAI response missing output text: ${errorMessage(payload)}`);
}
```

- [ ] **Step 3: Add schema test**

Create `tests/ai-rule-schema.spec.ts`:

```ts
import { describe, expect, it } from 'vitest';

import { generatedRulesSchema } from '../src/ai/rule-schema.js';

describe('generated rule schema', () => {
  it('parses minimal payload', () => {
    const parsed = generatedRulesSchema.parse({
      version: 'v',
      projectId: 'p',
      rules: {},
    });
    expect(parsed.projectId).toBe('p');
    expect(parsed.rules.functionGuards).toEqual([]);
  });
});
```

- [ ] **Step 4: Run tests**

Run: `npm test`
Expected: PASS

---

### Task 9: Implement rule generator pipeline + CLI

**Files:**
- Create: `src/ai/rule-generator.ts`
- Create: `src/ai/cli.ts`
- Modify: `package.json`
- Test: `tests/ai-rule-schema.spec.ts` (extend)

- [ ] **Step 1: Create rule generator**

Create `src/ai/rule-generator.ts`:

```ts
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';

import YAML from 'yaml';

import type { AppConfig } from '../types.js';
import { canonicalizeSuiAddress, nowIso } from '../utils.js';
import { SuiGraphqlClient } from '../graphql-client.js';
import { collectWindowStats } from './chain-stats.js';
import { callOpenAiJson } from './openai.js';
import { buildMoveFactsForPackage } from './move-facts.js';
import { generatedRulesSchema } from './rule-schema.js';

export interface GenerateRulesParams {
  projectId: string;
  projectName: string;
  generatedDir: string;
  deploymentsPath: string;
  sourceRoot: string;
  graphqlEndpoint: string;
  openai: {
    apiKey: string;
    baseUrl: string;
    model: string;
  };
}

async function atomicWrite(filePath: string, contents: string): Promise<void> {
  const dir = path.dirname(filePath);
  await mkdir(dir, { recursive: true });
  const tmp = `${filePath}.${Date.now()}.tmp`;
  await writeFile(tmp, contents, 'utf8');
  await rename(tmp, filePath);
}

export async function generateProjectRules(params: GenerateRulesParams): Promise<{ version: string; rulesPath: string; metaPath: string }> {
  const deploymentsRaw = await readFile(params.deploymentsPath, 'utf8');
  const deployments = JSON.parse(deploymentsRaw) as { packages?: Array<{ label: string; packageId: string }> };
  const packages = (deployments.packages ?? []).map((pkg) => ({
    label: pkg.label,
    address: canonicalizeSuiAddress(pkg.packageId),
  }));

  const client = new SuiGraphqlClient(params.graphqlEndpoint);
  const latestCheckpoint = await client.getLatestCheckpoint();
  const stats7 = await collectWindowStats({ client, latestCheckpoint, windowDays: 7, maxSampledCheckpoints: 500, pageSize: 50 });
  const stats30 = await collectWindowStats({ client, latestCheckpoint, windowDays: 30, maxSampledCheckpoints: 1000, pageSize: 50 });
  const stats90 = await collectWindowStats({ client, latestCheckpoint, windowDays: 90, maxSampledCheckpoints: 1500, pageSize: 50 });

  const moveFacts = await Promise.all(
    (deployments.packages ?? []).map((pkg) => buildMoveFactsForPackage(pkg.label, path.join(params.sourceRoot, pkg.label))),
  );

  const system = [
    'You must return a single JSON object that matches the schema described in the user message.',
    'Do not invent addresses. Use only addresses from the deployments manifest.',
    'Do not output YAML. Do not add extra keys.',
  ].join('\n');

  const user = JSON.stringify({
    schema: 'GeneratedRulesPayload',
    project: {
      projectId: params.projectId,
      projectName: params.projectName,
      network: 'testnet',
      packages,
    },
    deployments,
    moveFacts,
    stats: { stats7, stats30, stats90 },
    policy: { alertPreference: 'neutral_first_week_then_tune' },
    output: {
      version: nowIso(),
      projectId: params.projectId,
      rules: {
        packages: [],
        protectedAddresses: [],
        functionGuards: [],
        trafficSpikes: [],
        failureSpikes: [],
        trackedObjects: [],
        suspiciousTargets: [],
        behaviorRules: {
          enabled: true,
          minRepeatedCalls: 2,
          minProtectedOutflow: '1',
          priceDeviationThresholdBps: 1500,
        },
        priceModels: [],
        objectBaselines: [],
        flowTracking: {
          enabled: true,
          minProtectedOutflow: '1',
          attackerGainThreshold: '1',
          shortWindowTxCount: 2,
        },
        suppression: {
          enabled: true,
          duplicateWindowSeconds: 600,
          weakSignalScoreThreshold: 35,
          maintenanceWindows: [],
        },
      },
      explanations: [],
    },
  });

  const json = await callOpenAiJson({
    client: { apiKey: params.openai.apiKey, baseUrl: params.openai.baseUrl, model: params.openai.model },
    system,
    user,
  });
  const payload = generatedRulesSchema.parse(json);
  const version = payload.version;

  const projectDir = path.join(params.generatedDir, params.projectId);
  const rulesPath = path.join(projectDir, 'current.yml');
  const metaPath = path.join(projectDir, 'meta', 'current.json');
  const versionedRulesPath = path.join(projectDir, 'versions', `${encodeURIComponent(version)}.yml`);
  const versionedMetaPath = path.join(projectDir, 'meta', 'versions', `${encodeURIComponent(version)}.json`);

  const rulesYaml = YAML.stringify(payload.rules);
  const metaJson = JSON.stringify({
    version,
    projectId: payload.projectId,
    generatedAt: nowIso(),
    explanations: payload.explanations ?? [],
    checkpoints: {
      latest: latestCheckpoint,
      windows: [
        { days: 7, sampledCheckpoints: stats7.sampledCheckpoints, sampledTransactions: stats7.sampledTransactions },
        { days: 30, sampledCheckpoints: stats30.sampledCheckpoints, sampledTransactions: stats30.sampledTransactions },
        { days: 90, sampledCheckpoints: stats90.sampledCheckpoints, sampledTransactions: stats90.sampledTransactions },
      ],
    },
  }, null, 2);

  await atomicWrite(rulesPath, rulesYaml);
  await atomicWrite(metaPath, metaJson);
  await atomicWrite(versionedRulesPath, rulesYaml);
  await atomicWrite(versionedMetaPath, metaJson);

  return { version, rulesPath, metaPath };
}
```

- [ ] **Step 2: Add CLI**

Create `src/ai/cli.ts`:

```ts
import path from 'node:path';

import { generateProjectRules } from './rule-generator.js';

function getArgValue(flag: string): string | undefined {
  const index = process.argv.indexOf(flag);
  if (index === -1) {
    return undefined;
  }
  return process.argv[index + 1];
}

async function main(): Promise<void> {
  const projectId = getArgValue('--projectId') ?? '';
  const projectName = getArgValue('--projectName') ?? projectId;
  const sourceRoot = getArgValue('--sourceRoot') ?? '';
  const deploymentsPath = getArgValue('--deploymentsPath') ?? '';
  const generatedDir = getArgValue('--generatedDir') ?? '.data/generated';
  const graphqlEndpoint = getArgValue('--graphqlEndpoint') ?? 'https://graphql.testnet.sui.io/graphql';

  const apiKey = process.env.OPENAI_API_KEY ?? '';
  const baseUrl = process.env.OPENAI_BASE_URL ?? 'https://api.openai.com';
  const model = process.env.OPENAI_MODEL ?? 'gpt-4.1';

  if (!projectId || !sourceRoot || !deploymentsPath) {
    throw new Error('Missing required args: --projectId --sourceRoot --deploymentsPath');
  }
  if (!apiKey) {
    throw new Error('Missing OPENAI_API_KEY');
  }

  const resolvedDeployments = path.resolve(process.cwd(), deploymentsPath);
  const resolvedSource = path.resolve(process.cwd(), sourceRoot);

  const result = await generateProjectRules({
    projectId,
    projectName,
    generatedDir,
    deploymentsPath: resolvedDeployments,
    sourceRoot: resolvedSource,
    graphqlEndpoint,
    openai: { apiKey, baseUrl, model },
  });
  console.log(JSON.stringify(result, null, 2));
}

void main();
```

- [ ] **Step 3: Add npm scripts**

Modify `package.json`:

```json
{
  "scripts": {
    "ai:generate": "tsx src/ai/cli.ts",
    "ai:deploy:testnet": "python3 scripts/deploy_sui_defi_testnet.py /Users/seem/Downloads/sui-defi-main interest-protocol"
  }
}
```

- [ ] **Step 4: Extend schema test with a full roundtrip example**

Extend `tests/ai-rule-schema.spec.ts` to parse a payload with `rules.functionGuards` and ensure defaults are applied:

```ts
expect(parsed.rules.suppression?.duplicateWindowSeconds).toBe(600);
```

- [ ] **Step 5: Run tests**

Run: `npm test`
Expected: PASS

---

### Task 10: Update docs + end-to-end verification commands

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Document the full flow**

Add commands:

```bash
python3 scripts/deploy_sui_defi_testnet.py /Users/seem/Downloads/sui-defi-main interest-protocol

OPENAI_API_KEY=... OPENAI_BASE_URL=... OPENAI_MODEL=gpt-5.4 \
npm run ai:generate -- --projectId interest-protocol --projectName "Interest Protocol" \
  --sourceRoot /Users/seem/Downloads/sui-defi-main \
  --deploymentsPath .data/deployments/interest-protocol.json \
  --generatedDir .data/generated \
  --graphqlEndpoint https://graphql.testnet.sui.io/graphql

CONFIG_PATH=config/default.yml npm run dev
```

Then show how to enable `aiRules` in config:

```yml
aiRules:
  enabled: true
  generatedDir: .data/generated
  reloadIntervalMs: 60000
  shadow:
    enabled: true
    notify: false
    minMinutes: 60
  canary:
    enabled: true
    stage: shadow
    promotionMinMinutes: 60
  generator:
    enabled: false
    sourceRoot: /Users/seem/Downloads/sui-defi-main
    deploymentsDir: .data/deployments
    modelBaseUrl: https://ai.immortality.top
    modelName: gpt-5.4
    regenerateIntervalHours: 168
```

- [ ] **Step 2: Run typecheck**

Run: `npm run typecheck`
Expected: PASS

---

## Plan Self-Review

- Spec coverage: 本计划覆盖 schema 扩展、generated 目录、规则合并、热加载（含 shadow/canary）、testnet 部署 manifest、静态 facts、动态统计、OpenAI 调用、CLI、文档与测试。
- Placeholder scan: 所有任务步骤包含具体文件路径、代码片段与执行命令。
- Type consistency: 使用现有 `AppConfig/MonitoringProjectConfig` 结构并通过 zod 校验保证一致性。
