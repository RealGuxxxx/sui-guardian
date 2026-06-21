# Production Data Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 清理 `sui-guardian` 中所有默认展示链路里的 demo / generated / 测试样本数据，并将系统切换到默认只展示真实业务数据的生产模式，同时保留演练验证模块代码与脚本。

**Architecture:** 这次改造不新增新能力，重点是收紧数据来源边界。默认运行入口、状态文件、Dashboard 空态、接口返回和文档说明全部回归“真实配置优先”；演练配置和脚本继续保留，但只能显式触发，不能污染默认展示链路。

**Tech Stack:** TypeScript, Fastify, Vitest, YAML, Node.js

---

### Task 1: 清理默认运行链路中的实验配置引用

**Files:**
- Modify: `/Users/seem/Desktop/sui-guardian/README.md`
- Modify: `/Users/seem/Desktop/sui-guardian/package.json`
- Modify: `/Users/seem/Desktop/sui-guardian/docs/architecture.md`
- Test: `/Users/seem/Desktop/sui-guardian/tests/config.spec.ts`

- [ ] **Step 1: 写失败测试，确认默认配置不引用 generated 配置**

```ts
import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';

describe('production mode defaults', () => {
  it('does not point default run instructions to generated configs', async () => {
    const pkg = await readFile(new URL('../package.json', import.meta.url), 'utf8');
    expect(pkg).not.toContain('generated-defi-range.yml');
    expect(pkg).not.toContain('generated-vuln-defi-lab.yml');
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `npm test -- --run tests/config.spec.ts`
Expected: FAIL，若当前说明文档、脚本或测试尚未覆盖该约束，则需要新增断言或更新已有测试文件。

- [ ] **Step 3: 最小实现默认运行说明切回生产配置**

```json
{
  "scripts": {
    "dev": "tsx watch src/index.ts",
    "scan:once": "tsx src/index.ts --once",
    "lab:vuln-defi": "python3 scripts/run_vuln_defi_lab.py",
    "lab:defi-range": "python3 scripts/run_defi_range_lab.py"
  }
}
```

```md
默认运行仅使用 `config/default.yml` 或显式传入的真实项目配置。
演练配置仅用于手动验证，不作为默认展示链路。
```

- [ ] **Step 4: 再跑测试确认通过**

Run: `npm test -- --run tests/config.spec.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add README.md package.json docs/architecture.md tests/config.spec.ts
git commit -m "chore: remove generated configs from default run flow"
```

### Task 2: 删除默认展示用的 generated 状态文件与日志残留

**Files:**
- Delete: `/Users/seem/Desktop/sui-guardian/.data/generated-defi-range-state.json`
- Delete: `/Users/seem/Desktop/sui-guardian/.data/generated-vuln-defi-lab-state.json`
- Delete: `/Users/seem/Desktop/sui-guardian/.data/generated-defi-range-monitor.log`
- Delete: `/Users/seem/Desktop/sui-guardian/.data/generated-vuln-defi-lab-monitor.log`
- Modify: `/Users/seem/Desktop/sui-guardian/docs/research.md`

- [ ] **Step 1: 写失败测试，确认 generated 状态文件不应继续存在于默认展示链路**

```ts
import { access } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

describe('generated state cleanup', () => {
  it('removes generated state files from repository runtime defaults', async () => {
    await expect(access('.data/generated-defi-range-state.json')).rejects.toBeTruthy();
    await expect(access('.data/generated-vuln-defi-lab-state.json')).rejects.toBeTruthy();
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `npm test -- --run tests/config.spec.ts`
Expected: FAIL，提示 generated 状态文件仍然存在。

- [ ] **Step 3: 删除 generated 状态文件并更新说明文档**

```md
运行时默认仅使用 `.data/state.json`。
`generated-*` 状态文件不再作为仓库内默认展示数据保留。
```

- [ ] **Step 4: 再跑测试确认通过**

Run: `npm test -- --run tests/config.spec.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add .data docs/research.md tests/config.spec.ts
git commit -m "chore: remove generated runtime state artifacts"
```

### Task 3: 收紧 Dashboard 空态与文案，禁止 demo 展示

**Files:**
- Modify: `/Users/seem/Desktop/sui-guardian/src/dashboard.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/monitor-service.spec.ts`

- [ ] **Step 1: 写失败测试，要求页面只显示真实空态文案**

```ts
import { describe, expect, it } from 'vitest';
import { renderDashboard } from '../src/dashboard.js';

describe('dashboard production copy', () => {
  it('uses real-data empty states instead of demo wording', () => {
    const html = renderDashboard();
    expect(html).not.toContain('实验室');
    expect(html).not.toContain('靶场');
    expect(html).not.toContain('demo');
    expect(html).toContain('暂无真实数据');
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `npm test -- --run tests/monitor-service.spec.ts`
Expected: FAIL，提示页面里仍有实验/演练导向文案，或空态文案尚未改成真实数据模式。

- [ ] **Step 3: 最小实现生产空态文案**

```ts
body.innerHTML = '<div class="empty">暂无真实数据</div>';
```

```ts
body.innerHTML = '<div class="empty">尚未配置真实监控项目</div>';
```

- [ ] **Step 4: 再跑测试确认通过**

Run: `npm test -- --run tests/monitor-service.spec.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/dashboard.ts tests/monitor-service.spec.ts
git commit -m "feat: switch dashboard to production empty states"
```

### Task 4: 校验 API 仅返回真实状态或空结果

**Files:**
- Modify: `/Users/seem/Desktop/sui-guardian/src/monitor-service.ts`
- Modify: `/Users/seem/Desktop/sui-guardian/src/server.ts`
- Test: `/Users/seem/Desktop/sui-guardian/tests/monitor-service.spec.ts`

- [ ] **Step 1: 写失败测试，验证无真实项目配置时接口聚合结果为空态**

```ts
import { describe, expect, it } from 'vitest';
import { MonitorService } from '../src/monitor-service.js';

describe('production data source boundaries', () => {
  it('returns empty incident timeline when no real alerts exist', () => {
    const service = new MonitorService({
      network: {
        name: 'mainnet',
        graphqlEndpoint: 'https://graphql.mainnet.sui.io/graphql',
        pollIntervalMs: 5000,
        bootstrapLookbackCheckpoints: 5,
        checkpointOverlap: 3,
        maxCheckpointsPerTick: 5,
        maxTransactionsPerPage: 50,
      },
      storage: {
        stateFile: '.data/test-empty.json',
        maxAlerts: 50,
      },
      server: {
        host: '127.0.0.1',
        port: 3000,
      },
      alerts: {
        console: false,
        webhookUrl: '',
        webhookEnabled: false,
      },
      projects: [],
    } as never);

    expect(service.getIncidentTimeline()).toEqual([]);
    expect(service.getAssets()).toEqual([]);
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `npm test -- --run tests/monitor-service.spec.ts`
Expected: FAIL，若当前测试夹具不适配空配置，需要先修正测试构造方式。

- [ ] **Step 3: 最小实现接口只返回真实状态或空结果**

```ts
getAssets(projectId?: string): ObjectSnapshot[] {
  const snapshots = Object.values(this.state.trackedObjectSnapshots);
  const filtered = projectId ? snapshots.filter((item) => item.projectId === projectId) : snapshots;
  return filtered.sort((left, right) => left.label.localeCompare(right.label, 'zh-CN'));
}
```

```ts
getIncidentTimeline(limit = 10) {
  if (this.state.recentAlerts.length === 0) {
    return [];
  }
  // keep existing real aggregation only
}
```

- [ ] **Step 4: 再跑测试确认通过**

Run: `npm test -- --run tests/monitor-service.spec.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/monitor-service.ts src/server.ts tests/monitor-service.spec.ts
git commit -m "fix: enforce real-data only api responses"
```

### Task 5: 明确保留演练验证模块但不进入默认展示链路

**Files:**
- Modify: `/Users/seem/Desktop/sui-guardian/README.md`
- Modify: `/Users/seem/Desktop/sui-guardian/docs/open-source-references.md`
- Modify: `/Users/seem/Desktop/sui-guardian/config/projects.example.yml`

- [ ] **Step 1: 写失败测试，要求示例配置文档区分真实项目与演练配置**

```ts
import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';

describe('lab isolation docs', () => {
  it('documents lab configs as manual-only validation tools', async () => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8');
    expect(readme).toContain('演练验证模块');
    expect(readme).toContain('不参与默认运行');
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `npm test -- --run tests/config.spec.ts`
Expected: FAIL，提示文档尚未明确演练模块边界。

- [ ] **Step 3: 最小实现文档边界说明**

```md
演练验证模块保留，用于数据完整性验证和规则回归验证。
这些脚本和配置不参与默认运行，也不应作为生产界面的数据来源。
```

- [ ] **Step 4: 再跑测试确认通过**

Run: `npm test -- --run tests/config.spec.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add README.md docs/open-source-references.md config/projects.example.yml tests/config.spec.ts
git commit -m "docs: isolate lab validation from production display flow"
```

### Task 6: 输出数据清理报告与配置变更记录

**Files:**
- Create: `/Users/seem/Desktop/sui-guardian/docs/production-data-cleanup-report.md`
- Create: `/Users/seem/Desktop/sui-guardian/docs/production-config-change-log.md`

- [ ] **Step 1: 写报告文件骨架**

```md
# 数据清理报告

## 清理范围
- generated 状态文件
- 默认展示链路
- Dashboard 空态文案
- API 数据来源边界

## 已验证结果
- 默认配置不展示 demo 项目
- 无真实项目时返回空态
- 演练模块仅保留为手动验证能力
```

```md
# 配置变更记录

## 默认运行模式
- 默认使用 `config/default.yml`

## 已隔离的演练配置
- `config/generated-defi-range.yml`
- `config/generated-vuln-defi-lab.yml`

## 状态文件变更
- 删除 generated 状态文件
- 保留 `.data/state.json`
```

- [ ] **Step 2: 运行全文检查**

Run: `npm test`
Expected: PASS，且报告文件不影响代码测试。

- [ ] **Step 3: 补充实际清理结果与验证结论**

```md
## 数据流验证
1. 前端调用 `/api/*`
2. 后端仅返回真实状态或空态
3. 页面无 demo / generated 展示内容
```

- [ ] **Step 4: 再跑类型检查和测试**

Run: `npm run typecheck && npm test`
Expected: 全部通过

- [ ] **Step 5: 提交**

```bash
git add docs/production-data-cleanup-report.md docs/production-config-change-log.md
git commit -m "docs: add production data cleanup report"
```

## 自检

- 已覆盖配置、状态文件、前端文案、API 边界、演练模块隔离、报告交付
- 无 TBD / TODO / “后续再补” 占位语
- 任务顺序满足先测试、后实现、再验证的 TDD 流程
