import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { MonitorService } from '../src/monitor-service.js';
import type { AppConfig } from '../src/types.js';

describe('MonitorService aiRules reload', () => {
  it('merges generated rules into config summary', async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'sui-guardian-ai-rules-'));
    const generatedDir = path.join(tempDir, 'generated');
    await mkdir(path.join(generatedDir, 'demo'), { recursive: true });
    await writeFile(
      path.join(generatedDir, 'demo', 'current.yml'),
      `functionGuards:
  - label: withdraw
    package: "0x1"
    module: vault
    function: withdraw
    allowedSenders: ["0xabc"]
    severity: critical
`,
      'utf8',
    );

    const config: AppConfig = {
      network: {
        name: 'testnet',
        graphqlEndpoint: 'https://graphql.testnet.sui.io/graphql',
        pollIntervalMs: 5000,
        bootstrapLookbackCheckpoints: 10,
        checkpointOverlap: 2,
        maxCheckpointsPerTick: 5,
        maxTransactionsPerPage: 20,
      },
      storage: {
        stateFile: path.join(tempDir, 'state.json'),
        maxAlerts: 100,
      },
      server: {
        host: '127.0.0.1',
        port: 3000,
      },
      alerts: {
        console: false,
      },
      aiRules: {
        enabled: true,
        generatedDir,
        reloadIntervalMs: 60_000,
        shadow: { enabled: true, notify: false, minMinutes: 60 },
        canary: { enabled: true, stage: 'shadow', promotionMinMinutes: 60 },
        generator: {
          enabled: false,
          sourceRoot: '',
          deploymentsDir: path.join(tempDir, 'deployments'),
          modelBaseUrl: 'https://example.com',
          modelName: 'gpt-5.4',
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

    const service = new MonitorService(config) as unknown as { reloadGeneratedRulesOnce: () => Promise<boolean>; getConfigSummary: () => any };
    const changed = await service.reloadGeneratedRulesOnce();
    expect(changed).toBe(true);
    expect(service.getConfigSummary().projects[0].functionGuardCount).toBe(1);
  });
});

