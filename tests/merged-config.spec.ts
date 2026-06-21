import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { loadMergedConfig } from '../src/config.js';

describe('loadMergedConfig', () => {
  it('merges generated project rules when aiRules is enabled', async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'sui-guardian-merged-config-'));
    const generatedDir = path.join(tempDir, 'generated');
    const configPath = path.join(tempDir, 'config.yml');

    await mkdir(path.join(generatedDir, 'demo'), { recursive: true });
    await writeFile(
      path.join(generatedDir, 'demo', 'current.yml'),
      `packages:
  - label: core
    address: "0x0000000000000000000000000000000000000000000000000000000000000001"
    allowedUpgradeSenders: ["0xbbb"]
    deprecatedAddresses: ["0xdead"]
functionGuards:
  - label: withdraw
    package: "0x1"
    module: vault
    function: withdraw
    allowedSenders: ["0xabc"]
    severity: critical
`,
      'utf8',
    );

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
  stateFile: ${path.join(tempDir, 'state.json')}
  maxAlerts: 100

server:
  host: 127.0.0.1
  port: 3000

alerts:
  console: true
  webhookUrl: ""

aiRules:
  enabled: true
  generatedDir: ${generatedDir}
  reloadIntervalMs: 60000

projects:
  - id: demo
    name: Demo
    packages:
      - label: core
        address: "0x1"
        allowedUpgradeSenders: ["0xaaa"]
        deprecatedAddresses: ["0xbeef"]
    protectedAddresses: []
    functionGuards: []
    trafficSpikes: []
    failureSpikes: []
    trackedObjects: []
    suspiciousTargets: []
    behaviorRules:
      enabled: true
      minRepeatedCalls: 2
      minProtectedOutflow: "1"
      priceDeviationThresholdBps: 1500
    priceModels: []
    objectBaselines: []
    flowTracking:
      enabled: true
      minProtectedOutflow: "1"
      attackerGainThreshold: "1"
      shortWindowTxCount: 2
    suppression:
      enabled: true
      duplicateWindowSeconds: 600
      weakSignalScoreThreshold: 35
      maintenanceWindows: []
`,
      'utf8',
    );

    const config = await loadMergedConfig(configPath);
    expect(config.projects[0]!.functionGuards).toHaveLength(1);
    expect(config.projects[0]!.functionGuards[0]!.label).toBe('withdraw');
    expect(config.projects[0]!.packages[0]!.allowedUpgradeSenders).toEqual([
      '0x0000000000000000000000000000000000000000000000000000000000000aaa',
      '0xbbb',
    ]);
    expect(config.projects[0]!.packages[0]!.deprecatedAddresses).toEqual([
      '0x000000000000000000000000000000000000000000000000000000000000beef',
      '0xdead',
    ]);
  });
});
