import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { loadConfig } from '../src/config.js';

describe('loadConfig', () => {
  it('loads behavior rule settings and suspicious targets', async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'sui-guardian-config-'));
    const configPath = path.join(tempDir, 'behavior-config.yml');

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

projects:
  - id: demo
    name: Demo
    packages:
      - label: core
        address: "0x111"
        allowedUpgradeSenders:
          - "0xabc"
        deprecatedAddresses:
          - "0x333"
    protectedAddresses: []
    functionGuards: []
    trafficSpikes: []
    failureSpikes: []
    trackedObjects: []
    suspiciousTargets:
      - label: rogue-router
        address: "0x123"
    behaviorRules:
      enabled: true
      minRepeatedCalls: 3
      minProtectedOutflow: "250"
      priceDeviationThresholdBps: 1750
`,
      'utf8',
    );

    const config = await loadConfig(configPath);
    expect(config.projects[0]?.behaviorRules.enabled).toBe(true);
    expect(config.projects[0]?.behaviorRules.minRepeatedCalls).toBe(3);
    expect(config.projects[0]?.behaviorRules.minProtectedOutflow).toBe('250');
    expect(config.projects[0]?.behaviorRules.priceDeviationThresholdBps).toBe(1750);
    expect(config.projects[0]?.suspiciousTargets).toHaveLength(1);
  });

  it('loads hardening config blocks', async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'sui-guardian-hardening-config-'));
    const configPath = path.join(tempDir, 'hardening-config.yml');

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

projects:
  - id: demo
    name: Demo
    packages:
      - label: core
        address: "0x111"
        allowedUpgradeSenders:
          - "0xabc"
        deprecatedAddresses:
          - "0x333"
    protectedAddresses: []
    functionGuards: []
    trafficSpikes: []
    failureSpikes: []
    trackedObjects:
      - label: oracle-feed
        address: "0x111"
      - label: admin-vault
        address: "0x222"
    suspiciousTargets: []
    behaviorRules:
      enabled: true
      minRepeatedCalls: 2
      minProtectedOutflow: "100"
      priceDeviationThresholdBps: 1500
    priceModels:
      - label: oracle-price
        trackedObjectLabel: oracle-feed
        observedFieldPath: price
        referenceMode: rolling_median
        deviationThresholdBps: 2000
    objectBaselines:
      - label: vault-baseline
        trackedObjectLabel: admin-vault
        fields:
          - path: admin
            kind: permission
            allowedSenders:
              - "0xabc"
    flowTracking:
      enabled: true
      minProtectedOutflow: "500"
      attackerGainThreshold: "250"
      shortWindowTxCount: 2
    suppression:
      enabled: true
      duplicateWindowSeconds: 600
      weakSignalScoreThreshold: 35
      maintenanceWindows:
        - label: ops-window
          allowedSenders:
            - "0xabc"
          startHourUtc: 1
          endHourUtc: 3
`,
      'utf8',
    );

    const config = await loadConfig(configPath);
    const project = config.projects[0];

    expect(project?.priceModels[0]?.label).toBe('oracle-price');
    expect(project?.packages[0]?.deprecatedAddresses?.[0]).toBe('0x0000000000000000000000000000000000000000000000000000000000000333');
    expect(project?.objectBaselines[0]?.fields[0]?.path).toBe('admin');
    expect(project?.flowTracking.enabled).toBe(true);
    expect(project?.suppression.maintenanceWindows[0]?.label).toBe('ops-window');
  });

  it('documents lab configs as manual validation only', async () => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8');
    expect(readme).toContain('演练验证模块');
    expect(readme).toContain('不参与默认运行');
  });

  it('keeps runtime artifacts isolated from repository defaults', async () => {
    const gitignore = await readFile(new URL('../.gitignore', import.meta.url), 'utf8');
    const defaultConfig = await readFile(new URL('../config/default.yml', import.meta.url), 'utf8');

    expect(gitignore).toContain('.data');
    expect(defaultConfig).toContain('stateFile: .data/state.json');
    expect(defaultConfig).not.toContain('generated-defi-range');
    expect(defaultConfig).not.toContain('generated-vuln-defi-lab');
  });

  it('marks project template and docs as production-first', async () => {
    const template = await readFile(new URL('../config/projects.example.yml', import.meta.url), 'utf8');
    const references = await readFile(new URL('../docs/open-source-references.md', import.meta.url), 'utf8');

    expect(template).toContain('真实项目');
    expect(template).toContain('不应直接用于演练配置');
    expect(references).toContain('演练配置不得进入默认展示链路');
  });
});
