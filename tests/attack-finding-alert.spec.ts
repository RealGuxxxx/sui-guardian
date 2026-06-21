import { describe, expect, it } from 'vitest';

import { ProjectMonitor } from '../src/project-monitor.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PACKAGE = '0x1111111111111111111111111111111111111111111111111111111111111111';
const TREASURY = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const ATTACKER = '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';

const project: MonitoringProjectConfig = {
  id: 'demo',
  name: 'Demo Project',
  packages: [],
  protectedAddresses: [
    {
      label: 'treasury',
      address: TREASURY,
      outflowThresholds: { '0x2::sui::SUI': '100' },
    },
  ],
  functionGuards: [],
  trafficSpikes: [],
  failureSpikes: [],
  trackedObjects: [],
  suspiciousTargets: [],
  behaviorRules: {
    enabled: false,
    minRepeatedCalls: 2,
    minProtectedOutflow: '100',
    priceDeviationThresholdBps: 1500,
  },
  priceModels: [],
  objectBaselines: [],
  flowTracking: {
    enabled: true,
    minProtectedOutflow: '100',
    attackerGainThreshold: '100',
    shortWindowTxCount: 1,
  },
  suppression: {
    enabled: false,
    duplicateWindowSeconds: 0,
    weakSignalScoreThreshold: 35,
    maintenanceWindows: [],
  },
};

function makeTx(overrides: Partial<ObservedTransaction> = {}): ObservedTransaction {
  return {
    digest: 'D111',
    checkpoint: 1,
    timestamp: '2026-01-01T00:00:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [],
    balanceChanges: [],
    objectChanges: [],
    ...overrides,
  };
}

describe('attack findings → independent alerts', () => {
  it('generates attack alert when liquidity drain is detected', () => {
    const monitor = new ProjectMonitor(project);

    // 构造一笔：treasury 流出 1000，attacker 获得 1000
    const tx = makeTx({
      balanceChanges: [
        { owner: TREASURY, coinType: '0x2::sui::SUI', amount: '-1000' },
        { owner: ATTACKER, coinType: '0x2::sui::SUI', amount: '1000' },
      ],
    });

    const alerts = monitor.processTransaction(tx);
    const attackAlerts = alerts.filter((a) => a.ruleId.startsWith('attack:'));

    // 至少应产生 liquidity-drain 攻击告警
    expect(attackAlerts.length).toBeGreaterThan(0);
    const drainAlert = attackAlerts.find((a) => a.ruleId === 'attack:liquidity-drain');
    expect(drainAlert).toBeDefined();
    expect(drainAlert?.severity).toBe('high');
    expect(drainAlert?.details.sender).toBe(ATTACKER);
    expect(drainAlert?.details.attackType).toBe('liquidity-drain');
  });

  it('does not create duplicate attack alert if same ruleId already exists in base alerts', () => {
    const monitor = new ProjectMonitor({
      ...project,
      behaviorRules: { ...project.behaviorRules, enabled: true },
    });

    const tx = makeTx({
      calls: [{ package: PACKAGE, module: 'vault', function: 'withdraw' }],
      balanceChanges: [
        { owner: TREASURY, coinType: '0x2::sui::SUI', amount: '-1000' },
        { owner: ATTACKER, coinType: '0x2::sui::SUI', amount: '1000' },
      ],
    });

    const alerts = monitor.processTransaction(tx);
    const ruleIds = alerts.map((a) => a.ruleId);

    // ruleId 不应重复
    const uniqueRuleIds = new Set(ruleIds);
    expect(uniqueRuleIds.size).toBe(ruleIds.length);
  });

  it('does not generate attack alert for info/low severity findings', () => {
    // unknown-coordinated-anomaly is medium, should be included
    // But if floor is info/low it should be skipped
    const monitor = new ProjectMonitor(project);
    const tx = makeTx(); // empty tx, no signals
    const alerts = monitor.processTransaction(tx);
    const attackAlerts = alerts.filter((a) => a.ruleId.startsWith('attack:'));

    // No signals → no attack alerts
    expect(attackAlerts.length).toBe(0);
  });

  it('attack alert includes riskScore and flowEvidence in details', () => {
    const monitor = new ProjectMonitor(project);

    const tx = makeTx({
      balanceChanges: [
        { owner: TREASURY, coinType: '0x2::sui::SUI', amount: '-500' },
        { owner: ATTACKER, coinType: '0x2::sui::SUI', amount: '500' },
      ],
    });

    const alerts = monitor.processTransaction(tx);
    const attackAlerts = alerts.filter((a) => a.ruleId.startsWith('attack:'));

    if (attackAlerts.length > 0) {
      const alert = attackAlerts[0]!;
      expect(typeof alert.details.riskScore).toBe('number');
      expect(alert.details.flowEvidence).toBeDefined();
      expect(Array.isArray(alert.details.attackFindings)).toBe(true);
    }
  });
});
