import { describe, expect, it } from 'vitest';

import { ProjectMonitor } from '../src/project-monitor.js';
import type { MonitoringProjectConfig, ObservedTransaction, PackageVersionSnapshot } from '../src/types.js';

const PACKAGE = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ADMIN = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const TREASURY = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const ATTACKER = '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';

const project: MonitoringProjectConfig = {
  id: 'demo',
  name: 'Demo Project',
  packages: [
    {
      address: PACKAGE,
      allowedUpgradeSenders: [ADMIN],
    },
  ],
  protectedAddresses: [
    {
      label: 'treasury',
      address: TREASURY,
      outflowThresholds: {
        '0x2::sui::SUI': '100',
      },
      allowedSenders: [ADMIN],
    },
  ],
  functionGuards: [
    {
      label: 'emergency-withdraw',
      package: PACKAGE,
      module: 'vault',
      function: 'emergency_withdraw',
      allowedSenders: [ADMIN],
      severity: 'critical',
    },
  ],
  trafficSpikes: [
    {
      label: 'hot',
      package: PACKAGE,
      windowSeconds: 60,
      txCountThreshold: 2,
      uniqueSenderThreshold: 2,
      severity: 'high',
      cooldownSeconds: 60,
    },
  ],
  failureSpikes: [
    {
      label: 'fails',
      package: PACKAGE,
      windowSeconds: 60,
      failedTxThreshold: 2,
      severity: 'medium',
      cooldownSeconds: 60,
    },
  ],
  trackedObjects: [],
  suspiciousTargets: [
    {
      label: 'rogue-router',
      address: '0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    },
  ],
  behaviorRules: {
    enabled: true,
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
    shortWindowTxCount: 2,
  },
  suppression: {
    enabled: true,
    duplicateWindowSeconds: 600,
    weakSignalScoreThreshold: 35,
    maintenanceWindows: [],
  },
};

function buildTx(partial: Partial<ObservedTransaction>): ObservedTransaction {
  return {
    digest: 'digest-1',
    checkpoint: 1,
    timestamp: '2026-04-23T18:37:57.930Z',
    sender: ADMIN,
    status: 'SUCCESS',
    calls: [],
    balanceChanges: [],
    objectChanges: [],
    ...partial,
  };
}

describe('ProjectMonitor', () => {
  it('ignores transactions that do not touch the monitored project', () => {
    const monitor = new ProjectMonitor(project);
    const alerts = monitor.processTransaction(
      buildTx({
        sender: ATTACKER,
        calls: [
          {
            package: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
            module: 'vault',
            function: 'emergency_withdraw',
          },
        ],
      }),
    );

    expect(alerts).toHaveLength(0);
  });

  it('detects abnormal outflow and unauthorized function call', () => {
    const monitor = new ProjectMonitor(project);
    const alerts = monitor.processTransaction(
      buildTx({
        sender: ATTACKER,
        calls: [{ package: PACKAGE, module: 'vault', function: 'emergency_withdraw' }],
        balanceChanges: [
          { owner: TREASURY, coinType: '0x2::sui::SUI', amount: '-150' },
        ],
      }),
    );

    expect(alerts.map((item) => item.ruleName)).toContain('资金异常流出检测');
    expect(alerts.map((item) => item.ruleName)).toContain('高危函数越权调用检测');
    expect(alerts.map((item) => item.ruleName)).toContain('行为规则 / 非授权敏感函数调用');
  });

  it('detects package version upgrades', () => {
    const monitor = new ProjectMonitor(project);
    const previous: PackageVersionSnapshot = {
      packageAddress: PACKAGE,
      version: 1,
      sender: ADMIN,
      digest: 'old',
      updatedAt: '2026-04-23T18:37:00.000Z',
    };
    const next: PackageVersionSnapshot = {
      packageAddress: PACKAGE,
      version: 2,
      sender: ATTACKER,
      digest: 'new',
      updatedAt: '2026-04-23T18:37:59.000Z',
    };

    monitor.seedPackageVersion(previous);
    const alerts = monitor.processPackageVersion(next);

    expect(alerts).toHaveLength(1);
    expect(alerts[0]?.severity).toBe('critical');
    expect(alerts[0]?.details).toHaveProperty('attackFindings');
  });

  it('detects traffic and failure spikes', () => {
    const monitor = new ProjectMonitor(project);
    const first = buildTx({
      digest: 'tx-1',
      sender: ADMIN,
      calls: [{ package: PACKAGE, module: 'vault', function: 'deposit' }],
    });
    const second = buildTx({
      digest: 'tx-2',
      sender: ATTACKER,
      calls: [{ package: PACKAGE, module: 'vault', function: 'deposit' }],
      timestamp: '2026-04-23T18:38:00.000Z',
    });

    const alerts1 = monitor.processTransaction(first);
    const alerts2 = monitor.processTransaction(second);

    expect(alerts1).toHaveLength(0);
    expect(alerts2.some((item) => item.ruleName === '交易热度突增检测')).toBe(true);

    const fail1 = buildTx({
      digest: 'fail-1',
      sender: ADMIN,
      status: 'FAILURE',
      executionError: 'boom',
      calls: [{ package: PACKAGE, module: 'vault', function: 'borrow' }],
    });
    const fail2 = buildTx({
      digest: 'fail-2',
      sender: ATTACKER,
      status: 'FAILURE',
      executionError: 'boom',
      calls: [{ package: PACKAGE, module: 'vault', function: 'borrow' }],
      timestamp: '2026-04-23T18:38:01.000Z',
    });

    const failAlerts1 = monitor.processTransaction(fail1);
    const failAlerts2 = monitor.processTransaction(fail2);

    expect(failAlerts1).toHaveLength(0);
    expect(failAlerts2.some((item) => item.ruleName === '失败交易突增检测')).toBe(true);
  });

  it('detects repeated drain behavior patterns', () => {
    const monitor = new ProjectMonitor(project);
    const alerts = monitor.processTransaction(
      buildTx({
        sender: ATTACKER,
        calls: [
          { package: PACKAGE, module: 'vault', function: 'emergency_withdraw' },
          { package: PACKAGE, module: 'vault', function: 'withdraw' },
          { package: PACKAGE, module: 'vault', function: 'withdraw' },
        ],
        balanceChanges: [
          { owner: TREASURY, coinType: '0x2::sui::SUI', amount: '-200' },
        ],
      }),
    );

    expect(alerts.some((item) => item.ruleName === '行为规则 / 重复高危消耗模式')).toBe(true);
  });

  it('includes evidence placeholders in alert details', () => {
    const monitor = new ProjectMonitor(project);
    const alerts = monitor.processTransaction(
      buildTx({
        sender: ATTACKER,
        calls: [{ package: PACKAGE, module: 'vault', function: 'emergency_withdraw' }],
        balanceChanges: [{ owner: TREASURY, coinType: '0x2::sui::SUI', amount: '-150' }],
      }),
    );

    const alert = alerts.find((item) => item.ruleName === '行为规则 / 非授权敏感函数调用');
    expect(alert?.details).toHaveProperty('riskScore');
    expect(alert?.details).toHaveProperty('confidence');
    expect(alert?.details).toHaveProperty('evidenceSummary');
    expect(alert?.details).toHaveProperty('attackFindings');
  });

  it('includes bridge validation attack findings in behavior alert details', () => {
    const monitor = new ProjectMonitor(project);
    const alerts = monitor.processTransaction(
      buildTx({
        sender: ATTACKER,
        calls: [
          { package: PACKAGE, module: 'bridge', function: 'execute_message' },
          { package: PACKAGE, module: 'bridge', function: 'claim' },
        ],
        objectChanges: [
          {
            address: '0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
            idCreated: false,
            idDeleted: false,
            isPackage: false,
          },
        ],
      }),
    );

    const alert = alerts.find((item) => item.ruleName === '行为规则 / 可疑外部目标调用');
    const attackFindings = (alert?.details.attackFindings as Array<{ attackType: string }> | undefined) ?? [];
    expect(attackFindings.some((item) => item.attackType === 'bridge-message-validation-failure')).toBe(true);
  });
});
