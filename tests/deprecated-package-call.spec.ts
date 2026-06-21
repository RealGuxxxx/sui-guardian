import { describe, expect, it } from 'vitest';

import { ProjectMonitor } from '../src/project-monitor.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const CURRENT_PKG = '0x1111111111111111111111111111111111111111111111111111111111111111';
const DEPRECATED_PKG = '0x2222222222222222222222222222222222222222222222222222222222222222';
const ATTACKER = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

function buildProject(): MonitoringProjectConfig {
  return {
    id: 'scallop-test',
    name: 'Scallop Test',
    packages: [
      {
        label: 'Scallop Lending V3',
        address: CURRENT_PKG,
        allowedUpgradeSenders: [],
        deprecatedAddresses: [DEPRECATED_PKG],  // V2 is deprecated
      },
    ],
    protectedAddresses: [],
    functionGuards: [],
    trafficSpikes: [],
    failureSpikes: [],
    trackedObjects: [],
    suspiciousTargets: [],
    behaviorRules: { enabled: false, minRepeatedCalls: 2, minProtectedOutflow: '100', priceDeviationThresholdBps: 500 },
    priceModels: [],
    objectBaselines: [],
    flowTracking: { enabled: false, minProtectedOutflow: '100', attackerGainThreshold: '100', shortWindowTxCount: 2 },
    suppression: { enabled: false, duplicateWindowSeconds: 600, weakSignalScoreThreshold: 35, maintenanceWindows: [] },
  };
}

describe('deprecated package call detection (Scallop attack pattern)', () => {
  it('generates alert when deprecated package address is called', () => {
    const monitor = new ProjectMonitor(buildProject());

    const tx: ObservedTransaction = {
      digest: 'tx-scallop-attack',
      checkpoint: 600,
      timestamp: '2026-04-26T10:00:00.000Z',
      sender: ATTACKER,
      status: 'SUCCESS',
      // Attacker calls the deprecated V2 rewards contract
      calls: [
        { package: DEPRECATED_PKG, module: 'rewards_v2', function: 'claim_rewards' },
      ],
      balanceChanges: [],
      objectChanges: [],
    };

    const alerts = monitor.processTransaction(tx);

    expect(alerts.some((a) => a.ruleId.includes('deprecated-package-call'))).toBe(true);
    const alert = alerts.find((a) => a.ruleId.includes('deprecated-package-call'))!;
    expect(alert.severity).toBe('high');
    expect(alert.details['deprecatedPackagesCalled']).toContain(DEPRECATED_PKG);
  });

  it('does not alert for calls to current (non-deprecated) package', () => {
    const monitor = new ProjectMonitor(buildProject());

    const tx: ObservedTransaction = {
      digest: 'tx-legit-call',
      checkpoint: 601,
      timestamp: '2026-04-26T10:01:00.000Z',
      sender: ATTACKER,
      status: 'SUCCESS',
      calls: [
        { package: CURRENT_PKG, module: 'lending', function: 'deposit' },
      ],
      balanceChanges: [],
      objectChanges: [],
    };

    const alerts = monitor.processTransaction(tx);
    expect(alerts.some((a) => a.ruleId.includes('deprecated-package-call'))).toBe(false);
  });

  it('does not alert when package has no deprecatedAddresses configured', () => {
    const projectWithoutDeprecated: MonitoringProjectConfig = {
      ...buildProject(),
      packages: [{ address: CURRENT_PKG, allowedUpgradeSenders: [] }],
    };

    const monitor = new ProjectMonitor(projectWithoutDeprecated);

    const tx: ObservedTransaction = {
      digest: 'tx-unmonitored',
      checkpoint: 602,
      timestamp: '2026-04-26T10:02:00.000Z',
      sender: ATTACKER,
      status: 'SUCCESS',
      calls: [
        { package: DEPRECATED_PKG, module: 'anything', function: 'call' },
      ],
      balanceChanges: [],
      objectChanges: [],
    };

    const alerts = monitor.processTransaction(tx);
    expect(alerts.some((a) => a.ruleId.includes('deprecated-package-call'))).toBe(false);
  });
});
