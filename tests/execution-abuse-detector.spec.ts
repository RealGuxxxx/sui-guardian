import { describe, expect, it } from 'vitest';

import { detectExecutionAbuseAttacks } from '../src/detectors/known/execution-abuse-detector.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PACKAGE = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ADMIN = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

function buildProject(): MonitoringProjectConfig {
  return {
    id: 'demo',
    name: 'Demo Project',
    packages: [{ address: PACKAGE, allowedUpgradeSenders: [ADMIN] }],
    protectedAddresses: [],
    functionGuards: [],
    trafficSpikes: [],
    failureSpikes: [],
    trackedObjects: [],
    suspiciousTargets: [],
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
}

function buildTx(): ObservedTransaction {
  return {
    digest: 'tx-1',
    checkpoint: 1,
    timestamp: '2026-04-24T00:00:00.000Z',
    sender: ADMIN,
    status: 'SUCCESS',
    calls: [],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectExecutionAbuseAttacks', () => {
  it('emits execution abuse finding for repeated sensitive calls and suspicious targets', () => {
    const findings = detectExecutionAbuseAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        sameSensitiveCallRepeats: {
          'arena::emergency_withdraw_all': 3,
        },
        suspiciousTargets: ['0x111'],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('execution-abuse');
  });

  it('ignores repeated ordinary trading calls', () => {
    const findings = detectExecutionAbuseAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        sameSensitiveCallRepeats: {
          'pool::place_limit_order': 4,
        },
        suspiciousTargets: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings).toHaveLength(0);
  });
});
