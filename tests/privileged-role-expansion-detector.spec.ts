import { describe, expect, it } from 'vitest';

import { detectPrivilegedRoleExpansionAttacks } from '../src/detectors/known/privileged-role-expansion-detector.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PACKAGE = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ATTACKER = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

function buildProject(): MonitoringProjectConfig {
  return {
    id: 'demo',
    name: 'Demo Project',
    packages: [{ address: PACKAGE, allowedUpgradeSenders: [] }],
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
    digest: 'tx-11',
    checkpoint: 11,
    timestamp: '2026-04-24T00:08:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [{ package: PACKAGE, module: 'governance', function: 'grant_operator_role' }],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectPrivilegedRoleExpansionAttacks', () => {
  it('emits privileged role expansion finding when unauthorized sender expands multiple privileged fields', () => {
    const findings = detectPrivilegedRoleExpansionAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        baselineEvidence: [
          {
            objectLabel: 'admin-vault',
            field: 'admin',
            anomalyKind: 'permission_change',
            senderAuthorized: false,
          },
          {
            objectLabel: 'governance',
            field: 'operator',
            anomalyKind: 'permission_change',
            senderAuthorized: false,
          },
        ],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('privileged-role-expansion');
    expect(findings[0]?.category).toBe('permission');
    expect(findings[0]?.chainHints?.stage).toBe('takeover');
  });
});
