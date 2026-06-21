import { describe, expect, it } from 'vitest';

import { detectMaintenanceWindowBypassAttacks } from '../src/detectors/known/maintenance-window-bypass-detector.js';
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
      maintenanceWindows: [
        {
          label: 'weekly-upgrade',
          allowedSenders: [ADMIN],
          startHourUtc: 1,
          endHourUtc: 2,
        },
      ],
    },
  };
}

function buildTx(): ObservedTransaction {
  return {
    digest: 'tx-5',
    checkpoint: 5,
    timestamp: '2026-04-24T05:30:00.000Z',
    sender: ADMIN,
    status: 'SUCCESS',
    calls: [{ package: PACKAGE, module: 'vault', function: 'emergency_withdraw' }],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectMaintenanceWindowBypassAttacks', () => {
  it('emits maintenance window bypass for privileged action outside allowed maintenance hours', () => {
    const findings = detectMaintenanceWindowBypassAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        baselineEvidence: [
          {
            objectLabel: 'admin-vault',
            field: 'admin',
            anomalyKind: 'permission_change',
            senderAuthorized: true,
          },
        ],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('maintenance-window-bypass');
    expect(findings[0]?.category).toBe('governance');
  });
});
