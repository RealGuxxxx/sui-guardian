import { describe, expect, it } from 'vitest';

import { detectUnknownCoordinatedAttack } from '../src/detectors/anomaly/unknown-attack-detector.js';
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

describe('detectUnknownCoordinatedAttack', () => {
  it('emits unknown coordinated anomaly when multiple signals resonate', () => {
    const findings = detectUnknownCoordinatedAttack({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        priceEvidence: [
          {
            label: 'oracle-price',
            deviationBps: 2200,
            referenceKind: 'rolling_median',
            extractionCoupled: false,
          },
        ],
        baselineEvidence: [
          {
            objectLabel: 'vault',
            field: 'admin',
            anomalyKind: 'permission_change',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: false,
          pathRoles: [],
          netProtectedOutflow: '0',
          netAttackerGain: '0',
        },
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('unknown-coordinated-anomaly');
  });
});
