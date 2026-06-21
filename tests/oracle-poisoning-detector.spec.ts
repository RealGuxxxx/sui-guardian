import { describe, expect, it } from 'vitest';

import { detectOraclePoisoningAttacks } from '../src/detectors/known/oracle-poisoning-detector.js';
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
    digest: 'tx-6',
    checkpoint: 6,
    timestamp: '2026-04-24T00:04:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [{ package: PACKAGE, module: 'oracle', function: 'update_price_feed' }],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectOraclePoisoningAttacks', () => {
  it('emits oracle poisoning finding for oracle update plus extreme price deviation', () => {
    const findings = detectOraclePoisoningAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        priceEvidence: [
          {
            label: 'oracle-price',
            deviationBps: 4200,
            referenceKind: 'rolling_median',
            extractionCoupled: false,
          },
        ],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('oracle-poisoning');
    expect(findings[0]?.category).toBe('price-manipulation');
  });
});
