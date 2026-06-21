import { describe, expect, it } from 'vitest';

import { detectLiquidationManipulationAttacks } from '../src/detectors/known/liquidation-manipulation-detector.js';
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
    calls: [{ package: PACKAGE, module: 'lending', function: 'liquidate_position' }],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectLiquidationManipulationAttacks', () => {
  it('emits liquidation manipulation finding when liquidation follows strong price deviation', () => {
    const findings = detectLiquidationManipulationAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        valueExtractionDetected: true,
        priceEvidence: [
          {
            label: 'oracle-price',
            deviationBps: 2800,
            referenceKind: 'rolling_median',
            extractionCoupled: true,
          },
        ],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('liquidation-manipulation');
    expect(findings[0]?.category).toBe('liquidation');
  });
});
