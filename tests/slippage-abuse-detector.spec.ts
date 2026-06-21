import { describe, expect, it } from 'vitest';

import { detectSlippageAbuseAttacks } from '../src/detectors/known/slippage-abuse-detector.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PACKAGE = '0x1111111111111111111111111111111111111111111111111111111111111111';
const USER = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

function buildProject(): MonitoringProjectConfig {
  return {
    id: 'demo',
    name: 'Demo Project',
    packages: [{ address: PACKAGE, allowedUpgradeSenders: [USER] }],
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
    digest: 'tx-2',
    checkpoint: 2,
    timestamp: '2026-04-24T00:01:00.000Z',
    sender: USER,
    status: 'SUCCESS',
    calls: [
      { package: PACKAGE, module: 'dex', function: 'swap_exact_input' },
    ],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectSlippageAbuseAttacks', () => {
  it('emits slippage abuse finding when swap executes under extreme price deviation', () => {
    const findings = detectSlippageAbuseAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        valueExtractionDetected: true,
        priceEvidence: [
          {
            label: 'pool-price',
            deviationBps: 3600,
            referenceKind: 'rolling_median',
            extractionCoupled: true,
          },
        ],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('slippage-abuse');
    expect(findings[0]?.category).toBe('price-manipulation');
  });
});
