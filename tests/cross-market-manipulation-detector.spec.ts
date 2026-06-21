import { describe, expect, it } from 'vitest';

import { detectCrossMarketManipulationAttacks } from '../src/detectors/known/cross-market-manipulation-detector.js';
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
    digest: 'tx-15',
    checkpoint: 15,
    timestamp: '2026-04-24T00:12:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [
      { package: PACKAGE, module: 'amm_a', function: 'swap_exact' },
      { package: PACKAGE, module: 'amm_b', function: 'borrow' },
      { package: PACKAGE, module: 'router', function: 'redeem' },
    ],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectCrossMarketManipulationAttacks', () => {
  it('emits cross market manipulation finding when multi-market calls align with price deviation and attack path', () => {
    const findings = detectCrossMarketManipulationAttacks({
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
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['manipulation_target', 'protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '7000',
          netAttackerGain: '6500',
        },
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('cross-market-manipulation');
    expect(findings[0]?.category).toBe('price-manipulation');
    expect(findings[0]?.chainHints?.stage).toBe('manipulation');
  });
});
