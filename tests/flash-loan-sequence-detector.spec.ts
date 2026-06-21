import { describe, expect, it } from 'vitest';

import { detectFlashLoanSequenceAttacks } from '../src/detectors/known/flash-loan-sequence-detector.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PACKAGE = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ATTACKER = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const VAULT = '0x9999999999999999999999999999999999999999999999999999999999999999';

function buildProject(): MonitoringProjectConfig {
  return {
    id: 'demo',
    name: 'Demo Project',
    packages: [{ address: PACKAGE, allowedUpgradeSenders: [] }],
    protectedAddresses: [{ label: 'vault', address: VAULT, outflowThresholds: { '0x2::sui::SUI': '100' } }],
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
    digest: 'tx-flash-seq',
    checkpoint: 42,
    timestamp: '2026-04-24T02:00:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [
      { package: PACKAGE, module: 'flash_loan', function: 'borrow' },
      { package: PACKAGE, module: 'router', function: 'swap_exact' },
      { package: PACKAGE, module: 'lending_pool', function: 'borrow' },
    ],
    balanceChanges: [
      {
        owner: VAULT,
        coinType: '0x2::sui::SUI',
        amount: '-5000',
      },
      {
        owner: ATTACKER,
        coinType: '0x2::sui::SUI',
        amount: '4500',
      },
    ],
    objectChanges: [],
  };
}

describe('detectFlashLoanSequenceAttacks', () => {
  it('emits a flash-loan attack-chain finding for funding, manipulation and extraction sequence', () => {
    const findings = detectFlashLoanSequenceAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        flashLikeFundingDetected: true,
        valueExtractionDetected: true,
        priceEvidence: [
          {
            label: 'oracle-price',
            deviationBps: 2600,
            referenceKind: 'rolling_median',
            extractionCoupled: true,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['temporary_funding', 'protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '5000',
          netAttackerGain: '4500',
        },
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('flash-loan-sequence');
    expect(findings[0]?.category).toBe('liquidity-drain');
    expect(findings[0]?.chainHints?.stage).toBe('manipulation');
  });
});
