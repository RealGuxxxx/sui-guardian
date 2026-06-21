import { describe, expect, it } from 'vitest';

import { detectFlashLoanRepayMismatchAttacks } from '../src/detectors/known/flash-loan-repay-mismatch-detector.js';
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
    digest: 'tx-17',
    checkpoint: 17,
    timestamp: '2026-04-24T00:14:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [
      { package: PACKAGE, module: 'flash_loan', function: 'borrow' },
      { package: PACKAGE, module: 'vault', function: 'withdraw' },
      { package: PACKAGE, module: 'flash_loan', function: 'repay' },
    ],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectFlashLoanRepayMismatchAttacks', () => {
  it('emits repay mismatch finding when temporary funding path exists but attacker still retains net gain after repay', () => {
    const findings = detectFlashLoanRepayMismatchAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        flashLikeFundingDetected: true,
        valueExtractionDetected: true,
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['temporary_funding', 'protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '10000',
          netAttackerGain: '3200',
        },
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('flash-loan-repay-mismatch');
    expect(findings[0]?.category).toBe('liquidity-drain');
    expect(findings[0]?.chainHints?.stage).toBe('extraction');
  });
});
