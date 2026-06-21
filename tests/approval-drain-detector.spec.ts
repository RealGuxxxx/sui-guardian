import { describe, expect, it } from 'vitest';

import { detectApprovalDrainAttacks } from '../src/detectors/known/approval-drain-detector.js';
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
    suspiciousTargets: [{ label: 'rogue-spender', address: '0x999' }],
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
    digest: 'tx-24',
    checkpoint: 24,
    timestamp: '2026-04-24T00:21:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [
      { package: PACKAGE, module: 'token', function: 'approve_spender' },
      { package: PACKAGE, module: 'vault', function: 'transfer_from_vault' },
    ],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectApprovalDrainAttacks', () => {
  it('emits approval drain finding when approval style calls are followed by attacker extraction', () => {
    const findings = detectApprovalDrainAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        suspiciousTargets: ['0x999'],
        valueExtractionDetected: true,
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '5500',
          netAttackerGain: '5200',
        },
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('approval-drain');
    expect(findings[0]?.category).toBe('liquidity-drain');
    expect(findings[0]?.chainHints?.stage).toBe('extraction');
  });
});
