import { describe, expect, it } from 'vitest';

import { detectBridgeDrainAfterClaimAttacks } from '../src/detectors/known/bridge-drain-after-claim-detector.js';
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
    suspiciousTargets: [{ label: 'bridge-relayer', address: '0x999' }],
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
    digest: 'tx-16',
    checkpoint: 16,
    timestamp: '2026-04-24T00:13:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [
      { package: PACKAGE, module: 'bridge', function: 'claim' },
      { package: PACKAGE, module: 'vault', function: 'withdraw' },
    ],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectBridgeDrainAfterClaimAttacks', () => {
  it('emits bridge drain finding when claim is followed by protected outflow and attacker receipt', () => {
    const findings = detectBridgeDrainAfterClaimAttacks({
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
          netProtectedOutflow: '9000',
          netAttackerGain: '8100',
        },
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('bridge-drain-after-claim');
    expect(findings[0]?.category).toBe('liquidity-drain');
    expect(findings[0]?.chainHints?.stage).toBe('extraction');
  });
});
