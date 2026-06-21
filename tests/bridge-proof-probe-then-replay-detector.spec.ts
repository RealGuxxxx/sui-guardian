import { describe, expect, it } from 'vitest';

import { detectBridgeProofProbeThenReplayAttacks } from '../src/detectors/known/bridge-proof-probe-then-replay-detector.js';
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
    digest: 'tx-39',
    checkpoint: 39,
    timestamp: '2026-04-24T00:36:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [
      { package: PACKAGE, module: 'bridge', function: 'verify_proof' },
      { package: PACKAGE, module: 'bridge', function: 'claim_message' },
      { package: PACKAGE, module: 'vault', function: 'withdraw' },
    ],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectBridgeProofProbeThenReplayAttacks', () => {
  it('emits bridge proof probe then replay finding when recent probe alerts precede proof replay extraction', () => {
    const findings = detectBridgeProofProbeThenReplayAttacks({
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
          netProtectedOutflow: '9100',
          netAttackerGain: '8700',
        },
      },
      runtime: {
        recentAlerts: [
          { ruleId: 'traffic-spike:bridge-probe', details: {} },
          { ruleId: 'failure-spike:verify-proof', details: {} },
        ],
      },
    });

    expect(findings[0]?.attackType).toBe('bridge-proof-probe-then-replay');
    expect(findings[0]?.category).toBe('liquidity-drain');
    expect(findings[0]?.chainHints?.stage).toBe('extraction');
  });
});
