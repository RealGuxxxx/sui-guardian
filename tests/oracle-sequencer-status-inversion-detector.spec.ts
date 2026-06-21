import { describe, expect, it } from 'vitest';

import { detectOracleSequencerStatusInversionAttacks } from '../src/detectors/known/oracle-sequencer-status-inversion-detector.js';
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
    digest: 'tx-67',
    checkpoint: 67,
    timestamp: '2026-04-24T01:04:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [
      { package: PACKAGE, module: 'oracle', function: 'set_sequencer_status_inverted' },
      { package: PACKAGE, module: 'liquidation', function: 'liquidate_position' },
    ],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectOracleSequencerStatusInversionAttacks', () => {
  it('emits oracle sequencer status inversion finding when l2 status semantics are inverted before extraction', () => {
    const findings = detectOracleSequencerStatusInversionAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'oracle-config',
            field: 'sequencer_status_inverted',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '15600',
          netAttackerGain: '15100',
        },
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('oracle-sequencer-status-inversion');
    expect(findings[0]?.category).toBe('price-manipulation');
    expect(findings[0]?.chainHints?.stage).toBe('takeover');
  });
});
