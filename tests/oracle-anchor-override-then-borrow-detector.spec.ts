import { describe, expect, it } from 'vitest';

import { detectOracleAnchorOverrideThenBorrowAttacks } from '../src/detectors/known/oracle-anchor-override-then-borrow-detector.js';
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
    digest: 'tx-49',
    checkpoint: 49,
    timestamp: '2026-04-24T00:46:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [
      { package: PACKAGE, module: 'oracle', function: 'set_price_anchor' },
      { package: PACKAGE, module: 'lending', function: 'borrow' },
    ],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectOracleAnchorOverrideThenBorrowAttacks', () => {
  it('emits oracle anchor override then borrow finding when anchor pricing references are rewritten before borrowing extraction', () => {
    const findings = detectOracleAnchorOverrideThenBorrowAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'oracle-config',
            field: 'anchor_price_source',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '10100',
          netAttackerGain: '9700',
        },
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('oracle-anchor-override-then-borrow');
    expect(findings[0]?.category).toBe('price-manipulation');
    expect(findings[0]?.chainHints?.stage).toBe('takeover');
  });
});
