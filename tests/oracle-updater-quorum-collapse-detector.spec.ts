import { describe, expect, it } from 'vitest';

import { detectOracleUpdaterQuorumCollapseAttacks } from '../src/detectors/known/oracle-updater-quorum-collapse-detector.js';
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
    digest: 'tx-52',
    checkpoint: 52,
    timestamp: '2026-04-24T00:49:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [
      { package: PACKAGE, module: 'oracle', function: 'set_updater_quorum' },
      { package: PACKAGE, module: 'lending', function: 'borrow' },
    ],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectOracleUpdaterQuorumCollapseAttacks', () => {
  it('emits oracle updater quorum collapse finding when updater consensus thresholds are collapsed before extraction', () => {
    const findings = detectOracleUpdaterQuorumCollapseAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'oracle-config',
            field: 'updater_quorum',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '10400',
          netAttackerGain: '10000',
        },
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('oracle-updater-quorum-collapse');
    expect(findings[0]?.category).toBe('price-manipulation');
    expect(findings[0]?.chainHints?.stage).toBe('takeover');
  });
});
