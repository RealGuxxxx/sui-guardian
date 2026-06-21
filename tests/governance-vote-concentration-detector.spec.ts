import { describe, expect, it } from 'vitest';

import { detectGovernanceVoteConcentrationAttacks } from '../src/detectors/known/governance-vote-concentration-detector.js';
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
    digest: 'tx-14',
    checkpoint: 14,
    timestamp: '2026-04-24T00:11:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [
      { package: PACKAGE, module: 'governance', function: 'vote' },
      { package: PACKAGE, module: 'governance', function: 'vote' },
      { package: PACKAGE, module: 'governance', function: 'vote' },
    ],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectGovernanceVoteConcentrationAttacks', () => {
  it('emits governance vote concentration finding when the same governance vote is repeated and coupled with takeover signals', () => {
    const findings = detectGovernanceVoteConcentrationAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        sameSensitiveCallRepeats: {
          'governance::vote': 3,
        },
        baselineEvidence: [
          {
            objectLabel: 'governance',
            field: 'quorum_override',
            anomalyKind: 'permission_change',
            senderAuthorized: false,
          },
        ],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('governance-vote-concentration');
    expect(findings[0]?.category).toBe('governance');
    expect(findings[0]?.chainHints?.stage).toBe('takeover');
  });
});
