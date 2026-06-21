import { describe, expect, it } from 'vitest';

import { detectGovernanceExecutionAfterVoteSurgeAttacks } from '../src/detectors/known/governance-execution-after-vote-surge-detector.js';
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
    digest: 'tx-18',
    checkpoint: 18,
    timestamp: '2026-04-24T00:15:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [
      { package: PACKAGE, module: 'governance', function: 'vote' },
      { package: PACKAGE, module: 'governance', function: 'vote' },
      { package: PACKAGE, module: 'governance', function: 'execute_proposal' },
    ],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectGovernanceExecutionAfterVoteSurgeAttacks', () => {
  it('emits governance execution finding when vote surge is followed by execution and unauthorized governance shift', () => {
    const findings = detectGovernanceExecutionAfterVoteSurgeAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        sameSensitiveCallRepeats: {
          'governance::vote': 4,
        },
        baselineEvidence: [
          {
            objectLabel: 'governance',
            field: 'proposal_executor',
            anomalyKind: 'permission_change',
            senderAuthorized: false,
          },
        ],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('governance-execution-after-vote-surge');
    expect(findings[0]?.category).toBe('governance');
    expect(findings[0]?.chainHints?.stage).toBe('takeover');
  });
});
