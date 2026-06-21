import { describe, expect, it } from 'vitest';

import { detectGovernanceParameterPoisoningAttacks } from '../src/detectors/known/governance-parameter-poisoning-detector.js';
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
    digest: 'tx-28',
    checkpoint: 28,
    timestamp: '2026-04-24T00:25:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [
      { package: PACKAGE, module: 'governance', function: 'set_vote_threshold' },
      { package: PACKAGE, module: 'governance', function: 'execute_proposal' },
    ],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectGovernanceParameterPoisoningAttacks', () => {
  it('emits governance parameter poisoning finding when unauthorized governance thresholds are mutated before execution', () => {
    const findings = detectGovernanceParameterPoisoningAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        baselineEvidence: [
          {
            objectLabel: 'governance',
            field: 'vote_threshold_bps',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('governance-parameter-poisoning');
    expect(findings[0]?.category).toBe('governance');
    expect(findings[0]?.chainHints?.stage).toBe('manipulation');
  });
});
