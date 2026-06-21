import { describe, expect, it } from 'vitest';

import { detectGovernanceTimelockBypassAttacks } from '../src/detectors/known/governance-timelock-bypass-detector.js';
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
    digest: 'tx-7',
    checkpoint: 7,
    timestamp: '2026-04-24T00:05:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [{ package: PACKAGE, module: 'governance', function: 'execute_proposal_now' }],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectGovernanceTimelockBypassAttacks', () => {
  it('emits governance timelock bypass finding for immediate proposal execution', () => {
    const findings = detectGovernanceTimelockBypassAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        baselineEvidence: [
          {
            objectLabel: 'governance',
            field: 'timelock',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('governance-timelock-bypass');
    expect(findings[0]?.category).toBe('governance');
  });
});
