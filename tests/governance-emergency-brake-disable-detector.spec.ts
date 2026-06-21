import { describe, expect, it } from 'vitest';

import { detectGovernanceEmergencyBrakeDisableAttacks } from '../src/detectors/known/governance-emergency-brake-disable-detector.js';
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
    digest: 'tx-40',
    checkpoint: 40,
    timestamp: '2026-04-24T00:37:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [
      { package: PACKAGE, module: 'governance', function: 'disable_emergency_brake' },
      { package: PACKAGE, module: 'governance', function: 'execute_proposal' },
    ],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectGovernanceEmergencyBrakeDisableAttacks', () => {
  it('emits governance emergency brake disable finding when emergency brakes are disabled before governance execution', () => {
    const findings = detectGovernanceEmergencyBrakeDisableAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        baselineEvidence: [
          {
            objectLabel: 'governance',
            field: 'emergency_brake_enabled',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('governance-emergency-brake-disable');
    expect(findings[0]?.category).toBe('governance');
    expect(findings[0]?.chainHints?.stage).toBe('takeover');
  });
});
