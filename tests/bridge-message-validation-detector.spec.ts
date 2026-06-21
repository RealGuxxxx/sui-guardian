import { describe, expect, it } from 'vitest';

import { detectBridgeMessageValidationAttacks } from '../src/detectors/known/bridge-message-validation-detector.js';
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
    digest: 'tx-3',
    checkpoint: 3,
    timestamp: '2026-04-24T00:02:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [
      { package: PACKAGE, module: 'bridge', function: 'execute_message' },
      { package: PACKAGE, module: 'bridge', function: 'claim' },
    ],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectBridgeMessageValidationAttacks', () => {
  it('emits bridge validation finding for suspicious bridge execution plus extraction', () => {
    const findings = detectBridgeMessageValidationAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        suspiciousTargets: ['0x999'],
        valueExtractionDetected: true,
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('bridge-message-validation-failure');
    expect(findings[0]?.category).toBe('governance');
  });
});
