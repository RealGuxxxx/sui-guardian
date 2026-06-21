import { describe, expect, it } from 'vitest';

import { detectArbitraryExternalCallAttacks } from '../src/detectors/known/arbitrary-external-call-detector.js';
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
    suspiciousTargets: [{ label: 'rogue-router', address: '0x999' }],
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
    digest: 'tx-4',
    checkpoint: 4,
    timestamp: '2026-04-24T00:03:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [{ package: PACKAGE, module: 'router', function: 'call_unchecked' }],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectArbitraryExternalCallAttacks', () => {
  it('emits arbitrary external call finding for suspicious target plus extraction intent', () => {
    const findings = detectArbitraryExternalCallAttacks({
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

    expect(findings[0]?.attackType).toBe('arbitrary-external-call');
    expect(findings[0]?.category).toBe('execution-abuse');
  });
});
