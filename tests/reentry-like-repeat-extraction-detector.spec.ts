import { describe, expect, it } from 'vitest';

import { detectReentryLikeRepeatExtractionAttacks } from '../src/detectors/known/reentry-like-repeat-extraction-detector.js';
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
    digest: 'tx-23',
    checkpoint: 23,
    timestamp: '2026-04-24T00:20:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [
      { package: PACKAGE, module: 'vault', function: 'withdraw' },
      { package: PACKAGE, module: 'vault', function: 'withdraw' },
      { package: PACKAGE, module: 'vault', function: 'withdraw' },
    ],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectReentryLikeRepeatExtractionAttacks', () => {
  it('emits reentry-like finding when repeated extraction call clusters align with attack path', () => {
    const findings = detectReentryLikeRepeatExtractionAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        sameSensitiveCallRepeats: {
          'vault::withdraw': 3,
        },
        valueExtractionDetected: true,
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '6000',
          netAttackerGain: '5200',
        },
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('reentry-like-repeat-extraction');
    expect(findings[0]?.category).toBe('execution-abuse');
    expect(findings[0]?.chainHints?.stage).toBe('extraction');
  });
});
