import { describe, expect, it } from 'vitest';

import { detectAttackerProfitRealizationAttacks } from '../src/detectors/known/attacker-profit-realization-detector.js';
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
    digest: 'tx-8',
    checkpoint: 8,
    timestamp: '2026-04-24T00:06:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [{ package: PACKAGE, module: 'vault', function: 'withdraw_profit' }],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectAttackerProfitRealizationAttacks', () => {
  it('emits attacker profit realization when attack path and attacker gain both exist', () => {
    const findings = detectAttackerProfitRealizationAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '3000',
          netAttackerGain: '2500',
        },
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('attacker-profit-realization');
    expect(findings[0]?.category).toBe('liquidity-drain');
  });
});
