import { describe, expect, it } from 'vitest';

import { detectMultiAssetDrainAttacks } from '../src/detectors/known/multi-asset-drain-detector.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PACKAGE = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ATTACKER = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const VAULT = '0x9999999999999999999999999999999999999999999999999999999999999999';

function buildProject(): MonitoringProjectConfig {
  return {
    id: 'demo',
    name: 'Demo Project',
    packages: [{ address: PACKAGE, allowedUpgradeSenders: [] }],
    protectedAddresses: [{ label: 'vault', address: VAULT, outflowThresholds: { '0x2::sui::SUI': '100' } }],
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
    digest: 'tx-20',
    checkpoint: 20,
    timestamp: '2026-04-24T00:17:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [{ package: PACKAGE, module: 'vault', function: 'withdraw_all_assets' }],
    balanceChanges: [
      { owner: VAULT, coinType: '0x2::sui::SUI', amount: '-5000' },
      { owner: VAULT, coinType: '0x2::usdc::USDC', amount: '-9000' },
      { owner: ATTACKER, coinType: '0x2::sui::SUI', amount: '3000' },
      { owner: ATTACKER, coinType: '0x2::usdc::USDC', amount: '7000' },
    ],
    objectChanges: [],
  };
}

describe('detectMultiAssetDrainAttacks', () => {
  it('emits multi asset drain finding when multiple protected assets flow out in one attack path', () => {
    const findings = detectMultiAssetDrainAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        valueExtractionDetected: true,
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '14000',
          netAttackerGain: '10000',
        },
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('multi-asset-drain');
    expect(findings[0]?.category).toBe('liquidity-drain');
    expect(findings[0]?.chainHints?.stage).toBe('extraction');
  });
});
