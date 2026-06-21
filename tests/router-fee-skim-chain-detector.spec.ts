import { describe, expect, it } from 'vitest';

import { detectRouterFeeSkimChainAttacks } from '../src/detectors/known/router-fee-skim-chain-detector.js';
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
    digest: 'tx-41',
    checkpoint: 41,
    timestamp: '2026-04-24T00:38:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [
      { package: PACKAGE, module: 'router', function: 'set_fee_recipient' },
      { package: PACKAGE, module: 'router', function: 'collect_router_fee' },
      { package: PACKAGE, module: 'router', function: 'multi_hop_swap' },
    ],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectRouterFeeSkimChainAttacks', () => {
  it('emits router fee skim chain finding when router fee recipient changes are followed by fee collection and routed extraction', () => {
    const findings = detectRouterFeeSkimChainAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        suspiciousTargets: ['0x999'],
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'router-config',
            field: 'fee_recipient',
            anomalyKind: 'permission_change',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['intermediate_hop', 'protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '8400',
          netAttackerGain: '8000',
        },
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('router-fee-skim-chain');
    expect(findings[0]?.category).toBe('liquidity-drain');
    expect(findings[0]?.chainHints?.stage).toBe('extraction');
  });
});
