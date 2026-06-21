import { describe, expect, it } from 'vitest';

import { detectRouterApprovalReuseAttacks } from '../src/detectors/known/router-approval-reuse-detector.js';
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
    digest: 'tx-29',
    checkpoint: 29,
    timestamp: '2026-04-24T00:26:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [
      { package: PACKAGE, module: 'token', function: 'approve_router' },
      { package: PACKAGE, module: 'router', function: 'multi_hop_swap' },
    ],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectRouterApprovalReuseAttacks', () => {
  it('emits router approval reuse finding when approval style calls are reused via suspicious router hops for extraction', () => {
    const findings = detectRouterApprovalReuseAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        suspiciousTargets: ['0x999'],
        valueExtractionDetected: true,
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['intermediate_hop', 'protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '5100',
          netAttackerGain: '4800',
        },
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('router-approval-reuse');
    expect(findings[0]?.category).toBe('execution-abuse');
    expect(findings[0]?.chainHints?.stage).toBe('extraction');
  });
});
