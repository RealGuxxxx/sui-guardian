import { describe, expect, it } from 'vitest';

import { detectClmmExtremeTickAttacks } from '../src/detectors/known/clmm-extreme-tick-attack-detector.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PACKAGE = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ATTACKER = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const VAULT = '0x9999999999999999999999999999999999999999999999999999999999999999';

function buildProject(): MonitoringProjectConfig {
  return {
    id: 'cetus-test',
    name: 'CLMM Test',
    packages: [{ address: PACKAGE, allowedUpgradeSenders: [] }],
    protectedAddresses: [{ label: 'pool', address: VAULT, outflowThresholds: { '0x2::sui::SUI': '100' } }],
    functionGuards: [],
    trafficSpikes: [],
    failureSpikes: [],
    trackedObjects: [],
    suspiciousTargets: [],
    behaviorRules: { enabled: true, minRepeatedCalls: 2, minProtectedOutflow: '100', priceDeviationThresholdBps: 500 },
    priceModels: [],
    objectBaselines: [],
    flowTracking: { enabled: true, minProtectedOutflow: '100', attackerGainThreshold: '100', shortWindowTxCount: 2 },
    suppression: { enabled: true, duplicateWindowSeconds: 600, weakSignalScoreThreshold: 35, maintenanceWindows: [] },
  };
}

function buildClmmAttackTx(): ObservedTransaction {
  return {
    digest: 'tx-cetus-attack',
    checkpoint: 100,
    timestamp: '2025-05-22T12:00:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    // Cetus pattern: flash_swap -> add_liquidity -> remove_liquidity -> repay
    calls: [
      { package: PACKAGE, module: 'pool', function: 'flash_swap' },
      { package: PACKAGE, module: 'clmm_pool', function: 'add_liquidity' },
      { package: PACKAGE, module: 'clmm_pool', function: 'remove_liquidity' },
      { package: PACKAGE, module: 'pool', function: 'repay_flash_swap' },
    ],
    balanceChanges: [
      { owner: VAULT, coinType: '0x2::sui::SUI', amount: '-10000000' },
      { owner: ATTACKER, coinType: '0x2::sui::SUI', amount: '9000000' },
    ],
    objectChanges: [],
  };
}

describe('detectClmmExtremeTickAttacks', () => {
  it('detects Cetus-style CLMM flash-loan + liquidity manipulation attack', () => {
    const findings = detectClmmExtremeTickAttacks({
      project: buildProject(),
      tx: buildClmmAttackTx(),
      derived: {
        flashLikeFundingDetected: true,
        valueExtractionDetected: true,
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['temporary_funding', 'protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '10000000',
          netAttackerGain: '9000000',
        },
      },
      runtime: { recentAlerts: [] },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.attackType).toBe('clmm-extreme-tick-attack');
    expect(findings[0]?.category).toBe('liquidity-drain');
    expect(findings[0]?.chainHints?.stage).toBe('extraction');
    expect(findings[0]?.riskHints?.severityFloor).toBe('high');
  });

  it('does not fire without flash borrow call', () => {
    const tx = buildClmmAttackTx();
    tx.calls = [
      { package: PACKAGE, module: 'clmm_pool', function: 'add_liquidity' },
      { package: PACKAGE, module: 'clmm_pool', function: 'remove_liquidity' },
    ];

    const findings = detectClmmExtremeTickAttacks({
      project: buildProject(),
      tx,
      derived: { valueExtractionDetected: true, flowEvidence: { nodes: [], edges: [], attackPathFound: true, pathRoles: [], netProtectedOutflow: '10000000', netAttackerGain: '9000000' } },
      runtime: { recentAlerts: [] },
    });

    expect(findings).toHaveLength(0);
  });

  it('does not fire without value extraction', () => {
    const findings = detectClmmExtremeTickAttacks({
      project: buildProject(),
      tx: buildClmmAttackTx(),
      derived: {
        flashLikeFundingDetected: true,
        valueExtractionDetected: false,
        flowEvidence: { nodes: [], edges: [], attackPathFound: false, pathRoles: [], netProtectedOutflow: '0', netAttackerGain: '0' },
      },
      runtime: { recentAlerts: [] },
    });

    expect(findings).toHaveLength(0);
  });

  it('marks multi-pool attack as critical severity', () => {
    const tx = buildClmmAttackTx();
    const PKG2 = '0x2222222222222222222222222222222222222222222222222222222222222222';
    tx.calls = [
      { package: PACKAGE, module: 'pool', function: 'flash_swap' },
      { package: PACKAGE, module: 'clmm_pool', function: 'add_liquidity' },
      { package: PKG2, module: 'clmm_pool2', function: 'add_liquidity' },
      { package: PACKAGE, module: 'clmm_pool', function: 'remove_liquidity' },
      { package: PKG2, module: 'clmm_pool2', function: 'remove_liquidity' },
      { package: PACKAGE, module: 'pool', function: 'repay_flash_swap' },
    ];

    const findings = detectClmmExtremeTickAttacks({
      project: buildProject(),
      tx,
      derived: {
        flashLikeFundingDetected: true,
        valueExtractionDetected: true,
        flowEvidence: { nodes: [], edges: [], attackPathFound: true, pathRoles: [], netProtectedOutflow: '50000000', netAttackerGain: '45000000' },
      },
      runtime: { recentAlerts: [] },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.riskHints?.severityFloor).toBe('critical');
    expect(findings[0]?.evidence['isMultiPoolAttack']).toBe(true);
  });
});
