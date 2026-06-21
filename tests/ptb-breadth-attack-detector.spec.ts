import { describe, expect, it } from 'vitest';

import { detectPtbBreadthAttacks } from '../src/detectors/known/ptb-breadth-attack-detector.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PKG = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ATTACKER = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const VAULT = '0x9999999999999999999999999999999999999999999999999999999999999999';

function buildProject(): MonitoringProjectConfig {
  return {
    id: 'breadth-test',
    name: 'Breadth Attack Test',
    packages: [{ address: PKG, allowedUpgradeSenders: [] }],
    protectedAddresses: [{ label: 'vault', address: VAULT, outflowThresholds: {} }],
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

/** Build a PTB with N repeated calls to the same function */
function buildBreadthTx(fnName: string, repeatCount: number): ObservedTransaction {
  return {
    digest: `tx-breadth-${repeatCount}`,
    checkpoint: 500,
    timestamp: '2025-05-22T12:00:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: Array.from({ length: repeatCount }, (_, i) => ({
      package: PKG,
      module: 'clmm_pool',
      function: fnName,
    })),
    balanceChanges: [
      { owner: VAULT, coinType: '0x2::sui::SUI', amount: '-50000000' },
      { owner: ATTACKER, coinType: '0x2::sui::SUI', amount: '45000000' },
    ],
    objectChanges: [],
  };
}

describe('detectPtbBreadthAttacks', () => {
  it('detects Cetus-style CLMM add_liquidity repeated 10+ times with extraction', () => {
    const tx = buildBreadthTx('add_liquidity', 12);

    const findings = detectPtbBreadthAttacks({
      project: buildProject(),
      tx,
      derived: {
        valueExtractionDetected: true,
        flowEvidence: { nodes: [], edges: [], attackPathFound: true, pathRoles: [], netProtectedOutflow: '50000000', netAttackerGain: '45000000' },
      },
      runtime: { recentAlerts: [] },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.attackType).toBe('ptb-breadth-attack');
    expect(findings[0]?.category).toBe('liquidity-drain');
    expect(findings[0]?.riskHints?.severityFloor).toBe('critical');
    expect(findings[0]?.evidence['isClmmRelated']).toBe(true);
  });

  it('does not fire for small PTBs (< 8 calls)', () => {
    const tx = buildBreadthTx('add_liquidity', 5);

    const findings = detectPtbBreadthAttacks({
      project: buildProject(),
      tx,
      derived: { valueExtractionDetected: true },
      runtime: { recentAlerts: [] },
    });

    expect(findings).toHaveLength(0);
  });

  it('does not fire without extraction signal for non-CLMM giant PTBs', () => {
    const tx = buildBreadthTx('vote', 35);

    const findings = detectPtbBreadthAttacks({
      project: buildProject(),
      tx,
      derived: { valueExtractionDetected: false },
      runtime: { recentAlerts: [] },
    });

    expect(findings).toHaveLength(0);
  });

  it('detects giant CLMM PTB even without extraction signal (Cetus pre-drain setup)', () => {
    const tx: ObservedTransaction = {
      digest: 'tx-giant-clmm',
      checkpoint: 501,
      timestamp: '2025-05-22T12:05:00.000Z',
      sender: ATTACKER,
      status: 'SUCCESS',
      // 35 calls: mix of add_liquidity and remove_liquidity — giant CLMM PTB
      calls: [
        ...Array.from({ length: 18 }, () => ({ package: PKG, module: 'clmm', function: 'add_liquidity' })),
        ...Array.from({ length: 17 }, () => ({ package: PKG, module: 'clmm', function: 'remove_liquidity' })),
      ],
      balanceChanges: [],
      objectChanges: [],
    };

    const findings = detectPtbBreadthAttacks({
      project: buildProject(),
      tx,
      derived: { valueExtractionDetected: false },
      runtime: { recentAlerts: [] },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.attackType).toBe('ptb-breadth-attack');
    expect(findings[0]?.evidence['isGiantPtb']).toBe(true);
    expect(findings[0]?.evidence['isClmmRelated']).toBe(true);
  });

  it('marks high-repeat non-CLMM function as high severity with extraction', () => {
    const tx = buildBreadthTx('drain_pool', 10);

    const findings = detectPtbBreadthAttacks({
      project: buildProject(),
      tx,
      derived: {
        valueExtractionDetected: true,
        flowEvidence: { nodes: [], edges: [], attackPathFound: true, pathRoles: [], netProtectedOutflow: '1000000', netAttackerGain: '800000' },
      },
      runtime: { recentAlerts: [] },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.riskHints?.severityFloor).toBe('high');
  });
});
