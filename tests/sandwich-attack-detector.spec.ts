import { describe, expect, it } from 'vitest';

import { detectSandwichAttacks } from '../src/detectors/known/sandwich-attack-detector.js';
import type { AttackDetectorContext } from '../src/detectors/types.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PKG = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ATTACKER = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const USDC = '0x5d4b302506645c37ff133b98c4b50a406ae2a9dd::coin::USDC';
const SUI = '0x2::sui::SUI';

function buildProject(): MonitoringProjectConfig {
  return {
    id: 'test',
    name: 'Test',
    packages: [{ address: PKG, allowedUpgradeSenders: [] }],
    protectedAddresses: [],
    functionGuards: [],
    trafficSpikes: [],
    failureSpikes: [],
    trackedObjects: [],
    suspiciousTargets: [],
    behaviorRules: { enabled: false, minRepeatedCalls: 2, minProtectedOutflow: '100', priceDeviationThresholdBps: 500 },
    priceModels: [],
    objectBaselines: [],
    flowTracking: { enabled: false, minProtectedOutflow: '100', attackerGainThreshold: '100', shortWindowTxCount: 2 },
    suppression: { enabled: false, duplicateWindowSeconds: 600, weakSignalScoreThreshold: 35, maintenanceWindows: [] },
  };
}

function buildCtx(
  calls: ObservedTransaction['calls'],
  balanceChanges: ObservedTransaction['balanceChanges'] = [],
  recentAlerts: AttackDetectorContext['runtime']['recentAlerts'] = [],
): AttackDetectorContext {
  return {
    project: buildProject(),
    tx: {
      digest: 'tx-test',
      checkpoint: 100,
      timestamp: '2026-05-05T10:00:00.000Z',
      sender: ATTACKER,
      status: 'SUCCESS',
      calls,
      balanceChanges,
      objectChanges: [],
    },
    derived: {
      flashLikeFundingDetected: false,
      valueExtractionDetected: false,
      suspiciousTargets: [],
      sameSensitiveCallRepeats: {},
      priceEvidence: [],
      baselineEvidence: [],
      flowEvidence: { nodes: [] },
      risk: { score: 0, recommendedSeverity: 'info' },
      evidenceSummary: { categories: [], totalWeight: 0 },
    },
    runtime: {
      recentAlerts,
      senderHistory: null,
    },
  };
}

describe('detectSandwichAttacks', () => {
  it('does not fire with only 1 swap call', () => {
    const ctx = buildCtx([{ package: PKG, module: 'pool', function: 'swap_a2b' }]);
    expect(detectSandwichAttacks(ctx)).toHaveLength(0);
  });

  it('does not fire with 2 swap calls (need 3 for intra-PTB)', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'pool', function: 'swap_a2b' },
      { package: PKG, module: 'pool', function: 'swap_b2a' },
    ]);
    expect(detectSandwichAttacks(ctx)).toHaveLength(0);
  });

  it('fires for intra-PTB sandwich: 3+ swap calls in single PTB', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'pool', function: 'swap_a2b' },
      { package: PKG, module: 'victim', function: 'swap_exact_input' },
      { package: PKG, module: 'pool', function: 'swap_b2a' },
    ]);
    const findings = detectSandwichAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.attackType).toBe('sandwich-attack');
    expect(findings[0]?.evidence['isIntraPtbSandwich']).toBe(true);
    expect(findings[0]?.evidence['swapCallCount']).toBe(3);
    expect(findings[0]?.riskHints?.severityFloor).toBe('critical');
    expect(findings[0]?.riskHints?.scoreDelta).toBe(40);
    expect(findings[0]?.chainHints?.stage).toBe('extraction');
  });

  it('fires for cross-TX variant: large swap + prior DEX alert from same sender', () => {
    const priorAlerts: AttackDetectorContext['runtime']['recentAlerts'] = [
      { ruleId: 'price-manipulation', details: { sender: ATTACKER } },
    ];
    const balanceChanges = [
      { owner: ATTACKER, coinType: SUI, amount: '20000000000' }, // +20 SUI (large gain)
      { owner: ATTACKER, coinType: USDC, amount: '-20000000' }, // -20 USDC
    ];
    const ctx = buildCtx(
      [{ package: PKG, module: 'pool', function: 'swap_exact_input' }],
      balanceChanges,
      priorAlerts,
    );
    const findings = detectSandwichAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['isCrossTxSandwich']).toBe(true);
    expect(findings[0]?.evidence['priorDexAlertCount']).toBe(1);
    expect(findings[0]?.riskHints?.severityFloor).toBe('high');
    expect(findings[0]?.riskHints?.scoreDelta).toBe(30);
  });

  it('does not fire for cross-TX when no prior alert despite large swap', () => {
    const balanceChanges = [
      { owner: ATTACKER, coinType: SUI, amount: '20000000000' },
    ];
    const ctx = buildCtx(
      [{ package: PKG, module: 'pool', function: 'swap' }],
      balanceChanges,
      [], // no prior alerts
    );
    expect(detectSandwichAttacks(ctx)).toHaveLength(0);
  });

  it('does not count prior alerts from different senders', () => {
    const OTHER = '0xcccc000000000000000000000000000000000000000000000000000000000000';
    const priorAlerts: AttackDetectorContext['runtime']['recentAlerts'] = [
      { ruleId: 'price-manipulation', details: { sender: OTHER } },
    ];
    const balanceChanges = [
      { owner: ATTACKER, coinType: SUI, amount: '20000000000' },
    ];
    const ctx = buildCtx(
      [{ package: PKG, module: 'pool', function: 'swap_a2b' }],
      balanceChanges,
      priorAlerts,
    );
    // Only 1 swap call, no prior alert from ATTACKER → should not fire
    expect(detectSandwichAttacks(ctx)).toHaveLength(0);
  });

  it('fires for intra-PTB with 4 swap calls (more aggressive sandwich)', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'dex', function: 'route_swap' },
      { package: PKG, module: 'dex', function: 'trade' },
      { package: PKG, module: 'dex', function: 'swap_a2b' },
      { package: PKG, module: 'dex', function: 'route_swap' },
    ]);
    const findings = detectSandwichAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['swapCallCount']).toBe(4);
  });

  it('includes affected functions in evidence', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'cetus', function: 'swap_a2b' },
      { package: PKG, module: 'deepbook', function: 'place_market_order' },
      { package: PKG, module: 'cetus', function: 'swap_b2a' },
    ]);
    const findings = detectSandwichAttacks(ctx);
    expect(findings[0]?.evidence['affectedFunctions']).toEqual(
      expect.arrayContaining(['cetus::swap_a2b', 'deepbook::place_market_order', 'cetus::swap_b2a']),
    );
  });
});
