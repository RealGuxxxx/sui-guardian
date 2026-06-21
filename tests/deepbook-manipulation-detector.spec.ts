import { describe, expect, it } from 'vitest';

import { detectDeepBookManipulationAttacks } from '../src/detectors/known/deepbook-manipulation-detector.js';
import type { AttackDetectorContext } from '../src/detectors/types.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PKG = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ATTACKER = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

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
  flashLikeFundingDetected = false,
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
      balanceChanges: [],
      objectChanges: [],
    },
    derived: {
      flashLikeFundingDetected,
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
      recentAlerts: [],
      senderHistory: null,
    },
  };
}

function deepbookPlaceCall(fn = 'place_limit_order') {
  return { package: PKG, module: 'deepbook', function: fn };
}
function deepbookCancelCall(fn = 'cancel_order') {
  return { package: PKG, module: 'deepbook', function: fn };
}

describe('detectDeepBookManipulationAttacks', () => {
  it('returns empty when no DeepBook order calls', () => {
    const ctx = buildCtx([{ package: PKG, module: 'pool', function: 'swap' }]);
    expect(detectDeepBookManipulationAttacks(ctx)).toHaveLength(0);
  });

  it('returns empty for a single place order (below all thresholds)', () => {
    const ctx = buildCtx([deepbookPlaceCall()]);
    expect(detectDeepBookManipulationAttacks(ctx)).toHaveLength(0);
  });

  it('fires for wash-trading: 5+ place_limit_order calls', () => {
    const ctx = buildCtx([
      deepbookPlaceCall(), deepbookPlaceCall(), deepbookPlaceCall(),
      deepbookPlaceCall(), deepbookPlaceCall(),
    ]);
    const findings = detectDeepBookManipulationAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.attackType).toBe('deepbook-manipulation');
    expect(findings[0]?.evidence['isWashTrading']).toBe(true);
    expect(findings[0]?.evidence['placeOrderCount']).toBe(5);
    expect(findings[0]?.riskHints?.scoreDelta).toBe(30);
  });

  it('fires for quote-stuffing: 8+ total order ops (place + cancel)', () => {
    const ctx = buildCtx([
      deepbookPlaceCall(), deepbookPlaceCall(), deepbookPlaceCall(),
      deepbookPlaceCall(), deepbookPlaceCall(),
      deepbookCancelCall(), deepbookCancelCall(), deepbookCancelCall(),
    ]);
    const findings = detectDeepBookManipulationAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['isQuoteStuffing']).toBe(true);
    expect(findings[0]?.evidence['totalOrderOps']).toBe(8);
    expect(findings[0]?.riskHints?.scoreDelta).toBe(35);
    expect(findings[0]?.riskHints?.severityFloor).toBe('high');
  });

  it('fires for layering: 2+ place + 1+ cancel, total >= 5', () => {
    const ctx = buildCtx([
      deepbookPlaceCall(), deepbookPlaceCall(), deepbookPlaceCall(),
      deepbookCancelCall(), deepbookCancelCall(),
    ]);
    const findings = detectDeepBookManipulationAttacks(ctx);
    // 3 place + 2 cancel = 5 total. isWashTrading: 3>=5? No. isQuoteStuffing: 5>=8? No. isLayering: Yes.
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['isLayering']).toBe(true);
    expect(findings[0]?.riskHints?.scoreDelta).toBe(25);
  });

  it('fires for flash-order-drain: flashLikeFunding + market order', () => {
    const ctx = buildCtx(
      [{ package: PKG, module: 'deepbook', function: 'place_market_order' }],
      true, // flashLikeFundingDetected
    );
    const findings = detectDeepBookManipulationAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['isFlashOrderDrain']).toBe(true);
    expect(findings[0]?.riskHints?.scoreDelta).toBe(40);
    expect(findings[0]?.chainHints?.stage).toBe('extraction');
  });

  it('does NOT fire for flash funding without market order', () => {
    const ctx = buildCtx(
      [deepbookPlaceCall('place_limit_order')], // limit, not market
      true,
    );
    // 1 place limit, no cancel, flashFunding+limit but no market → no flash drain
    // Also 1 place < 5 wash threshold, 1 < 8 quote stuff, 0 cancel → no layering
    expect(detectDeepBookManipulationAttacks(ctx)).toHaveLength(0);
  });

  it('detects clob module variant', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'clob', function: 'place_limit_order' },
      { package: PKG, module: 'clob', function: 'place_limit_order' },
      { package: PKG, module: 'clob', function: 'place_limit_order' },
      { package: PKG, module: 'clob', function: 'place_limit_order' },
      { package: PKG, module: 'clob', function: 'place_limit_order' },
    ]);
    const findings = detectDeepBookManipulationAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['isWashTrading']).toBe(true);
  });

  it('includes place/cancel counts and function names in evidence', () => {
    const ctx = buildCtx([
      deepbookPlaceCall(), deepbookPlaceCall(), deepbookPlaceCall(),
      deepbookPlaceCall(), deepbookPlaceCall(),
      deepbookCancelCall(),
    ]);
    const findings = detectDeepBookManipulationAttacks(ctx);
    expect(findings[0]?.evidence['placeOrderCount']).toBe(5);
    expect(findings[0]?.evidence['cancelOrderCount']).toBe(1);
    expect(findings[0]?.evidence['placeOrderFunctions']).toContain('deepbook::place_limit_order');
  });

  it('flash-order-drain has highest score priority over other signals', () => {
    // 5 place + flash = both wash-trading AND flash-drain → flash wins
    const ctx = buildCtx(
      [
        deepbookPlaceCall('place_market_order'),
        deepbookPlaceCall(), deepbookPlaceCall(), deepbookPlaceCall(), deepbookPlaceCall(),
      ],
      true,
    );
    const findings = detectDeepBookManipulationAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['isFlashOrderDrain']).toBe(true);
    expect(findings[0]?.riskHints?.scoreDelta).toBe(40); // flash wins
    expect(findings[0]?.chainHints?.stage).toBe('extraction');
  });
});
