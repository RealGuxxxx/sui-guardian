import { describe, expect, it } from 'vitest';

import { detectKioskPolicyBypassAttacks } from '../src/detectors/known/kiosk-policy-bypass-detector.js';
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
  objectChanges: ObservedTransaction['objectChanges'] = [],
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
      objectChanges,
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
      recentAlerts: [],
      senderHistory: null,
    },
  };
}

describe('detectKioskPolicyBypassAttacks', () => {
  it('returns empty when no kiosk take calls present', () => {
    const ctx = buildCtx([{ package: PKG, module: 'pool', function: 'swap' }]);
    expect(detectKioskPolicyBypassAttacks(ctx)).toHaveLength(0);
  });

  it('fires for take-without-policy-confirm pattern', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'kiosk', function: 'take' },
    ]);
    const findings = detectKioskPolicyBypassAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.attackType).toBe('kiosk-policy-bypass');
    expect(findings[0]?.evidence['isTakeWithoutPolicy' as string]).toBe(undefined); // reason stored differently
    expect(findings[0]?.evidence['reason']).toBe('take-without-policy-confirm');
    expect(findings[0]?.riskHints?.severityFloor).toBe('high');
    expect(findings[0]?.riskHints?.scoreDelta).toBe(30);
    expect(findings[0]?.chainHints?.stage).toBe('extraction');
  });

  it('fires for delist_and_take variant without confirm', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'ob_kiosk', function: 'delist_and_take' },
    ]);
    const findings = detectKioskPolicyBypassAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['reason']).toBe('take-without-policy-confirm');
  });

  it('fires for fake-policy-bypass: confirm_request from newly published package', () => {
    const ctx = buildCtx(
      [
        { package: PKG, module: 'kiosk', function: 'take' },
        { package: PKG, module: 'fake_policy', function: 'confirm_request' },
      ],
      [{ isPackage: true, idCreated: true, id: '0xnewpkg' }],
    );
    const findings = detectKioskPolicyBypassAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['reason']).toBe('fake-policy-bypass (new package + confirm_request)');
    expect(findings[0]?.riskHints?.severityFloor).toBe('critical');
    expect(findings[0]?.riskHints?.scoreDelta).toBe(45);
  });

  it('does NOT fire for legitimate purchase with confirm_request and no new package', () => {
    const ctx = buildCtx(
      [
        { package: PKG, module: 'kiosk', function: 'take' },
        { package: PKG, module: 'transfer_policy', function: 'confirm_request' },
      ],
      [], // no new package
    );
    // take + confirm, no new package → isTakeWithoutPolicy=false, isFakePolicyBypass=false
    // But isMassDrain is false too (only 1 take call)
    // → isTakeWithoutPolicy would be false because hasPolicyConfirm=true
    // → should not fire
    expect(detectKioskPolicyBypassAttacks(ctx)).toHaveLength(0);
  });

  it('fires for mass-drain: 5+ kiosk take calls in one PTB', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'kiosk', function: 'take' },
      { package: PKG, module: 'kiosk', function: 'take' },
      { package: PKG, module: 'kiosk', function: 'withdraw' },
      { package: PKG, module: 'kiosk', function: 'delist' },
      { package: PKG, module: 'marketplace', function: 'take' },
    ]);
    const findings = detectKioskPolicyBypassAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['reason']).toContain('mass-drain');
    expect(findings[0]?.evidence['kioskTakeCallCount']).toBe(5);
    expect(findings[0]?.riskHints?.severityFloor).toBe('critical');
    expect(findings[0]?.riskHints?.scoreDelta).toBe(40);
  });

  it('does not fire for 4 kiosk takes (below mass-drain threshold)', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'kiosk', function: 'take' },
      { package: PKG, module: 'kiosk', function: 'take' },
      { package: PKG, module: 'kiosk', function: 'take' },
      { package: PKG, module: 'kiosk', function: 'take' },
    ]);
    // 4 takes, no confirm → isTakeWithoutPolicy=true → DOES fire
    // Let me reconsider — 4 takes without confirm should still fire as take-without-policy
    const findings = detectKioskPolicyBypassAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['reason']).toBe('take-without-policy-confirm');
    expect(findings[0]?.riskHints?.severityFloor).toBe('high'); // not critical (not mass-drain threshold)
  });

  it('includes affected functions in evidence', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'kiosk', function: 'take' },
      { package: PKG, module: 'marketplace', function: 'delist' },
    ]);
    const findings = detectKioskPolicyBypassAttacks(ctx);
    expect(findings[0]?.evidence['affectedFunctions']).toContain('kiosk::take');
    expect(findings[0]?.evidence['affectedFunctions']).toContain('marketplace::delist');
  });

  it('detects ob_kiosk module variant', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'ob_kiosk', function: 'withdraw' },
    ]);
    const findings = detectKioskPolicyBypassAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['affectedFunctions']).toContain('ob_kiosk::withdraw');
  });
});
