import { describe, expect, it } from 'vitest';

import { detectDynamicFieldAbuseAttacks } from '../src/detectors/known/dynamic-field-abuse-detector.js';
import type { AttackDetectorContext } from '../src/detectors/types.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PKG = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ATTACKER = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

function buildProject(): MonitoringProjectConfig {
  return {
    id: 'test', name: 'Test',
    packages: [{ address: PKG, allowedUpgradeSenders: [] }],
    protectedAddresses: [], functionGuards: [], trafficSpikes: [], failureSpikes: [],
    trackedObjects: [], suspiciousTargets: [],
    behaviorRules: { enabled: false, minRepeatedCalls: 2, minProtectedOutflow: '100', priceDeviationThresholdBps: 500 },
    priceModels: [], objectBaselines: [],
    flowTracking: { enabled: false, minProtectedOutflow: '100', attackerGainThreshold: '100', shortWindowTxCount: 2 },
    suppression: { enabled: false, duplicateWindowSeconds: 600, weakSignalScoreThreshold: 35, maintenanceWindows: [] },
  };
}

function buildCtx(
  calls: ObservedTransaction['calls'],
  balanceChanges: ObservedTransaction['balanceChanges'] = [],
  valueExtractionDetected = false,
): AttackDetectorContext {
  return {
    project: buildProject(),
    tx: {
      digest: 'tx-test', checkpoint: 100, timestamp: '2026-05-05T10:00:00.000Z',
      sender: ATTACKER, status: 'SUCCESS', calls, balanceChanges, objectChanges: [],
    },
    derived: {
      flashLikeFundingDetected: false, valueExtractionDetected,
      suspiciousTargets: [], sameSensitiveCallRepeats: {},
      priceEvidence: [], baselineEvidence: [],
      flowEvidence: { nodes: [] },
      risk: { score: 0, recommendedSeverity: 'info' },
      evidenceSummary: { categories: [], totalWeight: 0 },
    },
    runtime: { recentAlerts: [], senderHistory: null },
  };
}

const SUI = '0x2::sui::SUI';

describe('detectDynamicFieldAbuseAttacks', () => {
  it('returns empty when no dynamic field calls', () => {
    const ctx = buildCtx([{ package: PKG, module: 'pool', function: 'swap' }]);
    expect(detectDynamicFieldAbuseAttacks(ctx)).toHaveLength(0);
  });

  it('fires for unauthorized mutation: borrow_mut + valueExtractionDetected', () => {
    const ctx = buildCtx(
      [{ package: PKG, module: 'dynamic_field', function: 'borrow_mut' }],
      [],
      true, // valueExtractionDetected
    );
    const findings = detectDynamicFieldAbuseAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.attackType).toBe('dynamic-field-abuse');
    expect(findings[0]?.evidence['isUnauthorizedMutation']).toBe(true);
    expect(findings[0]?.riskHints?.scoreDelta).toBe(40);
    expect(findings[0]?.riskHints?.severityFloor).toBe('high');
    expect(findings[0]?.chainHints?.stage).toBe('extraction');
  });

  it('fires for dynamic drain: 2+ removes + outflow', () => {
    const ctx = buildCtx(
      [
        { package: PKG, module: 'dynamic_field', function: 'remove' },
        { package: PKG, module: 'dynamic_object_field', function: 'remove' },
      ],
      [{ owner: ATTACKER, coinType: SUI, amount: '-5000000000' }],
    );
    const findings = detectDynamicFieldAbuseAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['isDynamicDrain']).toBe(true);
    expect(findings[0]?.riskHints?.scoreDelta).toBe(35);
    expect(findings[0]?.chainHints?.stage).toBe('extraction');
  });

  it('does NOT fire for single remove without outflow', () => {
    const ctx = buildCtx(
      [{ package: PKG, module: 'dynamic_field', function: 'remove' }],
      [],
    );
    expect(detectDynamicFieldAbuseAttacks(ctx)).toHaveLength(0);
  });

  it('fires for mass manipulation: 5+ dynamic field ops', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'dynamic_field', function: 'add' },
      { package: PKG, module: 'dynamic_field', function: 'add' },
      { package: PKG, module: 'dynamic_field', function: 'remove' },
      { package: PKG, module: 'dynamic_object_field', function: 'add' },
      { package: PKG, module: 'dynamic_field', function: 'borrow_mut' },
    ]);
    const findings = detectDynamicFieldAbuseAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['isMassManipulation']).toBe(true);
    expect(findings[0]?.evidence['totalDfOps']).toBe(5);
    expect(findings[0]?.riskHints?.scoreDelta).toBe(30);
  });

  it('does NOT fire for 4 df ops (below mass threshold)', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'dynamic_field', function: 'add' },
      { package: PKG, module: 'dynamic_field', function: 'add' },
      { package: PKG, module: 'dynamic_field', function: 'add' },
      { package: PKG, module: 'dynamic_field', function: 'add' },
    ]);
    expect(detectDynamicFieldAbuseAttacks(ctx)).toHaveLength(0);
  });

  it('fires for field key collision: add + borrow_mut + privileged call', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'dynamic_field', function: 'add' },
      { package: PKG, module: 'dynamic_field', function: 'borrow_mut' },
      { package: PKG, module: 'vault', function: 'withdraw' },
    ]);
    const findings = detectDynamicFieldAbuseAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['isKeyCollision']).toBe(true);
  });

  it('detects df alias module names (dof)', () => {
    const ctx = buildCtx(
      [
        { package: PKG, module: 'dof', function: 'remove' },
        { package: PKG, module: 'dof', function: 'remove' },
      ],
      [{ owner: ATTACKER, coinType: SUI, amount: '-1000000000' }],
    );
    const findings = detectDynamicFieldAbuseAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['isDynamicDrain']).toBe(true);
  });

  it('includes affected modules in evidence', () => {
    const ctx = buildCtx(
      [
        { package: PKG, module: 'dynamic_field', function: 'borrow_mut' },
        { package: PKG, module: 'dynamic_object_field', function: 'remove' },
        { package: PKG, module: 'dynamic_object_field', function: 'remove' },
      ],
      [{ owner: ATTACKER, coinType: SUI, amount: '-2000000000' }],
      true,
    );
    const findings = detectDynamicFieldAbuseAttacks(ctx);
    expect(findings[0]?.evidence['affectedModules']).toContain('dynamic_field');
    expect(findings[0]?.evidence['affectedModules']).toContain('dynamic_object_field');
  });

  it('stage is manipulation for key-collision without direct extraction', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'dynamic_field', function: 'add' },
      { package: PKG, module: 'dynamic_field', function: 'borrow_mut' },
      { package: PKG, module: 'config', function: 'set_fee' },
    ]);
    const findings = detectDynamicFieldAbuseAttacks(ctx);
    expect(findings[0]?.chainHints?.stage).toBe('manipulation');
  });
});
