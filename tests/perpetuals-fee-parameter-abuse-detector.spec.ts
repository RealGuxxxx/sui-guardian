import { describe, expect, it } from 'vitest';

import { detectPerpetualsFeeParameterAbuseAttacks } from '../src/detectors/known/perpetuals-fee-parameter-abuse-detector.js';
import type { AttackDetectorContext } from '../src/detectors/types.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PKG = '0x1111111111111111111111111111111111111111111111111111111111111111';
const VAULT = '0xaaaa000000000000000000000000000000000000000000000000000000000000';
const ATTACKER = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

function buildProject(): MonitoringProjectConfig {
  return {
    id: 'test',
    name: 'Test',
    packages: [{ address: PKG, allowedUpgradeSenders: [] }],
    protectedAddresses: [{ label: 'vault', address: VAULT, allowedSenders: [] }],
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

function buildTx(calls: ObservedTransaction['calls'], extraOverrides: Partial<ObservedTransaction> = {}): ObservedTransaction {
  return {
    digest: 'tx-test',
    checkpoint: 100,
    timestamp: '2026-04-29T10:00:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls,
    balanceChanges: [],
    objectChanges: [],
    ...extraOverrides,
  };
}

function buildCtx(
  tx: ObservedTransaction,
  derivedOverrides: Partial<AttackDetectorContext['derived']> = {},
): AttackDetectorContext {
  return {
    project: buildProject(),
    tx,
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
      ...derivedOverrides,
    },
    runtime: {
      recentAlerts: [],
      senderHistory: null,
    },
  };
}

describe('detectPerpetualsFeeParameterAbuseAttacks', () => {
  it('does not fire when no fee-setting call is present', () => {
    const tx = buildTx([{ package: PKG, module: 'perp', function: 'open_position' }]);
    const ctx = buildCtx(tx, { valueExtractionDetected: true });
    expect(detectPerpetualsFeeParameterAbuseAttacks(ctx)).toHaveLength(0);
  });

  it('does not fire when fee call present but no corroborating signal', () => {
    const tx = buildTx([
      { package: PKG, module: 'perp', function: 'set_taker_fee', pureInputs: ['100000'] },
    ]);
    const ctx = buildCtx(tx); // no extraction, no flash, no outflow
    expect(detectPerpetualsFeeParameterAbuseAttacks(ctx)).toHaveLength(0);
  });

  it('fires when fee-setting call + value extraction detected', () => {
    const tx = buildTx([
      { package: PKG, module: 'integrator', function: 'set_taker_fee', pureInputs: ['50000'] },
    ]);
    const ctx = buildCtx(tx, { valueExtractionDetected: true });
    const findings = detectPerpetualsFeeParameterAbuseAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.attackType).toBe('perpetuals-fee-parameter-abuse');
    expect(findings[0]?.category).toBe('execution-abuse');
  });

  it('fires when fee-setting call + flash-like funding detected', () => {
    const tx = buildTx([
      { package: PKG, module: 'fee', function: 'update_fee_rate', pureInputs: ['200000'] },
    ]);
    const ctx = buildCtx(tx, { flashLikeFundingDetected: true });
    const findings = detectPerpetualsFeeParameterAbuseAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.riskHints?.severityFloor).toBe('critical'); // 200000 > 10000 threshold
    expect(findings[0]?.riskHints?.scoreDelta).toBe(45);
  });

  it('fires when fee-setting call + large protected address outflow', () => {
    const tx = buildTx([
      { package: PKG, module: 'perp', function: 'set_integrator_fee', pureInputs: ['500'] },
    ]);
    const ctx = buildCtx(tx, {
      flowEvidence: {
        nodes: [],
        netProtectedOutflow: '-2000000', // 2M MIST outflow
      },
    });
    const findings = detectPerpetualsFeeParameterAbuseAttacks(ctx);
    expect(findings).toHaveLength(1);
    // 500 bps < 10000 threshold → high severity
    expect(findings[0]?.riskHints?.severityFloor).toBe('high');
    expect(findings[0]?.riskHints?.scoreDelta).toBe(30);
  });

  it('detects extreme fee value (Aftermath pattern: -100,000 bps as large u64)', () => {
    // In Aftermath, -100,000 bps is stored as u64 underflow (a very large number)
    const extremeVal = (2n ** 64n - 100_000n).toString(); // u64 underflow representation
    const tx = buildTx([
      { package: PKG, module: 'integrator', function: 'register_and_set_fee', pureInputs: [extremeVal] },
    ]);
    const ctx = buildCtx(tx, { valueExtractionDetected: true });
    const findings = detectPerpetualsFeeParameterAbuseAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['hasExtremeFeeValue']).toBe(true);
    expect(findings[0]?.riskHints?.severityFloor).toBe('critical');
  });

  it('includes affected functions in evidence', () => {
    const tx = buildTx([
      { package: PKG, module: 'perp', function: 'set_fee_bps', pureInputs: ['50000'] },
    ]);
    const ctx = buildCtx(tx, { flashLikeFundingDetected: true });
    const findings = detectPerpetualsFeeParameterAbuseAttacks(ctx);
    expect(findings[0]?.evidence['feeSettingFunctions']).toContain('perp::set_fee_bps');
  });

  it('handles mixed calls — only matches fee-related ones', () => {
    const tx = buildTx([
      { package: PKG, module: 'pool', function: 'swap' },
      { package: PKG, module: 'fee', function: 'configure_fee', pureInputs: ['99999'] },
      { package: PKG, module: 'usdc', function: 'withdraw' },
    ]);
    const ctx = buildCtx(tx, { valueExtractionDetected: true });
    const findings = detectPerpetualsFeeParameterAbuseAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['feeSettingFunctions']).toEqual(['fee::configure_fee']);
  });
});
