import { describe, expect, it } from 'vitest';

import { detectMultiVaultRapidDrainAttacks } from '../src/detectors/known/multi-vault-rapid-drain-detector.js';
import type { AttackDetectorContext } from '../src/detectors/types.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PKG = '0x1111111111111111111111111111111111111111111111111111111111111111';
const VAULT_A = '0xaaaa000000000000000000000000000000000000000000000000000000000001';
const VAULT_B = '0xaaaa000000000000000000000000000000000000000000000000000000000002';
const VAULT_C = '0xaaaa000000000000000000000000000000000000000000000000000000000003';
const VAULT_D = '0xaaaa000000000000000000000000000000000000000000000000000000000004';
const ATTACKER = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

// Helper to create a meaningful balance change (outflow from a vault)
function outflow(vaultAddress: string, amountMist: bigint) {
  return {
    owner: vaultAddress,
    coinType: '0x2::sui::SUI',
    amount: (-amountMist).toString(),
  };
}

function inflow(toAddress: string, amountMist: bigint) {
  return {
    owner: toAddress,
    coinType: '0x2::sui::SUI',
    amount: amountMist.toString(),
  };
}

function buildProject(vaultCount: number): MonitoringProjectConfig {
  const vaults = [VAULT_A, VAULT_B, VAULT_C, VAULT_D].slice(0, vaultCount);
  return {
    id: 'test',
    name: 'Test',
    packages: [{ address: PKG, allowedUpgradeSenders: [] }],
    protectedAddresses: vaults.map((addr, i) => ({
      label: `vault-${i}`,
      address: addr,
      allowedSenders: [],
    })),
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
  balanceChanges: ObservedTransaction['balanceChanges'],
  vaultCount: number,
  recentAlerts: AttackDetectorContext['runtime']['recentAlerts'] = [],
  calls: ObservedTransaction['calls'] = [],
): AttackDetectorContext {
  return {
    project: buildProject(vaultCount),
    tx: {
      digest: 'tx-test',
      checkpoint: 100,
      timestamp: '2026-04-22T10:00:00.000Z',
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
      flowEvidence: { nodes: [], netAttackerGain: '1000000000' },
      risk: { score: 0, recommendedSeverity: 'info' },
      evidenceSummary: { categories: [], totalWeight: 0 },
    },
    runtime: {
      recentAlerts,
      senderHistory: null,
    },
  };
}

describe('detectMultiVaultRapidDrainAttacks', () => {
  it('does not fire when protocol has fewer than 3 protected addresses', () => {
    const changes = [
      outflow(VAULT_A, 200_000_000n),
      outflow(VAULT_B, 200_000_000n),
    ];
    // Only 2 vaults configured
    const ctx = buildCtx(changes, 2);
    expect(detectMultiVaultRapidDrainAttacks(ctx)).toHaveLength(0);
  });

  it('does not fire when only 2 vaults drained in single TX (below threshold)', () => {
    const changes = [
      outflow(VAULT_A, 500_000_000n),
      outflow(VAULT_B, 500_000_000n),
    ];
    const ctx = buildCtx(changes, 3);
    expect(detectMultiVaultRapidDrainAttacks(ctx)).toHaveLength(0);
  });

  it('fires for single-TX drain of 3+ protected addresses', () => {
    const changes = [
      outflow(VAULT_A, 500_000_000n), // 0.5 SUI
      outflow(VAULT_B, 300_000_000n), // 0.3 SUI
      outflow(VAULT_C, 200_000_000n), // 0.2 SUI
      inflow(ATTACKER, 1_000_000_000n),
    ];
    const ctx = buildCtx(changes, 3);
    const findings = detectMultiVaultRapidDrainAttacks(ctx);
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.attackType).toBe('multi-vault-rapid-drain');
    expect(f.category).toBe('liquidity-drain');
    expect(f.evidence['isSingleTxMultiVault']).toBe(true);
    expect(f.evidence['drainedVaultsCount']).toBe(3);
    expect(f.riskHints?.severityFloor).toBe('critical');
    expect(f.riskHints?.scoreDelta).toBe(50);
  });

  it('ignores small outflows below MIN_OUTFLOW_PER_VAULT threshold', () => {
    const changes = [
      outflow(VAULT_A, 50_000_000n),  // 0.05 SUI — below 0.1 SUI threshold
      outflow(VAULT_B, 50_000_000n),
      outflow(VAULT_C, 200_000_000n), // only this one is above threshold
    ];
    const ctx = buildCtx(changes, 3);
    expect(detectMultiVaultRapidDrainAttacks(ctx)).toHaveLength(0);
  });

  it('fires for cross-TX pattern: 2+ prior outflow alerts + current drain', () => {
    const priorAlerts: AttackDetectorContext['runtime']['recentAlerts'] = [
      { ruleId: 'attack:liquidity-drain', details: { sender: ATTACKER } },
      { ruleId: 'address-outflow:vault-a', details: { sender: ATTACKER } },
    ];
    const changes = [
      outflow(VAULT_C, 200_000_000n), // current TX drains one more vault
    ];
    // Need 3+ configured vaults
    const ctx = buildCtx(changes, 3, priorAlerts);
    const findings = detectMultiVaultRapidDrainAttacks(ctx);
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.evidence['isCrossTxMultiVault']).toBe(true);
    expect(f.evidence['priorVaultDrainAlerts']).toBe(2);
    expect(f.riskHints?.scoreDelta).toBe(40);
  });

  it('does not count prior alerts from different senders', () => {
    const OTHER_ATTACKER = '0xcccc000000000000000000000000000000000000000000000000000000000000';
    const priorAlerts: AttackDetectorContext['runtime']['recentAlerts'] = [
      { ruleId: 'attack:liquidity-drain', details: { sender: OTHER_ATTACKER } },
      { ruleId: 'address-outflow:vault-a', details: { sender: OTHER_ATTACKER } },
    ];
    const changes = [
      outflow(VAULT_C, 200_000_000n),
    ];
    const ctx = buildCtx(changes, 3, priorAlerts);
    expect(detectMultiVaultRapidDrainAttacks(ctx)).toHaveLength(0);
  });

  it('detects admin function calls and marks hasAdminCall in evidence', () => {
    const changes = [
      outflow(VAULT_A, 500_000_000n),
      outflow(VAULT_B, 500_000_000n),
      outflow(VAULT_C, 500_000_000n),
    ];
    const adminCalls = [
      { package: PKG, module: 'vault', function: 'emergency_withdraw' },
    ];
    const ctx = buildCtx(changes, 3, [], adminCalls);
    const findings = detectMultiVaultRapidDrainAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['hasAdminCall']).toBe(true);
  });

  it('handles balance changes with undefined owner gracefully', () => {
    const changes = [
      { owner: undefined, coinType: '0x2::sui::SUI', amount: '-500000000' },
      outflow(VAULT_A, 500_000_000n),
      outflow(VAULT_B, 500_000_000n),
      outflow(VAULT_C, 500_000_000n),
    ];
    const ctx = buildCtx(changes as ObservedTransaction['balanceChanges'], 3);
    const findings = detectMultiVaultRapidDrainAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['drainedVaultsCount']).toBe(3);
  });
});
