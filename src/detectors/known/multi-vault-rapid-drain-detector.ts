import type { AttackDetectorContext, AttackFinding } from '../types.js';

/**
 * Volo Protocol $3.5M exploit (April 21-22, 2026) — Admin Key Compromise / Multi-Vault Rapid Drain
 *
 * When an admin private key is compromised, the attacker has full access to ALL privileged
 * functions. The resulting attack pattern is distinctive:
 * - Same sender calls privileged withdrawal functions on MULTIPLE vaults within minutes
 * - The same address hits WBTC vault, XAUm vault, USDC vault — sequentially
 * - This is the attacker running a script to drain as many vaults as possible before detection
 *
 * Detection: cross-TX awareness via recentAlerts — if we see 3+ "protected address outflow"
 * alerts from the same sender in the recent window, flag as coordinated multi-vault drain.
 *
 * Also detects single-TX cases: one TX causing outflows from 3+ distinct protected addresses.
 */

// Minimum number of distinct vaults to consider a "multi-vault" drain
const MULTI_VAULT_THRESHOLD = 3;
// Minimum USD-equivalent outflow per vault (in MIST, 1B MIST ≈ 1 SUI ≈ ~$5)
const MIN_OUTFLOW_PER_VAULT = BigInt(100_000_000); // 0.1 SUI equivalent

// Rule IDs that indicate a prior protected-address outflow from the same sender
const OUTFLOW_RULE_PATTERNS = [
  'behavior:unauthorized-sensitive',
  'address-outflow:',
  'multi-vault-rapid-drain',
  'attack:liquidity-drain',
];

function isOutflowAlert(ruleId: string): boolean {
  return OUTFLOW_RULE_PATTERNS.some((pattern) => ruleId.includes(pattern));
}

export function detectMultiVaultRapidDrainAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const { tx, derived, project, runtime } = ctx;
  const protectedAddresses = project.protectedAddresses;

  if (protectedAddresses.length < MULTI_VAULT_THRESHOLD) {
    // Protocol doesn't have enough configured vaults to match the pattern
    return [];
  }

  // ── Single-TX pattern: one TX drains 3+ distinct protected addresses ──────

  const drainedVaultsInTx = new Map<string, bigint>(); // address → total outflow

  for (const change of tx.balanceChanges) {
    if (!change.owner) continue;
    const ownerLower = change.owner.toLowerCase();
    const isProtected = protectedAddresses.some(
      (addr) => addr.address.toLowerCase() === ownerLower,
    );
    if (!isProtected) continue;

    const amount = BigInt(change.amount ?? '0');
    if (amount >= 0n) continue; // Only outflows

    const existing = drainedVaultsInTx.get(ownerLower) ?? 0n;
    drainedVaultsInTx.set(ownerLower, existing + amount); // sum negatives
  }

  // Filter to only vaults with meaningful outflow
  const significantDrains = [...drainedVaultsInTx.entries()].filter(
    ([, outflow]) => outflow <= -MIN_OUTFLOW_PER_VAULT, // outflow is negative
  );

  const singleTxMultiVault = significantDrains.length >= MULTI_VAULT_THRESHOLD;

  // ── Cross-TX pattern: same sender drained vaults in prior TXs too ─────────

  const sender = tx.sender;
  const priorOutflowAlertsFromSender = sender
    ? runtime.recentAlerts.filter((alert) => {
        const alertSender = alert.details['sender'] as string | undefined;
        return alertSender?.toLowerCase() === sender.toLowerCase() && isOutflowAlert(alert.ruleId);
      })
    : [];

  const crossTxMultiVault = priorOutflowAlertsFromSender.length >= 2 && significantDrains.length >= 1;

  if (!singleTxMultiVault && !crossTxMultiVault) return [];

  // Check also for admin/sensitive function calls (admin key compromise signature)
  const hasAdminCall = tx.calls.some((call) => {
    const fn = call.function.toLowerCase();
    return /withdraw|drain|emergency|admin|migrate|set_admin|transfer_all/.test(fn);
  });

  const totalOutflowMist = significantDrains.reduce((sum, [, v]) => sum + v, 0n);
  const priorVaultCount = priorOutflowAlertsFromSender.length;

  return [
    {
      attackType: 'multi-vault-rapid-drain',
      category: 'liquidity-drain',
      summary: singleTxMultiVault
        ? `检测到单笔交易抽空 ${significantDrains.length} 个受保护地址（Volo 管理员密钥泄露模式），总流出 ${(Number(-totalOutflowMist) / 1e9).toFixed(2)} SUI 等值`
        : `检测到跨交易多 Vault 快速抽空：该发送者此前已有 ${priorVaultCount} 条受保护地址流出告警，疑似管理员密钥泄露后的自动化提款脚本`,
      evidence: {
        sender,
        drainedVaultsCount: significantDrains.length,
        drainedVaults: significantDrains.map(([addr, outflow]) => ({
          address: addr,
          outflowMist: String(-outflow),
        })),
        priorVaultDrainAlerts: priorVaultCount,
        hasAdminCall,
        isSingleTxMultiVault: singleTxMultiVault,
        isCrossTxMultiVault: crossTxMultiVault,
        totalOutflowMist: String(-totalOutflowMist),
        netAttackerGain: derived.flowEvidence?.netAttackerGain ?? '0',
      },
      riskHints: {
        scoreDelta: singleTxMultiVault ? 50 : 40,
        severityFloor: 'critical',
      },
      chainHints: {
        stage: 'extraction',
      },
    },
  ];
}
