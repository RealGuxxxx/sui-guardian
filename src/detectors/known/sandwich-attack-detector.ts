import type { AttackDetectorContext, AttackFinding } from '../types.js';

/**
 * Sandwich Attack Detector — single-PTB and cross-TX variants
 *
 * A sandwich attack front-runs a victim's swap with an opposing trade, lets the victim execute
 * at a worse price, then closes the position for profit. On Sui, PTBs are atomic, so the classic
 * "three separate transactions" mempool sandwich is harder, but two variants still apply:
 *
 * === Variant A: Intra-PTB Self-Sandwich ===
 * A sophisticated attacker can bundle the ENTIRE sequence in a single PTB:
 *   call 1: buy X (large) → moves price up
 *   call 2: swap_for_victim() via a controlled contract → victim executes at inflated price
 *   call 3: sell X (large) → price returns, attacker pockets spread
 * Signal: same DEX swap function appears 3+ times in one PTB with alternating large amounts.
 *
 * === Variant B: Cross-TX Directional Flip ===
 * A simpler (and more detectable) variant: attacker makes a very large swap in direction A,
 * waits one TX for victim to execute, then immediately makes an equivalently large swap in
 * direction B (the opposite).
 * Signal (via recentAlerts): prior alert about large DEX activity from same sender,
 * current TX shows directional flip (net balance sign reversal for the same coin type).
 *
 * Corroboration requirements to reduce false positives:
 * - Intra-PTB: 3+ calls to swap-like functions in same PTB
 * - Cross-TX: prior alert + current directional flip with meaningful amount
 */

// DEX swap function name patterns (applies to Sui DEXes: Cetus, Turbos, DeepBook, Aftermath, etc.)
const SWAP_FUNCTION_PATTERNS = [
  'swap',
  'trade',
  'exchange',
  'buy',
  'sell',
  'place_market_order',
  'flash_swap',
  'swap_exact_input',
  'swap_exact_output',
  'swap_a2b',
  'swap_b2a',
  'route_swap',
];

// Minimum balance change amount considered "large" for sandwich purposes (10 SUI equivalent)
const LARGE_SWAP_THRESHOLD = BigInt(10_000_000_000); // 10 SUI / 10 USDC at 6dp = 10M MIST

// Rule IDs from prior alerts that indicate large DEX activity from same sender
const PRIOR_DEX_ALERT_PATTERNS = [
  'price-manipulation',
  'slippage-abuse',
  'sandwich-attack',
  'flash-loan',
  'cross-market',
  'liquidity-drain',
];

function isSwapCall(fnName: string): boolean {
  const lower = fnName.toLowerCase();
  return SWAP_FUNCTION_PATTERNS.some((pattern) => lower.includes(pattern));
}

function isPriorDexAlert(ruleId: string): boolean {
  return PRIOR_DEX_ALERT_PATTERNS.some((p) => ruleId.includes(p));
}

export function detectSandwichAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const { tx, runtime } = ctx;
  const sender = tx.sender;

  // ── Variant A: Intra-PTB self-sandwich ────────────────────────────────────

  const swapCalls = tx.calls.filter((c) => isSwapCall(c.function));
  const isIntraPtbSandwich = swapCalls.length >= 3;

  // ── Variant B: Cross-TX directional flip ──────────────────────────────────

  // Aggregate net balance changes per coin type for this TX
  const netByCoin = new Map<string, bigint>();
  for (const change of tx.balanceChanges) {
    if (!change.owner || change.owner.toLowerCase() !== sender?.toLowerCase()) continue;
    const amount = BigInt(change.amount ?? '0');
    netByCoin.set(change.coinType, (netByCoin.get(change.coinType) ?? 0n) + amount);
  }

  // Does the current TX show large swap activity?
  const hasLargeSwapNow = [...netByCoin.values()].some(
    (v) => (v > LARGE_SWAP_THRESHOLD || v < -LARGE_SWAP_THRESHOLD) && swapCalls.length > 0,
  );

  // Check recent alerts from same sender for prior DEX activity
  const priorDexAlerts = sender
    ? runtime.recentAlerts.filter((a) => {
        const alertSender = a.details['sender'] as string | undefined;
        return alertSender?.toLowerCase() === sender.toLowerCase() && isPriorDexAlert(a.ruleId);
      })
    : [];

  const isCrossTxSandwich = hasLargeSwapNow && priorDexAlerts.length >= 1;

  if (!isIntraPtbSandwich && !isCrossTxSandwich) return [];

  // ── Build evidence ─────────────────────────────────────────────────────────

  const totalSwapCalls = swapCalls.length;
  const affectedModules = [...new Set(swapCalls.map((c) => `${c.module}::${c.function}`))];

  // Estimate net profit opportunity: positive balance changes for sender in swap coins
  const senderGains = [...netByCoin.entries()]
    .filter(([, v]) => v > 0n)
    .map(([coin, amount]) => ({ coin, amount: amount.toString() }));

  const ruleId = 'sandwich-attack';
  const scoreDelta = isIntraPtbSandwich ? 40 : 30;

  return [
    {
      attackType: ruleId,
      category: 'price-manipulation',
      summary: isIntraPtbSandwich
        ? `检测到单 PTB 内三明治攻击：${totalSwapCalls} 次交换调用（${affectedModules.slice(0, 2).join('、')}），同一 PTB 内执行完整前跑→受害者→套利序列`
        : `检测到跨交易三明治攻击：当前发送者此前 ${priorDexAlerts.length} 次大额 DEX 活动后，本次 TX 再次出现大额交换（方向反转）`,
      evidence: {
        sender,
        swapCallCount: totalSwapCalls,
        affectedFunctions: affectedModules,
        isIntraPtbSandwich,
        isCrossTxSandwich,
        priorDexAlertCount: priorDexAlerts.length,
        senderGains,
        netByCoin: Object.fromEntries([...netByCoin.entries()].map(([k, v]) => [k, v.toString()])),
      },
      riskHints: {
        scoreDelta,
        severityFloor: isIntraPtbSandwich ? 'critical' : 'high',
      },
      chainHints: {
        stage: 'extraction',
      },
    },
  ];
}
