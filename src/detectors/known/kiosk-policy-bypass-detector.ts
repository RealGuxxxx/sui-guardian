import type { AttackDetectorContext, AttackFinding } from '../types.js';

/**
 * Sui Kiosk / TransferPolicy Bypass Detector
 *
 * Sui's NFT marketplace uses a Kiosk + TransferPolicy system:
 * - Items are locked inside a Kiosk and can only be transferred if a
 *   TransferPolicy's rules are satisfied (e.g., pay royalty, check collection).
 * - `kiosk::take()` extracts an item WITHOUT satisfying policy — only valid for
 *   the kiosk owner on their OWN items.
 * - `kiosk::purchase()` is the LEGITIMATE path for buyers (must provide payment
 *   matching the listing price AND call `transfer_policy::confirm_request()`).
 *
 * Attack patterns:
 * 1. **Take without confirm**: `kiosk::take` or `kiosk::delist` called WITHOUT
 *    a corresponding `transfer_policy::confirm_request` in the same PTB.
 *    → Attacker extracts item while bypassing royalty/policy enforcement.
 *
 * 2. **Fake policy bypass**: custom TransferPolicy rule that always returns
 *    a completed `TransferRequest` without actually enforcing anything.
 *    Signal: `transfer_policy::confirm_request` call from a module whose
 *    package address was published very recently (same or recent checkpoint).
 *
 * 3. **Mass kiosk drain**: 5+ kiosk take/purchase calls from same sender in
 *    one PTB → automated sweep of a compromised kiosk collection.
 */

// Functions that extract items from Kiosks
const KIOSK_TAKE_PATTERNS = [
  'take',
  'delist',
  'delist_and_take',
  'withdraw',
];

// Functions that should accompany a legitimate purchase
const POLICY_CONFIRM_PATTERNS = [
  'confirm_request',
  'confirm_transfer',
];

// Threshold for "mass drain" pattern
const MASS_DRAIN_THRESHOLD = 5;

function isKioskTakeCall(mod: string, fn: string): boolean {
  const combined = `${mod}::${fn}`.toLowerCase();
  return (
    (combined.includes('kiosk') || combined.includes('marketplace') || combined.includes('ob_kiosk')) &&
    KIOSK_TAKE_PATTERNS.some((p) => fn.toLowerCase().includes(p))
  );
}

function isPolicyConfirmCall(fn: string): boolean {
  return POLICY_CONFIRM_PATTERNS.some((p) => fn.toLowerCase().includes(p));
}

export function detectKioskPolicyBypassAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const { tx } = ctx;

  const kioskTakeCalls = tx.calls.filter((c) => isKioskTakeCall(c.module, c.function));
  if (kioskTakeCalls.length === 0) return [];

  const hasPolicyConfirm = tx.calls.some((c) => isPolicyConfirmCall(c.function));
  const isMassDrain = kioskTakeCalls.length >= MASS_DRAIN_THRESHOLD;

  // Pattern 1: take without policy confirmation
  const isTakeWithoutPolicy = !hasPolicyConfirm;

  // Pattern 2: newly published package confirming policy (fresh bypass contract)
  const hasNewPackage = tx.objectChanges.some((o) => o.isPackage && o.idCreated);
  const isFakePolicyBypass = hasPolicyConfirm && hasNewPackage;

  if (!isTakeWithoutPolicy && !isMassDrain && !isFakePolicyBypass) return [];

  const reason = isMassDrain
    ? `mass-drain (${kioskTakeCalls.length} take calls)`
    : isFakePolicyBypass
      ? 'fake-policy-bypass (new package + confirm_request)'
      : 'take-without-policy-confirm';

  const affectedFunctions = kioskTakeCalls.map((c) => `${c.module}::${c.function}`);

  return [
    {
      attackType: 'kiosk-policy-bypass',
      category: 'execution-abuse',
      summary: `检测到 Kiosk TransferPolicy 绕过（${reason}）：${affectedFunctions[0]} 调用${hasPolicyConfirm ? '' : '缺少对应的 confirm_request'}，疑似未授权提取 NFT 资产`,
      evidence: {
        sender: tx.sender,
        kioskTakeCallCount: kioskTakeCalls.length,
        affectedFunctions,
        hasPolicyConfirm,
        isMassDrain,
        isFakePolicyBypass,
        hasNewPackage,
        reason,
      },
      riskHints: {
        scoreDelta: isMassDrain ? 40 : isFakePolicyBypass ? 45 : 30,
        severityFloor: isFakePolicyBypass || isMassDrain ? 'critical' : 'high',
      },
      chainHints: {
        stage: 'extraction',
      },
    },
  ];
}
