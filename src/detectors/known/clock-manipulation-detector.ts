import type { AttackDetectorContext, AttackFinding } from '../types.js';

/**
 * Sui Clock Manipulation / Time-Lock Bypass Detector
 *
 * Sui uses the `sui::clock::Clock` shared object (ID 0x6) to provide
 * on-chain timestamps. Many protocols implement time-locks, vesting
 * schedules, and TWAP windows using `clock::timestamp_ms`.
 *
 * Attack patterns:
 *
 * 1. **Time-Lock Bypass via Rapid Claim** — Calling unlock/vest/redeem
 *    functions multiple times in a single PTB. Since `Clock` is read-only
 *    in a PTB (shared, immutable ref), all calls see the same timestamp,
 *    allowing an attacker to bypass "once per epoch" or "once per interval"
 *    guards that rely on stored timestamps vs. current clock.
 *    Signal: 3+ clock-dependent function calls in one PTB.
 *
 * 2. **Expiry-Window Exploit** — Calling a function that depends on
 *    `clock::timestamp_ms` for an expiry check right at the boundary
 *    (e.g., just before a timelock expires) combined with a large outflow.
 *    Signal: time-sensitive function + large balance outflow.
 *
 * 3. **Epoch-Gate Bypass** — Protocol guards access by epoch number or
 *    day-level timestamp. Attacker exploits checkpoint timing to call
 *    time-gated admin functions outside the intended window.
 *    Signal: admin/config function call outside business hours (UTC 2–6am),
 *    combined with a privilege change or outflow.
 *
 * 4. **TWAP Manipulation via Rapid Oracle Updates** — Calling price-update
 *    functions repeatedly within a single PTB to shrink the effective TWAP
 *    window or inject manipulated observations before a borrow/liquidate.
 *    Signal: 3+ oracle-update calls + borrow/liquidate in same PTB.
 */

const CLOCK_SENSITIVE_PATTERNS = [
  'unlock', 'vest', 'vesting', 'redeem', 'release', 'claim',
  'withdraw_vested', 'unstake', 'mature', 'settle',
  'epoch_reward', 'epoch_claim', 'daily', 'weekly',
];

const ORACLE_UPDATE_PATTERNS = [
  'update_price', 'set_price', 'push_price', 'submit_price',
  'feed_price', 'update_twap', 'update_observation',
];

const BORROW_LIQUIDATE_PATTERNS = [
  'borrow', 'liquidate', 'repay', 'flash_borrow',
];

const CLOCK_OBJ_ID = '0x0000000000000000000000000000000000000000000000000000000000000006';

// Business hours exclusion: UTC 6-22 is normal; 22-6 is suspicious for admin calls
const SUSPICIOUS_HOUR_START = 22; // 22:00 UTC
const SUSPICIOUS_HOUR_END = 6;    // 06:00 UTC

const RAPID_CLAIM_THRESHOLD = 3;
const RAPID_ORACLE_THRESHOLD = 3;

function isClockSensitive(fn: string): boolean {
  const fnLower = fn.toLowerCase();
  return CLOCK_SENSITIVE_PATTERNS.some((p) => fnLower.includes(p));
}

function isOracleUpdate(fn: string): boolean {
  const fnLower = fn.toLowerCase();
  return ORACLE_UPDATE_PATTERNS.some((p) => fnLower.includes(p));
}

function isBorrowOrLiquidate(fn: string): boolean {
  const fnLower = fn.toLowerCase();
  return BORROW_LIQUIDATE_PATTERNS.some((p) => fnLower === p || fnLower.startsWith(p));
}

function isSuspiciousHour(isoTimestamp: string): boolean {
  const hour = new Date(isoTimestamp).getUTCHours();
  return hour >= SUSPICIOUS_HOUR_START || hour < SUSPICIOUS_HOUR_END;
}

function usesClockObject(ctx: AttackDetectorContext): boolean {
  // Check if the Clock shared object (0x6) appears in object changes
  return ctx.tx.objectChanges.some(
    (o) => o.address?.toLowerCase() === CLOCK_OBJ_ID,
  );
}

export function detectClockManipulationAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const { tx } = ctx;

  const clockSensitiveCalls = tx.calls.filter((c) => isClockSensitive(c.function));
  const oracleUpdateCalls = tx.calls.filter((c) => isOracleUpdate(c.function));
  const borrowLiquidateCalls = tx.calls.filter((c) => isBorrowOrLiquidate(c.function));

  const hasOutflow = tx.balanceChanges.some((c) => {
    try { return BigInt(c.amount ?? '0') < 0n; } catch { return false; }
  });

  if (clockSensitiveCalls.length === 0 && oracleUpdateCalls.length === 0) return [];

  // Pattern 1: Rapid claim — multiple time-sensitive calls in one PTB
  const isRapidClaim = clockSensitiveCalls.length >= RAPID_CLAIM_THRESHOLD;

  // Pattern 2: Expiry window — time-sensitive + outflow
  const isExpiryWindowExploit = clockSensitiveCalls.length >= 1 && hasOutflow;

  // Pattern 3: Off-hours admin (suspicious UTC hour)
  const isOffHoursAdmin = isSuspiciousHour(tx.timestamp) &&
    clockSensitiveCalls.length >= 1 &&
    hasOutflow;

  // Pattern 4: Rapid oracle update + borrow/liquidate
  const isOracleTwapManipulation =
    oracleUpdateCalls.length >= RAPID_ORACLE_THRESHOLD &&
    borrowLiquidateCalls.length >= 1;

  if (!isRapidClaim && !isExpiryWindowExploit && !isOffHoursAdmin && !isOracleTwapManipulation) {
    return [];
  }

  // Require at least one meaningful corroborating signal for low-count cases
  // (avoid firing on simple "1 vest + outflow" which is legitimate)
  const hasCorroboratingSignal =
    isRapidClaim ||
    isOracleTwapManipulation ||
    (isOffHoursAdmin && clockSensitiveCalls.length >= 2) ||
    (isExpiryWindowExploit && clockSensitiveCalls.length >= 2);

  if (!hasCorroboratingSignal) return [];

  const patterns: string[] = [];
  if (isRapidClaim) patterns.push(`rapid-claim (${clockSensitiveCalls.length}x time-sensitive calls)`);
  if (isOffHoursAdmin) patterns.push('off-hours-time-sensitive-call');
  if (isOracleTwapManipulation) patterns.push(`oracle-twap-manipulation (${oracleUpdateCalls.length} updates + borrow/liquidate)`);
  else if (isExpiryWindowExploit) patterns.push('expiry-window-exploit');

  const scoreDelta = isOracleTwapManipulation ? 40 : isRapidClaim ? 35 : 25;
  const severityFloor = isOracleTwapManipulation || isRapidClaim ? 'high' : 'medium';

  return [
    {
      attackType: 'clock-manipulation',
      category: 'execution-abuse',
      summary: `检测到链上时间操控攻击：${patterns.join('、')}，${clockSensitiveCalls.length} 次时间敏感函数调用在同一 PTB`,
      evidence: {
        sender: tx.sender,
        clockSensitiveCallCount: clockSensitiveCalls.length,
        oracleUpdateCallCount: oracleUpdateCalls.length,
        borrowLiquidateCallCount: borrowLiquidateCalls.length,
        isRapidClaim,
        isExpiryWindowExploit,
        isOffHoursAdmin,
        isOracleTwapManipulation,
        hasOutflow,
        txTimestamp: tx.timestamp,
        txHourUtc: new Date(tx.timestamp).getUTCHours(),
        clockSensitiveFunctions: [
          ...new Set(clockSensitiveCalls.map((c) => `${c.module}::${c.function}`)),
        ],
        patterns,
      },
      riskHints: {
        scoreDelta,
        severityFloor,
      },
      chainHints: {
        stage: isExpiryWindowExploit || isOracleTwapManipulation ? 'extraction' : 'manipulation',
      },
    },
  ];
}
