import type { AttackDetectorContext, AttackFinding } from '../types.js';

/**
 * Aftermath Finance $1.14M exploit (April 29, 2026) — Perpetuals Fee Parameter Abuse
 *
 * The attacker:
 * 1. Registered as an integrator (permissionless, costs cents in gas)
 * 2. Set taker fee to -100,000 bps — a massive negative value that created an
 *    artificial credit/subsidy instead of a fee charge
 * 3. The protocol's collateral accounting treated this fee credit as real collateral
 * 4. Withdrew real USDC against the inflated "collateral" in 11 transactions over 36 minutes
 *
 * Detection strategy: fee-setting function call + value extraction in same TX,
 * OR suspiciously large pure input argument in a fee-setting context.
 *
 * Corroborating signals required to reduce false positives:
 * - At least one of: value extraction, large protected-address outflow, or flash-like funding
 */

const FEE_SETTING_FUNCTION_PATTERNS = [
  'set_taker_fee',
  'set_maker_fee',
  'set_fee_rate',
  'update_fee_rate',
  'set_rebate',
  'set_builder_fee',
  'set_integrator_fee',
  'update_fee',
  'set_protocol_fee',
  'configure_fee',
  'set_fee_bps',
  'update_taker_fee',
  'register_and_set_fee',
];

// Threshold for "suspiciously extreme" fee value
// Legitimate fees are typically 0–500 bps (0–5%)
// Anything above 5,000 bps (50%) is unusual; above 10,000 bps is almost certainly malicious
const SUSPICIOUS_FEE_PURE_THRESHOLD = BigInt(10_000);

function isFeeSettingCall(fnName: string): boolean {
  const lower = fnName.toLowerCase();
  return FEE_SETTING_FUNCTION_PATTERNS.some((pattern) => lower.includes(pattern));
}

export function detectPerpetualsFeeParameterAbuseAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const calls = ctx.tx.calls;

  // Find calls to fee-setting functions
  const feeSettingCalls = calls.filter((call) =>
    isFeeSettingCall(call.function),
  );

  if (feeSettingCalls.length === 0) return [];

  // Check for extreme pure input values (indicative of fee manipulation)
  const hasExtremeFeeValue = feeSettingCalls.some((call) => {
    const pureis = call.pureInputs ?? [];
    return pureis.some((v) => {
      if (typeof v !== 'string') return false;
      const parsed = BigInt(v.replace(/\D/g, '') || '0');
      // Either extremely large (possible u64 underflow representing negative) OR unreasonable bps
      return parsed > SUSPICIOUS_FEE_PURE_THRESHOLD;
    });
  });

  // Corroborating signals
  const hasExtraction = ctx.derived.valueExtractionDetected;
  const hasFlashLike = ctx.derived.flashLikeFundingDetected;
  const flowEvidence = ctx.derived.flowEvidence;
  const hasLargeOutflow = BigInt(flowEvidence?.netProtectedOutflow ?? '0') < BigInt(-1_000_000); // >1M MIST outflow

  // Require at least one corroborating signal
  const hasCorroboration = hasExtraction || hasFlashLike || hasLargeOutflow;

  if (!hasCorroboration) return [];

  const affectedFunctions = feeSettingCalls.map((c) => `${c.module}::${c.function}`);

  return [
    {
      attackType: 'perpetuals-fee-parameter-abuse',
      category: 'execution-abuse',
      summary: `检测到手续费参数滥用攻击（Aftermath Finance 模式）：调用手续费设置函数 ${affectedFunctions[0]} 后紧跟价值提取，疑似设置极端负费率以虚增抵押品`,
      evidence: {
        sender: ctx.tx.sender,
        feeSettingFunctions: affectedFunctions,
        hasExtremeFeeValue,
        hasExtraction,
        hasFlashLike,
        netProtectedOutflow: flowEvidence?.netProtectedOutflow ?? '0',
        pureInputs: feeSettingCalls.map((c) => ({ fn: c.function, args: c.pureInputs })),
      },
      riskHints: {
        scoreDelta: hasExtremeFeeValue ? 45 : 30,
        severityFloor: hasExtremeFeeValue ? 'critical' : 'high',
      },
      chainHints: {
        stage: 'extraction',
      },
    },
  ];
}
