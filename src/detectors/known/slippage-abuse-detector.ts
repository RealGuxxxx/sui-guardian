import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectSlippageAbuseAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const hasSwapCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('swap') || name.includes('route');
  });
  const matched = (ctx.derived.priceEvidence ?? []).find(
    (item) => (item.deviationBps ?? 0) >= 2000 && item.extractionCoupled,
  );

  if (!hasSwapCall || !matched || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  return [
    {
      attackType: 'slippage-abuse',
      category: 'price-manipulation',
      summary: `检测到极端价格偏离 ${matched.deviationBps} bps 下的异常成交`,
      evidence: {
        ...matched,
        calls: ctx.tx.calls,
      },
      riskHints: {
        scoreDelta: 25,
        severityFloor: 'high',
      },
      chainHints: {
        stage: 'manipulation',
      },
    },
  ];
}
