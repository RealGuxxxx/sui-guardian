import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectOraclePoisoningAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const hasOracleUpdate = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('oracle') || name.includes('price_feed') || name.includes('update_price');
  });
  const matched = (ctx.derived.priceEvidence ?? []).find((item) => (item.deviationBps ?? 0) >= 3000);

  if (!hasOracleUpdate || !matched) {
    return [];
  }

  return [
    {
      attackType: 'oracle-poisoning',
      category: 'price-manipulation',
      summary: `检测到预言机更新伴随极端价格偏离 ${matched.deviationBps} bps`,
      evidence: {
        ...matched,
        calls: ctx.tx.calls,
      },
      riskHints: {
        scoreDelta: 30,
        severityFloor: 'high',
      },
      chainHints: {
        stage: 'manipulation',
      },
    },
  ];
}
