import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectPriceManipulationAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const matched = (ctx.derived.priceEvidence ?? []).find(
    (item) => (item.deviationBps ?? 0) >= 1500 && item.extractionCoupled,
  );

  if (!matched || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  return [
    {
      attackType: 'oracle-price-manipulation',
      category: 'price-manipulation',
      summary: `检测到价格偏离 ${matched.deviationBps} bps 且伴随价值提取`,
      evidence: { ...matched },
      riskHints: {
        scoreDelta: 35,
        severityFloor: 'high',
      },
      chainHints: {
        stage: 'manipulation',
      },
    },
  ];
}
