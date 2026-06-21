import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectLiquidationManipulationAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const hasLiquidationCall = ctx.tx.calls.some((call) =>
    `${call.module}::${call.function}`.toLowerCase().includes('liquidat'),
  );
  const matched = (ctx.derived.priceEvidence ?? []).find(
    (item) => (item.deviationBps ?? 0) >= 1500 && item.extractionCoupled,
  );

  if (!hasLiquidationCall || !matched || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  return [
    {
      attackType: 'liquidation-manipulation',
      category: 'liquidation',
      summary: `检测到价格偏离 ${matched.deviationBps} bps 后的异常清算行为`,
      evidence: {
        ...matched,
        calls: ctx.tx.calls,
      },
      riskHints: {
        scoreDelta: 30,
        severityFloor: 'high',
      },
      chainHints: {
        stage: 'extraction',
      },
    },
  ];
}
