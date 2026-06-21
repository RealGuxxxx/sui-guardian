import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectCrossMarketManipulationAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const uniqueMarkets = new Set(
    ctx.tx.calls
      .map((call) => call.module.toLowerCase())
      .filter((moduleName) => moduleName.startsWith('amm') || moduleName.includes('router') || moduleName.includes('pool')),
  );
  const matched = (ctx.derived.priceEvidence ?? []).find(
    (item) => (item.deviationBps ?? 0) >= 2000 && item.extractionCoupled,
  );
  const flow = ctx.derived.flowEvidence;

  if (uniqueMarkets.size < 2 || !matched || !ctx.derived.valueExtractionDetected || !flow?.attackPathFound) {
    return [];
  }

  return [
    {
      attackType: 'cross-market-manipulation',
      category: 'price-manipulation',
      summary: '检测到跨市场价格扰动后伴随受保护资产抽离',
      evidence: {
        markets: [...uniqueMarkets],
        label: matched.label,
        deviationBps: matched.deviationBps,
        pathRoles: flow.pathRoles,
        netProtectedOutflow: flow.netProtectedOutflow,
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
