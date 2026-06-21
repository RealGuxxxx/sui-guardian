import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectFlashLoanSequenceAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const flow = ctx.derived.flowEvidence;
  const hasFunding = ctx.derived.flashLikeFundingDetected;
  const hasExtraction = ctx.derived.valueExtractionDetected;
  const hasPriceShock = (ctx.derived.priceEvidence ?? []).some(
    (item) => (item.deviationBps ?? 0) >= 1500 || item.extractionCoupled,
  );
  const callNames = ctx.tx.calls.map((call) => `${call.module}::${call.function}`.toLowerCase());
  const hasManipulation = callNames.some((name) =>
    ['swap', 'route', 'mint', 'vote', 'price', 'oracle'].some((keyword) => name.includes(keyword)),
  );
  const pathRoles = new Set(flow?.pathRoles ?? []);

  if (
    !hasFunding ||
    !hasExtraction ||
    !flow?.attackPathFound ||
    !hasManipulation ||
    !hasPriceShock ||
    !pathRoles.has('temporary_funding') ||
    !pathRoles.has('protected_outflow')
  ) {
    return [];
  }

  return [
    {
      attackType: 'flash-loan-sequence',
      category: 'liquidity-drain',
      summary: '检测到闪电贷注资后紧随状态操纵与价值提取的多步攻击序列',
      evidence: {
        priceSignals: ctx.derived.priceEvidence ?? [],
        pathRoles: flow.pathRoles,
        netProtectedOutflow: flow.netProtectedOutflow,
        netAttackerGain: flow.netAttackerGain,
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
