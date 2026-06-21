import type { AttackDetectorContext, AttackFinding } from '../types.js';

const BAND_FIELD_KEYWORDS = ['band', 'deviation', 'guardrail', 'price_band'];

export function detectOraclePriceBandDisableAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const bandShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && BAND_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrSwapCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('swap');
  });
  const flow = ctx.derived.flowEvidence;

  if (!bandShift || !hasBorrowOrSwapCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-price-band-disable',
      category: 'price-manipulation',
      summary: '检测到 oracle 价格带/偏离 guardrail 被关闭后紧随借贷或成交提取',
      evidence: {
        objectLabel: bandShift.objectLabel,
        field: bandShift.field,
        anomalyKind: bandShift.anomalyKind,
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
