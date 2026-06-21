import type { AttackDetectorContext, AttackFinding } from '../types.js';

const ANSWER_DECIMALS_FIELD_KEYWORDS = ['answer_decimals', 'decimals', 'price_decimals', 'oracle_decimals'];

export function detectOracleAnswerDecimalsFlipAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const decimalsShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && ANSWER_DECIMALS_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrLiquidationCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('liquidat');
  });
  const flow = ctx.derived.flowEvidence;

  if (!decimalsShift || !hasBorrowOrLiquidationCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-answer-decimals-flip',
      category: 'price-manipulation',
      summary: '检测到 oracle 价格 answer decimals/scale 被篡改后紧随借贷或清算提取',
      evidence: {
        objectLabel: decimalsShift.objectLabel,
        field: decimalsShift.field,
        anomalyKind: decimalsShift.anomalyKind,
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
