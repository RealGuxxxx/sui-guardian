import type { AttackDetectorContext, AttackFinding } from '../types.js';

const ANCHOR_DECIMALS_FIELD_KEYWORDS = [
  'anchor_decimals',
  'reference_decimals',
  'anchor_scale',
  'base_price_decimals',
];

export function detectOracleAnchorDecimalsMismatchAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const decimalsShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && ANCHOR_DECIMALS_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
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
      attackType: 'oracle-anchor-decimals-mismatch',
      category: 'price-manipulation',
      summary: '检测到 oracle anchor/reference 价格源 decimals/scale 被篡改后紧随借贷或清算提取',
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
        stage: 'takeover',
      },
    },
  ];
}
