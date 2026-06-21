import type { AttackDetectorContext, AttackFinding } from '../types.js';

const FALLBACK_DECIMALS_FIELD_KEYWORDS = [
  'fallback_decimals',
  'backup_decimals',
  'fallback_scale',
  'fallback_price_decimals',
];

export function detectOracleFallbackDecimalsMismatchAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const decimalsShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && FALLBACK_DECIMALS_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrSwapCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('swap');
  });
  const flow = ctx.derived.flowEvidence;

  if (!decimalsShift || !hasBorrowOrSwapCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-fallback-decimals-mismatch',
      category: 'price-manipulation',
      summary: '检测到 oracle fallback 价格源 decimals/scale 与主路径解释不一致后紧随借贷或成交提取',
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
