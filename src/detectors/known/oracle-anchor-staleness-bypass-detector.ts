import type { AttackDetectorContext, AttackFinding } from '../types.js';

const ANCHOR_STALENESS_FIELD_KEYWORDS = [
  'anchor_staleness',
  'anchor_stale_check',
  'reference_staleness',
  'anchor_freshness',
];

export function detectOracleAnchorStalenessBypassAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const staleShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && ANCHOR_STALENESS_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrLiquidationCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('liquidat');
  });
  const flow = ctx.derived.flowEvidence;

  if (!staleShift || !hasBorrowOrLiquidationCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-anchor-staleness-bypass',
      category: 'price-manipulation',
      summary: '检测到 oracle anchor/reference 新鲜度校验被绕过后紧随借贷或清算提取',
      evidence: {
        objectLabel: staleShift.objectLabel,
        field: staleShift.field,
        anomalyKind: staleShift.anomalyKind,
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
