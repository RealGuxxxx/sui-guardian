import type { AttackDetectorContext, AttackFinding } from '../types.js';

const ANCHOR_DEVIATION_FIELD_KEYWORDS = [
  'anchor_deviation',
  'anchor_max_deviation',
  'reference_deviation',
  'anchor_max_deviation_bps',
];

export function detectOracleAnchorDeviationThresholdCollapseAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const deviationShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && ANCHOR_DEVIATION_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrLiquidationCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('liquidat');
  });
  const flow = ctx.derived.flowEvidence;

  if (!deviationShift || !hasBorrowOrLiquidationCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-anchor-deviation-threshold-collapse',
      category: 'price-manipulation',
      summary: '检测到 oracle anchor/reference 偏离阈值被压缩或关闭后紧随借贷或清算提取',
      evidence: {
        objectLabel: deviationShift.objectLabel,
        field: deviationShift.field,
        anomalyKind: deviationShift.anomalyKind,
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
