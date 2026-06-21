import type { AttackDetectorContext, AttackFinding } from '../types.js';

const DEVIATION_FIELD_KEYWORDS = ['deviation', 'max_delta', 'threshold', 'max_deviation_bps'];

export function detectOracleDeviationThresholdCollapseAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const deviationShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && DEVIATION_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrSwapCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('swap');
  });
  const flow = ctx.derived.flowEvidence;

  if (!deviationShift || !hasBorrowOrSwapCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-deviation-threshold-collapse',
      category: 'price-manipulation',
      summary: '检测到 oracle 偏离阈值被压缩或关闭后紧随借贷或成交提取',
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
