import type { AttackDetectorContext, AttackFinding } from '../types.js';

const TWAP_FIELD_KEYWORDS = ['twap', 'window', 'interval', 'observation'];

export function detectOracleTwapWindowCollapseAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const twapShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && TWAP_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrLiquidationCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('liquidat');
  });
  const flow = ctx.derived.flowEvidence;

  if (!twapShift || !hasBorrowOrLiquidationCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-twap-window-collapse',
      category: 'price-manipulation',
      summary: '检测到 oracle TWAP/window 平滑窗口被压缩后紧随借贷或清算提取',
      evidence: {
        objectLabel: twapShift.objectLabel,
        field: twapShift.field,
        anomalyKind: twapShift.anomalyKind,
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
