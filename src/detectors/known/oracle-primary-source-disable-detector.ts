import type { AttackDetectorContext, AttackFinding } from '../types.js';

const PRIMARY_SOURCE_FIELD_KEYWORDS = ['primary_source', 'main_feed', 'primary_feed', 'source_enabled'];

export function detectOraclePrimarySourceDisableAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const sourceShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && PRIMARY_SOURCE_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrLiquidationCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('liquidat');
  });
  const flow = ctx.derived.flowEvidence;

  if (!sourceShift || !hasBorrowOrLiquidationCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-primary-source-disable',
      category: 'price-manipulation',
      summary: '检测到 oracle 主价格源被关闭后回落脆弱路径并紧随借贷或清算提取',
      evidence: {
        objectLabel: sourceShift.objectLabel,
        field: sourceShift.field,
        anomalyKind: sourceShift.anomalyKind,
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
