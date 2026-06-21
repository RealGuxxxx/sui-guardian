import type { AttackDetectorContext, AttackFinding } from '../types.js';

const ROUND_ID_FIELD_KEYWORDS = ['round_id', 'latest_round', 'round', 'aggregator_round'];

export function detectOracleRoundIdResetAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const roundShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && ROUND_ID_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrLiquidationCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('liquidat');
  });
  const flow = ctx.derived.flowEvidence;

  if (!roundShift || !hasBorrowOrLiquidationCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-round-id-reset',
      category: 'price-manipulation',
      summary: '检测到 oracle round id / latest round 元数据被重置后紧随借贷或清算提取',
      evidence: {
        objectLabel: roundShift.objectLabel,
        field: roundShift.field,
        anomalyKind: roundShift.anomalyKind,
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
