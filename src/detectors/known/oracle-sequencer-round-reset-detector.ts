import type { AttackDetectorContext, AttackFinding } from '../types.js';

const SEQUENCER_ROUND_FIELD_KEYWORDS = [
  'sequencer_round',
  'sequencer_round_id',
  'l2_round',
  'uptime_round',
];

export function detectOracleSequencerRoundResetAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const roundShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && SEQUENCER_ROUND_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
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
      attackType: 'oracle-sequencer-round-reset',
      category: 'price-manipulation',
      summary: '检测到 oracle sequencer/L2 round 元数据被重置后紧随借贷或清算提取',
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
