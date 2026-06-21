import type { AttackDetectorContext, AttackFinding } from '../types.js';

const SEQUENCER_STATUS_FIELD_KEYWORDS = [
  'sequencer_status',
  'status_inverted',
  'status_flip',
  'l2_status',
];

export function detectOracleSequencerStatusInversionAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const statusShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && SEQUENCER_STATUS_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrLiquidationCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('liquidat');
  });
  const flow = ctx.derived.flowEvidence;

  if (!statusShift || !hasBorrowOrLiquidationCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-sequencer-status-inversion',
      category: 'price-manipulation',
      summary: '检测到 oracle sequencer/L2 状态语义被翻转后紧随借贷或清算提取',
      evidence: {
        objectLabel: statusShift.objectLabel,
        field: statusShift.field,
        anomalyKind: statusShift.anomalyKind,
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
