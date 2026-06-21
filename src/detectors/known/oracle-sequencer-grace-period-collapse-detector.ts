import type { AttackDetectorContext, AttackFinding } from '../types.js';

const SEQUENCER_GRACE_PERIOD_FIELD_KEYWORDS = [
  'sequencer_grace_period',
  'grace_period',
  'sequencer_delay_window',
  'l2_grace_window',
];

export function detectOracleSequencerGracePeriodCollapseAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const graceShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && SEQUENCER_GRACE_PERIOD_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrLiquidationCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('liquidat');
  });
  const flow = ctx.derived.flowEvidence;

  if (!graceShift || !hasBorrowOrLiquidationCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-sequencer-grace-period-collapse',
      category: 'price-manipulation',
      summary: '检测到 oracle sequencer/L2 grace period 被压缩或归零后紧随借贷或清算提取',
      evidence: {
        objectLabel: graceShift.objectLabel,
        field: graceShift.field,
        anomalyKind: graceShift.anomalyKind,
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
