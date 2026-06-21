import type { AttackDetectorContext, AttackFinding } from '../types.js';

const OBSERVATION_DELAY_FIELD_KEYWORDS = [
  'observation_delay',
  'sample_delay',
  'observation_window_delay',
  'delay_seconds',
];

export function detectOracleObservationDelayBypassAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const delayShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && OBSERVATION_DELAY_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrLiquidationCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('liquidat');
  });
  const flow = ctx.derived.flowEvidence;

  if (!delayShift || !hasBorrowOrLiquidationCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-observation-delay-bypass',
      category: 'price-manipulation',
      summary: '检测到 oracle observation/sampling delay 约束被绕过后紧随借贷或清算提取',
      evidence: {
        objectLabel: delayShift.objectLabel,
        field: delayShift.field,
        anomalyKind: delayShift.anomalyKind,
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
