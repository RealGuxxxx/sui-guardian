import type { AttackDetectorContext, AttackFinding } from '../types.js';

const OBSERVATION_FIELD_KEYWORDS = ['observation', 'cardinality', 'sample_count', 'history_depth'];

export function detectOracleObservationCardinalityDropAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const observationShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && OBSERVATION_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrLiquidationCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('liquidat');
  });
  const flow = ctx.derived.flowEvidence;

  if (!observationShift || !hasBorrowOrLiquidationCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-observation-cardinality-drop',
      category: 'price-manipulation',
      summary: '检测到 oracle observation/cardinality 采样深度被压缩后紧随借贷或清算提取',
      evidence: {
        objectLabel: observationShift.objectLabel,
        field: observationShift.field,
        anomalyKind: observationShift.anomalyKind,
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
