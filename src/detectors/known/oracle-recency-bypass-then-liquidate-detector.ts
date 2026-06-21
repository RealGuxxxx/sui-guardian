import type { AttackDetectorContext, AttackFinding } from '../types.js';

const RECENCY_FIELD_KEYWORDS = ['recency', 'stale', 'freshness', 'age_limit'];

export function detectOracleRecencyBypassThenLiquidateAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const recencyShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && RECENCY_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasLiquidationCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('liquidat');
  });
  const flow = ctx.derived.flowEvidence;

  if (!recencyShift || !hasLiquidationCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-recency-bypass-then-liquidate',
      category: 'liquidation',
      summary: '检测到 oracle recency/stale 校验被绕过后紧随异常清算并形成攻击者获利',
      evidence: {
        objectLabel: recencyShift.objectLabel,
        field: recencyShift.field,
        anomalyKind: recencyShift.anomalyKind,
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
        stage: 'extraction',
      },
    },
  ];
}
