import type { AttackDetectorContext, AttackFinding } from '../types.js';

const BRAKE_FIELD_KEYWORDS = ['emergency_brake', 'emergency_stop', 'circuit_breaker', 'brake'];

export function detectGovernanceEmergencyBrakeDisableAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const brakeShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && BRAKE_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasGovernanceExecution = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return (name.includes('govern') || name.includes('proposal')) && name.includes('execute');
  });

  if (!brakeShift || !hasGovernanceExecution) {
    return [];
  }

  return [
    {
      attackType: 'governance-emergency-brake-disable',
      category: 'governance',
      summary: '检测到治理 emergency brake/circuit breaker 被未授权关闭后紧随治理执行',
      evidence: {
        objectLabel: brakeShift.objectLabel,
        field: brakeShift.field,
        anomalyKind: brakeShift.anomalyKind,
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
