import type { AttackDetectorContext, AttackFinding } from '../types.js';

const DELAY_FIELD_KEYWORDS = ['delay', 'timelock', 'execution_delay', 'grace_period'];

export function detectGovernanceDelayCollapseAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const delayShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && DELAY_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasImmediateExecution = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return (name.includes('govern') || name.includes('proposal')) && (name.includes('execute') || name.includes('now'));
  });

  if (!delayShift || !hasImmediateExecution) {
    return [];
  }

  return [
    {
      attackType: 'governance-delay-collapse',
      category: 'governance',
      summary: '检测到治理执行延迟被压缩后紧随即时执行，呈现延迟塌陷式接管',
      evidence: {
        objectLabel: delayShift.objectLabel,
        field: delayShift.field,
        anomalyKind: delayShift.anomalyKind,
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
