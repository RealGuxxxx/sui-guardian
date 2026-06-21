import type { AttackDetectorContext, AttackFinding } from '../types.js';

const GOVERNANCE_FIELD_KEYWORDS = ['threshold', 'quorum', 'delay', 'timelock', 'vote', 'proposal'];
const GOVERNANCE_CALL_KEYWORDS = ['govern', 'proposal', 'vote'];
const PARAMETER_MUTATION_KEYWORDS = ['set_', 'update_', 'config', 'threshold', 'delay'];

export function detectGovernanceParameterPoisoningAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const matched = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && GOVERNANCE_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasGovernanceCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return GOVERNANCE_CALL_KEYWORDS.some((keyword) => name.includes(keyword));
  });
  const hasParameterMutation = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return PARAMETER_MUTATION_KEYWORDS.some((keyword) => name.includes(keyword));
  });

  if (!matched || !hasGovernanceCall || !hasParameterMutation) {
    return [];
  }

  return [
    {
      attackType: 'governance-parameter-poisoning',
      category: 'governance',
      summary: '检测到治理阈值/延迟等关键参数被未授权篡改后紧随治理执行',
      evidence: {
        objectLabel: matched.objectLabel,
        field: matched.field,
        anomalyKind: matched.anomalyKind,
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
