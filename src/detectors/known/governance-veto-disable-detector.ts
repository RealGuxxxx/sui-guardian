import type { AttackDetectorContext, AttackFinding } from '../types.js';

const VETO_FIELD_KEYWORDS = ['veto', 'guardian', 'cancel_guard', 'pause_guard'];

export function detectGovernanceVetoDisableAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const vetoShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && VETO_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasGovernanceExecution = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return (name.includes('govern') || name.includes('proposal')) && name.includes('execute');
  });

  if (!vetoShift || !hasGovernanceExecution) {
    return [];
  }

  return [
    {
      attackType: 'governance-veto-disable',
      category: 'governance',
      summary: '检测到 veto/guardian 保护被未授权关闭后紧随治理执行',
      evidence: {
        objectLabel: vetoShift.objectLabel,
        field: vetoShift.field,
        anomalyKind: vetoShift.anomalyKind,
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
