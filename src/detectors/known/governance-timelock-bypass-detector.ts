import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectGovernanceTimelockBypassAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const hasImmediateExecution = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return (name.includes('proposal') || name.includes('govern')) && (name.includes('execute') || name.includes('now'));
  });
  const timelockShift = (ctx.derived.baselineEvidence ?? []).find(
    (item) => item.field.toLowerCase().includes('timelock') && !item.senderAuthorized,
  );

  if (!hasImmediateExecution || !timelockShift) {
    return [];
  }

  return [
    {
      attackType: 'governance-timelock-bypass',
      category: 'governance',
      summary: '检测到治理执行绕过 timelock 约束',
      evidence: {
        objectLabel: timelockShift.objectLabel,
        field: timelockShift.field,
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
