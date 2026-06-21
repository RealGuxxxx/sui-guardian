import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectGovernanceExecutionAfterVoteSurgeAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const voteRepeats = Object.entries(ctx.derived.sameSensitiveCallRepeats ?? {}).find(
    ([key, count]) => key.toLowerCase().includes('governance::vote') && count >= 4,
  );
  const hasExecutionCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return (name.includes('govern') || name.includes('proposal')) && name.includes('execute');
  });
  const unauthorizedGovernanceShift = (ctx.derived.baselineEvidence ?? []).find(
    (item) =>
      item.anomalyKind === 'permission_change' &&
      !item.senderAuthorized &&
      (item.objectLabel.toLowerCase().includes('govern') || item.field.toLowerCase().includes('proposal')),
  );

  if (!voteRepeats || !hasExecutionCall || !unauthorizedGovernanceShift) {
    return [];
  }

  return [
    {
      attackType: 'governance-execution-after-vote-surge',
      category: 'governance',
      summary: '检测到治理投票异常集中后紧随提案执行与治理权限异常变化',
      evidence: {
        repeatedCall: voteRepeats[0],
        repeatCount: voteRepeats[1],
        objectLabel: unauthorizedGovernanceShift.objectLabel,
        field: unauthorizedGovernanceShift.field,
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
