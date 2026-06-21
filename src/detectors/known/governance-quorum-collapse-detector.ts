import type { AttackDetectorContext, AttackFinding } from '../types.js';

const QUORUM_FIELD_KEYWORDS = ['quorum', 'threshold', 'vote_threshold'];

export function detectGovernanceQuorumCollapseAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const quorumShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && QUORUM_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const voteRepeats = Object.entries(ctx.derived.sameSensitiveCallRepeats ?? {}).find(
    ([key, count]) => key.toLowerCase().includes('governance::vote') && count >= 4,
  );
  const hasExecutionCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return (name.includes('govern') || name.includes('proposal')) && name.includes('execute');
  });

  if (!quorumShift || !voteRepeats || !hasExecutionCall) {
    return [];
  }

  return [
    {
      attackType: 'governance-quorum-collapse',
      category: 'governance',
      summary: '检测到 quorum 类门槛被压缩后伴随集中投票与提案执行',
      evidence: {
        objectLabel: quorumShift.objectLabel,
        field: quorumShift.field,
        anomalyKind: quorumShift.anomalyKind,
        repeatedCall: voteRepeats[0],
        repeatCount: voteRepeats[1],
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
