import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectGovernanceVoteConcentrationAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const repeatedGovernanceVote = Object.entries(ctx.derived.sameSensitiveCallRepeats ?? {}).find(
    ([key, count]) => {
      const normalized = key.toLowerCase();
      return count >= 3 && (normalized.includes('governance::vote') || normalized.includes('proposal::vote'));
    },
  );
  const governancePermissionShift = (ctx.derived.baselineEvidence ?? []).find(
    (item) =>
      item.anomalyKind === 'permission_change' &&
      !item.senderAuthorized &&
      (item.objectLabel.toLowerCase().includes('govern') || item.field.toLowerCase().includes('quorum')),
  );

  if (!repeatedGovernanceVote || !governancePermissionShift) {
    return [];
  }

  return [
    {
      attackType: 'governance-vote-concentration',
      category: 'governance',
      summary: '检测到治理投票在单地址上异常集中并伴随治理权限异常变化',
      evidence: {
        repeatedCall: repeatedGovernanceVote[0],
        repeatCount: repeatedGovernanceVote[1],
        objectLabel: governancePermissionShift.objectLabel,
        field: governancePermissionShift.field,
      },
      riskHints: {
        scoreDelta: 25,
        severityFloor: 'high',
      },
      chainHints: {
        stage: 'takeover',
      },
    },
  ];
}
