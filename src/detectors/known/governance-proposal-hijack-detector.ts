import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectGovernanceProposalHijackAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const hasGovernanceCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('govern') || name.includes('vote') || name.includes('proposal');
  });
  const unauthorizedPermissionShift = (ctx.derived.baselineEvidence ?? []).find(
    (item) => item.anomalyKind === 'permission_change' && !item.senderAuthorized,
  );

  if (!hasGovernanceCall || !unauthorizedPermissionShift) {
    return [];
  }

  return [
    {
      attackType: 'governance-proposal-hijack',
      category: 'governance',
      summary: '检测到治理提案执行与未授权权限变化同时发生',
      evidence: {
        objectLabel: unauthorizedPermissionShift.objectLabel,
        field: unauthorizedPermissionShift.field,
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
