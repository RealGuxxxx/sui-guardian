import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectSuspiciousRouterHopAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const hasRouterLikeCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('router') || name.includes('invoke') || name.includes('hop');
  });
  const flow = ctx.derived.flowEvidence;

  if (!hasRouterLikeCall || !(ctx.derived.suspiciousTargets?.length) || !ctx.derived.valueExtractionDetected || !flow?.attackPathFound) {
    return [];
  }

  if (!flow.pathRoles.includes('intermediate_hop')) {
    return [];
  }

  return [
    {
      attackType: 'suspicious-router-hop',
      category: 'execution-abuse',
      summary: '检测到可疑目标参与的多跳路由调用并伴随价值提取',
      evidence: {
        suspiciousTargets: ctx.derived.suspiciousTargets,
        pathRoles: flow.pathRoles,
        netProtectedOutflow: flow.netProtectedOutflow,
        netAttackerGain: flow.netAttackerGain,
        calls: ctx.tx.calls,
      },
      riskHints: {
        scoreDelta: 25,
        severityFloor: 'high',
      },
      chainHints: {
        stage: 'extraction',
      },
    },
  ];
}
