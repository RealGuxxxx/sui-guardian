import type { AttackDetectorContext, AttackFinding } from '../types.js';

const APPROVAL_KEYWORDS = ['approve', 'permit', 'allowance'];
const ROUTER_KEYWORDS = ['router', 'hop', 'swap', 'invoke'];

export function detectRouterApprovalReuseAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const hasApprovalCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return APPROVAL_KEYWORDS.some((keyword) => name.includes(keyword));
  });
  const hasRouterCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return ROUTER_KEYWORDS.some((keyword) => name.includes(keyword));
  });
  const flow = ctx.derived.flowEvidence;

  if (!hasApprovalCall || !hasRouterCall || !(ctx.derived.suspiciousTargets?.length) || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('intermediate_hop') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'router-approval-reuse',
      category: 'execution-abuse',
      summary: '检测到 approval/permit 被可疑路由多跳链路复用并最终导向攻击者获利',
      evidence: {
        suspiciousTargets: ctx.derived.suspiciousTargets,
        pathRoles: flow.pathRoles,
        netProtectedOutflow: flow.netProtectedOutflow,
        netAttackerGain: flow.netAttackerGain,
        calls: ctx.tx.calls,
      },
      riskHints: {
        scoreDelta: 30,
        severityFloor: 'high',
      },
      chainHints: {
        stage: 'extraction',
      },
    },
  ];
}
