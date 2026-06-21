import type { AttackDetectorContext, AttackFinding } from '../types.js';

const APPROVAL_KEYWORDS = ['approve', 'permit', 'allowance'];
const ROUTER_KEYWORDS = ['router', 'swap', 'hop', 'invoke'];
const PROBE_RULE_KEYWORDS = ['failure-spike', 'traffic-spike', 'suspicious-target', 'probe'];

export function detectApprovalProbeThenReuseAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const hasProbeSignal = ctx.runtime.recentAlerts.some((alert) =>
    PROBE_RULE_KEYWORDS.some((keyword) => alert.ruleId.toLowerCase().includes(keyword)),
  );
  const hasApprovalCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return APPROVAL_KEYWORDS.some((keyword) => name.includes(keyword));
  });
  const hasRouterCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return ROUTER_KEYWORDS.some((keyword) => name.includes(keyword));
  });
  const flow = ctx.derived.flowEvidence;

  if (!hasProbeSignal || !hasApprovalCall || !hasRouterCall || !(ctx.derived.suspiciousTargets?.length) || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('intermediate_hop') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'approval-probe-then-reuse',
      category: 'execution-abuse',
      summary: '检测到近期探测后 approval/permit 被可疑路由复用并导向攻击者获利',
      evidence: {
        recentProbeAlerts: ctx.runtime.recentAlerts.map((alert) => alert.ruleId),
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
