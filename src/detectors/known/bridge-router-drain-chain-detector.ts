import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectBridgeRouterDrainChainAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const hasBridgeCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('bridge') || name.includes('claim') || name.includes('message');
  });
  const hasRouterCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('router') || name.includes('hop') || name.includes('swap');
  });
  const flow = ctx.derived.flowEvidence;

  if (!hasBridgeCall || !hasRouterCall || !(ctx.derived.suspiciousTargets?.length) || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('intermediate_hop') || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'bridge-router-drain-chain',
      category: 'liquidity-drain',
      summary: '检测到桥消息/认领经可疑路由中继后完成受保护资产提取并导向攻击者',
      evidence: {
        suspiciousTargets: ctx.derived.suspiciousTargets,
        pathRoles: flow.pathRoles,
        netProtectedOutflow: flow.netProtectedOutflow,
        netAttackerGain: flow.netAttackerGain,
        calls: ctx.tx.calls,
      },
      riskHints: {
        scoreDelta: 35,
        severityFloor: 'critical',
      },
      chainHints: {
        stage: 'extraction',
      },
    },
  ];
}
