import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectBridgeDrainAfterClaimAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const hasBridgeClaim = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('bridge') || name.includes('claim');
  });
  const flow = ctx.derived.flowEvidence;

  if (!hasBridgeClaim || !(ctx.derived.suspiciousTargets?.length) || !ctx.derived.valueExtractionDetected || !flow?.attackPathFound) {
    return [];
  }

  const hasDrainRoles = flow.pathRoles.includes('protected_outflow') && flow.pathRoles.includes('attacker_receipt');
  if (!hasDrainRoles) {
    return [];
  }

  return [
    {
      attackType: 'bridge-drain-after-claim',
      category: 'liquidity-drain',
      summary: '检测到桥认领后紧跟受保护资金外流并流向攻击者',
      evidence: {
        suspiciousTargets: ctx.derived.suspiciousTargets,
        netProtectedOutflow: flow.netProtectedOutflow,
        netAttackerGain: flow.netAttackerGain,
        pathRoles: flow.pathRoles,
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
