import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectAttackerProfitRealizationAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const flow = ctx.derived.flowEvidence;
  if (!flow?.attackPathFound) {
    return [];
  }

  const attackerGain = BigInt(flow.netAttackerGain || '0');
  const protectedOutflow = BigInt(flow.netProtectedOutflow || '0');
  if (attackerGain <= 0n || protectedOutflow <= 0n) {
    return [];
  }

  return [
    {
      attackType: 'attacker-profit-realization',
      category: 'liquidity-drain',
      summary: '检测到攻击路径完成后攻击者实现净获利',
      evidence: {
        netAttackerGain: flow.netAttackerGain,
        netProtectedOutflow: flow.netProtectedOutflow,
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
