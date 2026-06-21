import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectLiquidityDrainAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const flow = ctx.derived.flowEvidence;
  if (!flow?.attackPathFound) {
    return [];
  }

  return [
    {
      attackType: 'liquidity-drain',
      category: 'liquidity-drain',
      summary: '检测到受保护资金外流并伴随攻击者净获利',
      evidence: { ...flow },
      riskHints: {
        scoreDelta: 35,
        severityFloor: 'high',
      },
      chainHints: {
        stage: 'extraction',
      },
    },
  ];
}
