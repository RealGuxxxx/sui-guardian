import type { AttackDetectorContext, AttackFinding } from '../types.js';

const TREASURY_KEYWORDS = ['treasury', 'skim', 'fee', 'withdraw'];

export function detectTreasurySkimSequenceAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const treasuryCalls = ctx.tx.calls.filter((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return TREASURY_KEYWORDS.some((keyword) => name.includes(keyword));
  });
  const flow = ctx.derived.flowEvidence;

  if (treasuryCalls.length < 2 || !ctx.derived.valueExtractionDetected || !flow?.attackPathFound) {
    return [];
  }

  if (!flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'treasury-skim-sequence',
      category: 'liquidity-drain',
      summary: '检测到 treasury/skim 类连续提取动作后形成攻击者净获利',
      evidence: {
        calls: treasuryCalls,
        pathRoles: flow.pathRoles,
        netProtectedOutflow: flow.netProtectedOutflow,
        netAttackerGain: flow.netAttackerGain,
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
