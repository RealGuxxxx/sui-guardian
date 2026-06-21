import type { AttackDetectorContext, AttackFinding } from '../types.js';

const APPROVAL_KEYWORDS = ['approve', 'permit', 'allowance'];
const EXTRACTION_KEYWORDS = ['transfer_from', 'withdraw', 'redeem', 'drain', 'claim'];

export function detectApprovalDrainAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const hasApprovalCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return APPROVAL_KEYWORDS.some((keyword) => name.includes(keyword));
  });
  const hasExtractionCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return EXTRACTION_KEYWORDS.some((keyword) => name.includes(keyword));
  });
  const flow = ctx.derived.flowEvidence;

  if (!hasApprovalCall || !hasExtractionCall || !(ctx.derived.suspiciousTargets?.length) || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'approval-drain',
      category: 'liquidity-drain',
      summary: '检测到 approval/permit 类授权后紧随受保护资产被转出至攻击者',
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
