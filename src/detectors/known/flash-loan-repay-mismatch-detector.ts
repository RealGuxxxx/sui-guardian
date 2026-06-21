import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectFlashLoanRepayMismatchAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const flow = ctx.derived.flowEvidence;
  const hasRepayCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('flash') || name.includes('repay');
  });

  if (!ctx.derived.flashLikeFundingDetected || !ctx.derived.valueExtractionDetected || !hasRepayCall || !flow?.attackPathFound) {
    return [];
  }

  const pathRoles = new Set(flow.pathRoles);
  const attackerGain = BigInt(flow.netAttackerGain || '0');
  if (!pathRoles.has('temporary_funding') || !pathRoles.has('attacker_receipt') || attackerGain <= 0n) {
    return [];
  }

  return [
    {
      attackType: 'flash-loan-repay-mismatch',
      category: 'liquidity-drain',
      summary: '检测到闪电贷归还动作存在，但攻击者在归还后仍保留异常净收益',
      evidence: {
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
