import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectBridgeProofReplayDrainAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const hasProofVerification = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('bridge') && (name.includes('proof') || name.includes('verify'));
  });
  const hasClaimReplay = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('bridge') && (name.includes('claim') || name.includes('message'));
  });
  const flow = ctx.derived.flowEvidence;

  if (!hasProofVerification || !hasClaimReplay || !(ctx.derived.suspiciousTargets?.length) || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'bridge-proof-replay-drain',
      category: 'liquidity-drain',
      summary: '检测到桥 proof/verify 与 claim/message 链路疑似被重放后完成价值提取',
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
