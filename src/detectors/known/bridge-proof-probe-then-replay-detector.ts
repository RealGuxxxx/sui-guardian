import type { AttackDetectorContext, AttackFinding } from '../types.js';

const PROBE_RULE_KEYWORDS = ['traffic-spike', 'failure-spike', 'probe', 'verify-proof', 'bridge'];

export function detectBridgeProofProbeThenReplayAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const hasProbeSignal = ctx.runtime.recentAlerts.some((alert) =>
    PROBE_RULE_KEYWORDS.some((keyword) => alert.ruleId.toLowerCase().includes(keyword)),
  );
  const hasProofVerification = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('bridge') && (name.includes('proof') || name.includes('verify'));
  });
  const hasClaimReplay = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('bridge') && (name.includes('claim') || name.includes('message'));
  });
  const flow = ctx.derived.flowEvidence;

  if (!hasProbeSignal || !hasProofVerification || !hasClaimReplay || !(ctx.derived.suspiciousTargets?.length) || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'bridge-proof-probe-then-replay',
      category: 'liquidity-drain',
      summary: '检测到桥 proof 探测信号后紧随 verify/claim 重放链路并完成价值提取',
      evidence: {
        recentProbeAlerts: ctx.runtime.recentAlerts.map((alert) => alert.ruleId),
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
