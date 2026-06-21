import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectArbitraryExternalCallAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  if (!(ctx.derived.suspiciousTargets?.length) || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  const hasExternalCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('call') || name.includes('invoke') || name.includes('router');
  });

  if (!hasExternalCall) {
    return [];
  }

  return [
    {
      attackType: 'arbitrary-external-call',
      category: 'execution-abuse',
      summary: '检测到可疑目标上的任意外部调用并伴随价值提取意图',
      evidence: {
        suspiciousTargets: ctx.derived.suspiciousTargets,
        calls: ctx.tx.calls,
      },
      riskHints: {
        scoreDelta: 25,
        severityFloor: 'high',
      },
      chainHints: {
        stage: 'extraction',
      },
    },
  ];
}
