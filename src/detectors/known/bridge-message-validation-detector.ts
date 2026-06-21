import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectBridgeMessageValidationAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const hasBridgeExecution = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('bridge') || name.includes('message') || name.includes('claim');
  });

  if (!hasBridgeExecution || !ctx.derived.valueExtractionDetected || !(ctx.derived.suspiciousTargets?.length)) {
    return [];
  }

  return [
    {
      attackType: 'bridge-message-validation-failure',
      category: 'governance',
      summary: '检测到桥消息执行/认领伴随可疑目标交互与价值提取',
      evidence: {
        suspiciousTargets: ctx.derived.suspiciousTargets,
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
