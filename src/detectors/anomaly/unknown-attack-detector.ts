import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectUnknownCoordinatedAttack(ctx: AttackDetectorContext): AttackFinding[] {
  const signalCount = [
    (ctx.derived.priceEvidence ?? []).length > 0,
    (ctx.derived.baselineEvidence ?? []).length > 0,
    Boolean(ctx.derived.flowEvidence),
  ].filter(Boolean).length;

  if (signalCount < 2) {
    return [];
  }

  return [
    {
      attackType: 'unknown-coordinated-anomaly',
      category: 'unknown',
      summary: '检测到多证据共振但未归类的高危异常',
      evidence: {
        signalCount,
        evidenceSummary: ctx.derived.evidenceSummary ?? [],
      },
      riskHints: {
        scoreDelta: 25,
        severityFloor: 'medium',
      },
      chainHints: {
        stage: 'manipulation',
      },
    },
  ];
}
