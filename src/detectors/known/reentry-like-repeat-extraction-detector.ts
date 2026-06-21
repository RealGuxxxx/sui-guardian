import type { AttackDetectorContext, AttackFinding } from '../types.js';

const EXTRACTION_REPEAT_KEYWORDS = ['withdraw', 'redeem', 'claim', 'borrow', 'liquidate'];

export function detectReentryLikeRepeatExtractionAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const repeatedExtraction = Object.entries(ctx.derived.sameSensitiveCallRepeats ?? {}).find(([key, count]) => {
    const normalized = key.toLowerCase();
    return count >= 3 && EXTRACTION_REPEAT_KEYWORDS.some((keyword) => normalized.includes(keyword));
  });
  const flow = ctx.derived.flowEvidence;

  if (!repeatedExtraction || !ctx.derived.valueExtractionDetected || !flow?.attackPathFound) {
    return [];
  }

  return [
    {
      attackType: 'reentry-like-repeat-extraction',
      category: 'execution-abuse',
      summary: '检测到重复提取调用簇与价值外流同时发生，呈现近似重入的提取模式',
      evidence: {
        repeatedCall: repeatedExtraction[0],
        repeatCount: repeatedExtraction[1],
        pathRoles: flow.pathRoles,
        netProtectedOutflow: flow.netProtectedOutflow,
        netAttackerGain: flow.netAttackerGain,
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
