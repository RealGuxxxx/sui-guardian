import type { AttackDetectorContext, AttackFinding } from '../types.js';

const SENSITIVE_REPEAT_KEYWORDS = [
  'admin',
  'authorize',
  'borrow_flashloan',
  'change_owner',
  'deauthorize',
  'disable',
  'drain',
  'emergency',
  'liquidate',
  'mint_cap',
  'pause',
  'set_admin',
  'set_owner',
  'set_treasury',
  'unpause',
  'upgrade',
  'withdraw',
] as const;

export function detectExecutionAbuseAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const repeated = Object.entries(ctx.derived.sameSensitiveCallRepeats ?? {}).find(
    ([call, count]) => count >= 2 && isSensitiveRepeatedCall(call),
  );
  if (!repeated && !(ctx.derived.suspiciousTargets?.length)) {
    return [];
  }

  return [
    {
      attackType: 'execution-abuse',
      category: 'execution-abuse',
      summary: '检测到重复敏感执行或可疑目标交互',
      evidence: {
        repeatedCall: repeated?.[0],
        repeatCount: repeated?.[1],
        suspiciousTargets: ctx.derived.suspiciousTargets ?? [],
      },
      riskHints: {
        scoreDelta: 20,
        severityFloor: 'medium',
      },
      chainHints: {
        stage: 'probe',
      },
    },
  ];
}

function isSensitiveRepeatedCall(call: string): boolean {
  const normalized = call.toLowerCase();
  return SENSITIVE_REPEAT_KEYWORDS.some((keyword) => normalized.includes(keyword));
}
