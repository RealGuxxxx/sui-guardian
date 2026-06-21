import type { AttackDetectorContext, AttackFinding } from '../types.js';

const CONFIG_FIELD_KEYWORDS = ['pause', 'guard', 'limit', 'fee', 'config', 'whitelist'];

export function detectPrivilegedConfigFlipAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const matched = (ctx.derived.baselineEvidence ?? []).find((item) => {
    if (item.senderAuthorized) {
      return false;
    }

    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return (
      item.anomalyKind === 'state_flip' ||
      (item.anomalyKind === 'permission_change' && CONFIG_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword))) ||
      CONFIG_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword))
    );
  });

  if (!matched) {
    return [];
  }

  return [
    {
      attackType: 'privileged-config-flip',
      category: 'permission',
      summary: '检测到未授权地址翻转关键配置/保护开关',
      evidence: {
        objectLabel: matched.objectLabel,
        field: matched.field,
        anomalyKind: matched.anomalyKind,
        sender: ctx.tx.sender,
      },
      riskHints: {
        scoreDelta: 25,
        severityFloor: 'high',
      },
      chainHints: {
        stage: 'takeover',
      },
    },
  ];
}
