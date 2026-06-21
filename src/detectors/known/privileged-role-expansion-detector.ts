import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectPrivilegedRoleExpansionAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const permissionChanges = (ctx.derived.baselineEvidence ?? []).filter(
    (item) => item.anomalyKind === 'permission_change' && !item.senderAuthorized,
  );

  if (permissionChanges.length < 2) {
    return [];
  }

  return [
    {
      attackType: 'privileged-role-expansion',
      category: 'permission',
      summary: '检测到未授权地址在同一攻击步骤中扩散多个高权限角色',
      evidence: {
        sender: ctx.tx.sender,
        permissionFields: permissionChanges.map((item) => `${item.objectLabel}.${item.field}`),
        calls: ctx.tx.calls,
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
