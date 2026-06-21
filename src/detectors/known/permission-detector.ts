import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectPermissionAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const permissionChange = (ctx.derived.baselineEvidence ?? []).find(
    (item) => item.anomalyKind === 'permission_change' && !item.senderAuthorized,
  );

  if (!permissionChange) {
    return [];
  }

  return [
    {
      attackType: 'admin-takeover',
      category: 'permission',
      summary: `${permissionChange.objectLabel}.${permissionChange.field} 出现未授权权限变更`,
      evidence: {
        objectLabel: permissionChange.objectLabel,
        field: permissionChange.field,
        sender: ctx.tx.sender,
      },
      riskHints: {
        scoreDelta: 30,
        severityFloor: 'high',
      },
      chainHints: {
        stage: 'takeover',
      },
    },
  ];
}
