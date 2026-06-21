import type { AttackDetectorContext, AttackFinding } from '../types.js';

const ADMIN_FIELD_KEYWORDS = ['admin', 'owner', 'operator', 'authority'];

export function detectOracleAdminRotationThenBorrowAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const adminShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && ADMIN_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan');
  });
  const flow = ctx.derived.flowEvidence;

  if (!adminShift || !hasBorrowCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-admin-rotation-then-borrow',
      category: 'permission',
      summary: '检测到 oracle 管理权限被轮换后紧随借贷提取并导向攻击者获利',
      evidence: {
        objectLabel: adminShift.objectLabel,
        field: adminShift.field,
        anomalyKind: adminShift.anomalyKind,
        pathRoles: flow.pathRoles,
        netProtectedOutflow: flow.netProtectedOutflow,
        netAttackerGain: flow.netAttackerGain,
        calls: ctx.tx.calls,
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
