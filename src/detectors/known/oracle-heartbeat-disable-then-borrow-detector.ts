import type { AttackDetectorContext, AttackFinding } from '../types.js';

const HEARTBEAT_FIELD_KEYWORDS = ['heartbeat', 'freshness', 'heartbeat_enabled', 'stale_guard'];

export function detectOracleHeartbeatDisableThenBorrowAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const heartbeatShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && HEARTBEAT_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan');
  });
  const flow = ctx.derived.flowEvidence;

  if (!heartbeatShift || !hasBorrowCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-heartbeat-disable-then-borrow',
      category: 'price-manipulation',
      summary: '检测到 oracle heartbeat/freshness 约束被关闭后紧随借贷提取并导向攻击者获利',
      evidence: {
        objectLabel: heartbeatShift.objectLabel,
        field: heartbeatShift.field,
        anomalyKind: heartbeatShift.anomalyKind,
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
        stage: 'extraction',
      },
    },
  ];
}
