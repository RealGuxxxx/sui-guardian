import type { AttackDetectorContext, AttackFinding } from '../types.js';

const ANCHOR_HEARTBEAT_FIELD_KEYWORDS = [
  'anchor_heartbeat',
  'anchor_heartbeat_window',
  'reference_heartbeat',
  'anchor_stale_window',
];

export function detectOracleAnchorHeartbeatCollapseAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const heartbeatShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && ANCHOR_HEARTBEAT_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrLiquidationCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('liquidat');
  });
  const flow = ctx.derived.flowEvidence;

  if (!heartbeatShift || !hasBorrowOrLiquidationCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-anchor-heartbeat-collapse',
      category: 'price-manipulation',
      summary: '检测到 oracle anchor/reference heartbeat 窗口被压缩或放宽后紧随借贷或清算提取',
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
        stage: 'takeover',
      },
    },
  ];
}
