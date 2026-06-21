import type { AttackDetectorContext, AttackFinding } from '../types.js';

const HEARTBEAT_THRESHOLD_FIELD_KEYWORDS = [
  'heartbeat_threshold',
  'heartbeat_window',
  'stale_threshold',
  'stale_window',
  'heartbeat_seconds',
];

export function detectOracleHeartbeatThresholdCollapseAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const thresholdShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && HEARTBEAT_THRESHOLD_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrLiquidationCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('liquidat');
  });
  const flow = ctx.derived.flowEvidence;

  if (!thresholdShift || !hasBorrowOrLiquidationCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-heartbeat-threshold-collapse',
      category: 'price-manipulation',
      summary: '检测到 oracle heartbeat/stale threshold 被放宽或压塌后紧随借贷或清算提取',
      evidence: {
        objectLabel: thresholdShift.objectLabel,
        field: thresholdShift.field,
        anomalyKind: thresholdShift.anomalyKind,
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
