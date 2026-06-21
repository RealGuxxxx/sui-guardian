import type { AttackDetectorContext, AttackFinding } from '../types.js';

const MIN_UPDATE_INTERVAL_FIELD_KEYWORDS = [
  'min_update_interval',
  'update_interval',
  'publish_interval',
  'min_publish_interval',
  'update_delay',
];

export function detectOracleMinUpdateIntervalBypassAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const intervalShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && MIN_UPDATE_INTERVAL_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrLiquidationCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('liquidat');
  });
  const flow = ctx.derived.flowEvidence;

  if (!intervalShift || !hasBorrowOrLiquidationCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-min-update-interval-bypass',
      category: 'price-manipulation',
      summary: '检测到 oracle 最小更新时间隔被绕过或压缩后紧随借贷或清算提取',
      evidence: {
        objectLabel: intervalShift.objectLabel,
        field: intervalShift.field,
        anomalyKind: intervalShift.anomalyKind,
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
