import type { AttackDetectorContext, AttackFinding } from '../types.js';

const SEQUENCER_UPTIME_FEED_FIELD_KEYWORDS = [
  'sequencer_uptime_feed',
  'uptime_feed',
  'l2_uptime_feed',
  'sequencer_status_feed',
];

export function detectOracleSequencerUptimeFeedOverrideAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const feedShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && SEQUENCER_UPTIME_FEED_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrLiquidationCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('liquidat');
  });
  const flow = ctx.derived.flowEvidence;

  if (!feedShift || !hasBorrowOrLiquidationCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-sequencer-uptime-feed-override',
      category: 'price-manipulation',
      summary: '检测到 oracle sequencer/L2 uptime feed 被重写后紧随借贷或清算提取',
      evidence: {
        objectLabel: feedShift.objectLabel,
        field: feedShift.field,
        anomalyKind: feedShift.anomalyKind,
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
