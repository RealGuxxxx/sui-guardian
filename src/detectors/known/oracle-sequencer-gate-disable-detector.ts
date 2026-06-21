import type { AttackDetectorContext, AttackFinding } from '../types.js';

const SEQUENCER_FIELD_KEYWORDS = ['sequencer', 'live_gate', 'liveness_gate', 'gate_enabled'];

export function detectOracleSequencerGateDisableAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const sequencerShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && SEQUENCER_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrLiquidationCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('liquidat');
  });
  const flow = ctx.derived.flowEvidence;

  if (!sequencerShift || !hasBorrowOrLiquidationCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-sequencer-gate-disable',
      category: 'price-manipulation',
      summary: '检测到 oracle sequencer/liveness gate 被关闭后仍继续借贷或清算提取',
      evidence: {
        objectLabel: sequencerShift.objectLabel,
        field: sequencerShift.field,
        anomalyKind: sequencerShift.anomalyKind,
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
