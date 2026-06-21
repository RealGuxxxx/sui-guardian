import type { AttackDetectorContext, AttackFinding } from '../types.js';

const CAP_FIELD_KEYWORDS = ['liquidity_cap', 'cap', 'ceiling', 'limit'];
const EXTRACTION_CALL_KEYWORDS = ['withdraw', 'redeem', 'drain', 'remove_liquidity'];

export function detectLiquidityCapReleaseThenDrainAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const capShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && CAP_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasExtractionCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return EXTRACTION_CALL_KEYWORDS.some((keyword) => name.includes(keyword));
  });
  const flow = ctx.derived.flowEvidence;

  if (!capShift || !hasExtractionCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'liquidity-cap-release-then-drain',
      category: 'liquidity-drain',
      summary: '检测到流动性上限被未授权松开后紧随流动性提取并导向攻击者获利',
      evidence: {
        objectLabel: capShift.objectLabel,
        field: capShift.field,
        anomalyKind: capShift.anomalyKind,
        pathRoles: flow.pathRoles,
        netProtectedOutflow: flow.netProtectedOutflow,
        netAttackerGain: flow.netAttackerGain,
        calls: ctx.tx.calls,
      },
      riskHints: {
        scoreDelta: 35,
        severityFloor: 'critical',
      },
      chainHints: {
        stage: 'extraction',
      },
    },
  ];
}
