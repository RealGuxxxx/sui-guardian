import type { AttackDetectorContext, AttackFinding } from '../types.js';

const ANCHOR_FIELD_KEYWORDS = ['anchor', 'reference', 'base_price', 'peg_source'];

export function detectOracleAnchorOverrideThenBorrowAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const anchorShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && ANCHOR_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan');
  });
  const flow = ctx.derived.flowEvidence;

  if (!anchorShift || !hasBorrowCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-anchor-override-then-borrow',
      category: 'price-manipulation',
      summary: '检测到 oracle 锚定/参考价格来源被重写后紧随借贷提取并导向攻击者获利',
      evidence: {
        objectLabel: anchorShift.objectLabel,
        field: anchorShift.field,
        anomalyKind: anchorShift.anomalyKind,
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
