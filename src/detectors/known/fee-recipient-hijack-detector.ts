import type { AttackDetectorContext, AttackFinding } from '../types.js';

const FEE_FIELD_KEYWORDS = ['fee_recipient', 'fee_to', 'treasury', 'recipient'];
const FEE_CALL_KEYWORDS = ['fee', 'treasury', 'collect'];

export function detectFeeRecipientHijackAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const matched = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && FEE_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasFeeCollectionCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return FEE_CALL_KEYWORDS.some((keyword) => name.includes(keyword));
  });
  const flow = ctx.derived.flowEvidence;

  if (!matched || !hasFeeCollectionCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'fee-recipient-hijack',
      category: 'liquidity-drain',
      summary: '检测到协议费接收地址被未授权劫持后紧随费用提取并流向攻击者',
      evidence: {
        objectLabel: matched.objectLabel,
        field: matched.field,
        anomalyKind: matched.anomalyKind,
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
