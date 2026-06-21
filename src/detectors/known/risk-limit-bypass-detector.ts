import type { AttackDetectorContext, AttackFinding } from '../types.js';

const RISK_FIELD_KEYWORDS = ['limit', 'cap', 'guard', 'threshold', 'ceiling'];
const BYPASS_CALL_KEYWORDS = ['disable', 'set_', 'update_', 'override'];
const EXTRACTION_CALL_KEYWORDS = ['borrow', 'withdraw', 'redeem'];

export function detectRiskLimitBypassAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const matched = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && RISK_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBypassCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return BYPASS_CALL_KEYWORDS.some((keyword) => name.includes(keyword));
  });
  const hasExtractionCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return EXTRACTION_CALL_KEYWORDS.some((keyword) => name.includes(keyword));
  });
  const flow = ctx.derived.flowEvidence;

  if (!matched || !hasBypassCall || !hasExtractionCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow')) {
    return [];
  }

  return [
    {
      attackType: 'risk-limit-bypass',
      category: 'permission',
      summary: '检测到未授权风险限制被绕过后紧随借贷或提取并伴随资产外流',
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
        stage: 'manipulation',
      },
    },
  ];
}
