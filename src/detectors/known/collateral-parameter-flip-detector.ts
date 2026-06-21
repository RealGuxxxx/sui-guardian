import type { AttackDetectorContext, AttackFinding } from '../types.js';

const COLLATERAL_FIELD_KEYWORDS = ['collateral', 'ltv', 'liquidation', 'borrow_cap', 'debt_cap'];
const LENDING_CALL_KEYWORDS = ['borrow', 'liquidat', 'redeem'];
const PARAMETER_CALL_KEYWORDS = ['set_', 'update_', 'config', 'factor', 'threshold'];

export function detectCollateralParameterFlipAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const parameterShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const field = item.field.toLowerCase();
    return COLLATERAL_FIELD_KEYWORDS.some((keyword) => field.includes(keyword)) && !item.senderAuthorized;
  });
  const hasLendingCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return LENDING_CALL_KEYWORDS.some((keyword) => name.includes(keyword));
  });
  const hasParameterMutation = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return PARAMETER_CALL_KEYWORDS.some((keyword) => name.includes(keyword));
  });
  const flow = ctx.derived.flowEvidence;

  if (!parameterShift || !hasLendingCall || !hasParameterMutation || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow')) {
    return [];
  }

  return [
    {
      attackType: 'collateral-parameter-flip',
      category: 'liquidation',
      summary: '检测到未授权抵押/清算参数翻转后紧随借贷或赎回并伴随资金外流',
      evidence: {
        objectLabel: parameterShift.objectLabel,
        field: parameterShift.field,
        anomalyKind: parameterShift.anomalyKind,
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
