import type { AttackDetectorContext, AttackFinding } from '../types.js';

const FEE_FIELD_KEYWORDS = ['fee_recipient', 'fee_to', 'fee_receiver', 'recipient'];
const ROUTER_CALL_KEYWORDS = ['router', 'swap', 'hop', 'route'];
const FEE_CALL_KEYWORDS = ['fee', 'collect', 'skim'];

export function detectRouterFeeSkimChainAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const feeShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && FEE_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasRouterCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return ROUTER_CALL_KEYWORDS.some((keyword) => name.includes(keyword));
  });
  const hasFeeCollectionCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return FEE_CALL_KEYWORDS.some((keyword) => name.includes(keyword));
  });
  const flow = ctx.derived.flowEvidence;

  if (!feeShift || !hasRouterCall || !hasFeeCollectionCall || !(ctx.derived.suspiciousTargets?.length) || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('intermediate_hop') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'router-fee-skim-chain',
      category: 'liquidity-drain',
      summary: '检测到 router fee 接收地址被翻转后紧随费用归集与多跳路由提取',
      evidence: {
        objectLabel: feeShift.objectLabel,
        field: feeShift.field,
        anomalyKind: feeShift.anomalyKind,
        suspiciousTargets: ctx.derived.suspiciousTargets,
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
