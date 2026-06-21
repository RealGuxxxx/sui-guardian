import type { AttackDetectorContext, AttackFinding } from '../types.js';

const RECIPIENT_FIELD_KEYWORDS = ['recipient', 'beneficiary', 'receiver'];
const ROUTER_CALL_KEYWORDS = ['router', 'swap', 'hop', 'route'];

export function detectRouterRecipientFlipAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const recipientFlip = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && RECIPIENT_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasRouterCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return ROUTER_CALL_KEYWORDS.some((keyword) => name.includes(keyword));
  });
  const flow = ctx.derived.flowEvidence;

  if (!recipientFlip || !hasRouterCall || !(ctx.derived.suspiciousTargets?.length) || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('intermediate_hop') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'router-recipient-flip',
      category: 'execution-abuse',
      summary: '检测到路由接收地址被未授权翻转后，经可疑路由链路导向攻击者获利',
      evidence: {
        objectLabel: recipientFlip.objectLabel,
        field: recipientFlip.field,
        anomalyKind: recipientFlip.anomalyKind,
        suspiciousTargets: ctx.derived.suspiciousTargets,
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
