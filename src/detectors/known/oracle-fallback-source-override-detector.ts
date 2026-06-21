import type { AttackDetectorContext, AttackFinding } from '../types.js';

const FALLBACK_SOURCE_KEYWORDS = ['fallback_source', 'backup_source', 'source_override', 'fallback_provider'];

export function detectOracleFallbackSourceOverrideAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const fallbackShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && FALLBACK_SOURCE_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrSwapCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('swap');
  });
  const flow = ctx.derived.flowEvidence;

  if (!fallbackShift || !hasBorrowOrSwapCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-fallback-source-override',
      category: 'price-manipulation',
      summary: '检测到 oracle fallback 价格来源被重写后紧随借贷或成交提取',
      evidence: {
        objectLabel: fallbackShift.objectLabel,
        field: fallbackShift.field,
        anomalyKind: fallbackShift.anomalyKind,
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
