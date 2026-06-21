import type { AttackDetectorContext, AttackFinding } from '../types.js';

const FALLBACK_FIELD_KEYWORDS = ['fallback', 'backup_price', 'frozen', 'freeze'];

export function detectOracleFallbackFreezeThenLiquidateAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const fallbackShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && FALLBACK_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasLiquidationCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('liquidat');
  });
  const flow = ctx.derived.flowEvidence;

  if (!fallbackShift || !hasLiquidationCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-fallback-freeze-then-liquidate',
      category: 'liquidation',
      summary: '检测到 oracle fallback 定价路径被冻结后紧随异常清算并形成攻击者获利',
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
        stage: 'extraction',
      },
    },
  ];
}
