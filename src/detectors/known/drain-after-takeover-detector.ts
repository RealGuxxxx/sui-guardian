import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectDrainAfterTakeoverAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const permissionChange = (ctx.derived.baselineEvidence ?? []).find(
    (item) => item.anomalyKind === 'permission_change' && !item.senderAuthorized,
  );
  const flow = ctx.derived.flowEvidence;

  if (!permissionChange || !ctx.derived.valueExtractionDetected || !flow?.attackPathFound) {
    return [];
  }

  const protectedOutflow = BigInt(flow.netProtectedOutflow || '0');
  if (protectedOutflow <= 0n) {
    return [];
  }

  return [
    {
      attackType: 'drain-after-takeover',
      category: 'liquidity-drain',
      summary: '检测到权限接管信号后紧随受保护资产抽干',
      evidence: {
        objectLabel: permissionChange.objectLabel,
        field: permissionChange.field,
        netProtectedOutflow: flow.netProtectedOutflow,
        netAttackerGain: flow.netAttackerGain,
        pathRoles: flow.pathRoles,
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
