import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectMultiAssetDrainAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const flow = ctx.derived.flowEvidence;
  if (!ctx.derived.valueExtractionDetected || !flow?.attackPathFound) {
    return [];
  }

  const drainedCoinTypes = new Set(
    ctx.tx.balanceChanges
      .filter((change) => change.amount.startsWith('-'))
      .map((change) => change.coinType),
  );

  if (drainedCoinTypes.size < 2) {
    return [];
  }

  return [
    {
      attackType: 'multi-asset-drain',
      category: 'liquidity-drain',
      summary: '检测到单次攻击路径中多个资产种类同时从受保护侧外流',
      evidence: {
        drainedCoinTypes: [...drainedCoinTypes],
        pathRoles: flow.pathRoles,
        netProtectedOutflow: flow.netProtectedOutflow,
        netAttackerGain: flow.netAttackerGain,
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
