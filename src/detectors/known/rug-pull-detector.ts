import type { AttackDetectorContext, AttackFinding } from '../types.js';

/**
 * Rug Pull 检测器
 *
 * 检测模式：同一交易中出现 package 升级（版本号变化）+ 受保护地址大额资金流出。
 * 这是典型的"升级后跑路"攻击：攻击者控制升级权限后，通过升级合约逻辑绕过限制，
 * 随即提取资金。
 */
export function detectRugPullAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  // 检查本次交易是否包含 package 升级（isPackage 且版本发生变化）
  const hasPackageUpgrade = ctx.tx.objectChanges.some(
    (change) =>
      change.isPackage &&
      change.outputVersion !== undefined &&
      change.inputVersion !== undefined &&
      change.outputVersion > change.inputVersion,
  );

  if (!hasPackageUpgrade) {
    return [];
  }

  // 检查同一交易内是否存在受保护地址的大额资金流出
  const flow = ctx.derived.flowEvidence;
  const hasProtectedOutflow =
    flow?.attackPathFound === true ||
    (BigInt(flow?.netProtectedOutflow ?? '0') > BigInt(0) && ctx.derived.valueExtractionDetected);

  if (!hasProtectedOutflow) {
    return [];
  }

  const protectedOutflow = flow?.netProtectedOutflow ?? '0';
  const attackerGain = flow?.netAttackerGain ?? '0';

  return [
    {
      attackType: 'rug-pull',
      category: 'governance',
      summary: '检测到 package 升级后立即发生受保护资金提取，疑似 rug pull 攻击',
      evidence: {
        upgradedPackages: ctx.tx.objectChanges
          .filter(
            (change) =>
              change.isPackage &&
              change.outputVersion !== undefined &&
              change.inputVersion !== undefined &&
              change.outputVersion > change.inputVersion,
          )
          .map((change) => ({
            address: change.address,
            inputVersion: change.inputVersion,
            outputVersion: change.outputVersion,
          })),
        sender: ctx.tx.sender,
        netProtectedOutflow: protectedOutflow,
        netAttackerGain: attackerGain,
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
