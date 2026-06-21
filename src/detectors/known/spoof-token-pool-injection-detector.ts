import type { AttackDetectorContext, AttackFinding } from '../types.js';

/**
 * 伪造代币注入流动性池检测器
 *
 * Cetus $223M 攻击的预设置阶段：攻击者在同一 PTB 内：
 * 1. 发布（publish）一个新合约，创建 Coin 类型（BULLA、MOJO 等廉价代币）
 * 2. 立即将该新代币与蓝筹资产（SUI、USDC、USDT）配对注入流动性池
 *
 * 这是攻击前的"伪装流动性"布局，目的是让池子接受攻击代币作为配对资产，
 * 随后通过价格操纵套取真实资金。
 *
 * 检测信号：
 * 1. 同一 PTB 中存在包发布事件（新 package 对象创建）
 * 2. 紧接着调用了 CLMM 或 AMM 的 create_pool / add_liquidity 函数
 * 3. 发布包的年龄极短（刚创建）即进入池子
 */
export function detectSpoofTokenPoolInjectionAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  // 检测是否有新包发布
  const newlyPublishedPackages = ctx.tx.objectChanges.filter(
    (change) =>
      change.isPackage &&
      change.outputVersion !== undefined &&
      change.inputVersion === undefined, // inputVersion 为空表示是新发布（不是升级）
  );

  if (newlyPublishedPackages.length === 0) {
    return [];
  }

  const callNames = ctx.tx.calls.map((c) => `${c.module}::${c.function}`.toLowerCase());

  // 检测同一 PTB 是否调用了池子创建或流动性注入函数
  const hasPoolInjection = callNames.some((name) =>
    [
      'create_pool',
      'new_pool',
      'initialize_pool',
      'add_liquidity',
      'provide_liquidity',
      'open_position',
      'mint_position',
    ].some((kw) => name.includes(kw)),
  );

  if (!hasPoolInjection) {
    return [];
  }

  // 检测是否还包含代币铸造（新 coin 发布后立即 mint）
  const hasMint = callNames.some((name) =>
    ['mint', 'create_currency', 'new_unsupported_token', 'init_supply'].some((kw) => name.includes(kw)),
  );

  // 新 package 发布 + 立即注入流动性池 = 极高风险
  return [
    {
      attackType: 'spoof-token-pool-injection',
      category: 'liquidity-drain',
      summary:
        '检测到同一 PTB 中新发布合约后立即注入流动性池（伪造代币注入模式）：攻击者可能用廉价代币配对蓝筹资产来操纵池子',
      evidence: {
        sender: ctx.tx.sender,
        newlyPublishedPackages: newlyPublishedPackages.map((c) => ({
          address: c.address,
          outputVersion: c.outputVersion,
        })),
        hasPoolInjectionCall: hasPoolInjection,
        hasMintCall: hasMint,
        callSequence: ctx.tx.calls.map((c) => `${c.module}::${c.function}`),
      },
      riskHints: {
        scoreDelta: hasMint ? 35 : 25,
        severityFloor: 'high',
      },
      chainHints: {
        stage: 'manipulation',
      },
    },
  ];
}
