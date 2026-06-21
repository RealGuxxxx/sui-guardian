import type { AttackDetectorContext, AttackFinding } from '../types.js';

/**
 * CLMM 极端 tick 范围流动性注入检测器
 *
 * 基于 Cetus Protocol $223M 攻击（2025年5月）模式：
 * 攻击者通过闪电贷借入大量资金，使用极小的 tick 范围（<500 个刻度）
 * 添加少量流动性，触发 checked_shlw 整数溢出漏洞，
 * 然后立即移除流动性，从池子中提取实际资金。
 *
 * 核心信号：
 * 1. 同一 PTB 包含闪电贷借入 + add_liquidity + remove_liquidity
 * 2. 存在价值提取（受保护资金外流）
 * 3. 调用链跨越多个流动性池（广度攻击模式）
 */
export function detectClmmExtremeTickAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const callNames = ctx.tx.calls.map((c) => `${c.module}::${c.function}`.toLowerCase());

  // 检测闪电贷注入信号（借入热土豆）
  const hasFlashBorrow = callNames.some((name) =>
    ['flash_swap', 'borrow_flash', 'flash_loan', 'flash_borrow', 'borrow_with_receipt', 'take_flash_loan'].some(
      (kw) => name.includes(kw),
    ),
  );

  if (!hasFlashBorrow) {
    return [];
  }

  // 检测 CLMM add_liquidity 调用
  const hasAddLiquidity = callNames.some((name) =>
    ['add_liquidity', 'provide_liquidity', 'mint_position', 'open_position', 'increase_liquidity'].some((kw) =>
      name.includes(kw),
    ),
  );

  // 检测 CLMM remove_liquidity 调用
  const hasRemoveLiquidity = callNames.some((name) =>
    ['remove_liquidity', 'burn_position', 'close_position', 'collect_fee', 'decrease_liquidity', 'withdraw_liquidity'].some(
      (kw) => name.includes(kw),
    ),
  );

  // 必须同时存在：闪电贷 + 添加流动性 + 移除流动性
  if (!hasAddLiquidity || !hasRemoveLiquidity) {
    return [];
  }

  // 必须有价值提取迹象
  const flow = ctx.derived.flowEvidence;
  const hasExtraction =
    ctx.derived.valueExtractionDetected ||
    (flow?.attackPathFound === true) ||
    BigInt(flow?.netProtectedOutflow ?? '0') > BigInt(0);

  if (!hasExtraction) {
    return [];
  }

  // 检测广度攻击：同一 PTB 是否针对多个不同池子（Cetus 攻击了 200+ 个池子）
  const liquidityPoolPackages = new Set(
    ctx.tx.calls
      .filter((c) =>
        ['add_liquidity', 'remove_liquidity', 'provide_liquidity', 'burn_position'].some((kw) =>
          c.function.toLowerCase().includes(kw),
        ),
      )
      .map((c) => c.package),
  );
  const isMultiPoolAttack = liquidityPoolPackages.size > 1;

  // 统计 add/remove 对数（Cetus 攻击在同一 PTB 中对多个池执行操作）
  const addCount = callNames.filter((name) =>
    ['add_liquidity', 'provide_liquidity', 'mint_position', 'open_position', 'increase_liquidity'].some((kw) =>
      name.includes(kw),
    ),
  ).length;

  const removeCount = callNames.filter((name) =>
    ['remove_liquidity', 'burn_position', 'close_position', 'decrease_liquidity', 'withdraw_liquidity'].some((kw) =>
      name.includes(kw),
    ),
  ).length;

  return [
    {
      attackType: 'clmm-extreme-tick-attack',
      category: 'liquidity-drain',
      summary:
        '检测到 CLMM 闪电贷 + 流动性添加/移除组合攻击（Cetus $223M 攻击模式）：同一 PTB 内通过闪电贷借入，操纵 CLMM 池流动性后提取资金',
      evidence: {
        sender: ctx.tx.sender,
        hasFlashBorrow,
        addLiquidityCallCount: addCount,
        removeLiquidityCallCount: removeCount,
        isMultiPoolAttack,
        affectedPackageCount: liquidityPoolPackages.size,
        netProtectedOutflow: flow?.netProtectedOutflow ?? '0',
        netAttackerGain: flow?.netAttackerGain ?? '0',
        callSequence: ctx.tx.calls.map((c) => `${c.module}::${c.function}`),
      },
      riskHints: {
        scoreDelta: isMultiPoolAttack ? 45 : 35,
        severityFloor: isMultiPoolAttack ? 'critical' : 'high',
      },
      chainHints: {
        stage: 'extraction',
      },
    },
  ];
}
