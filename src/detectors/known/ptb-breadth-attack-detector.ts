import type { AttackDetectorContext, AttackFinding } from '../types.js';

/**
 * PTB 广度攻击检测器
 *
 * Cetus $223M 攻击的核心特征之一：攻击者在 **单个 PTB** 内对 200+ 个不同的流动性池
 * 调用相同的函数序列（add_liquidity + remove_liquidity）。
 *
 * 与一般的"重复调用"不同，广度攻击的特征是：
 * - 相同函数名被调用 >= 8 次（高频）
 * - 或总 moveCall 数量 >= 20（超大型 PTB）
 * - 且存在价值提取信号
 *
 * 这一模式对于正常用户行为极不寻常——正常的批量操作（如 DEX 路由）
 * 不会在同一函数上反复调用超过 10 次。
 *
 * 适用于：
 * - Cetus 攻击模式（CLMM 池广度提取）
 * - 任何"横扫全网池子"的批量攻击
 */

// 单一函数被调用次数的告警阈值
const SINGLE_FN_REPEAT_THRESHOLD = 8;
// PTB 总调用数的告警阈值（超大型 PTB）
const TOTAL_CALLS_THRESHOLD = 30;
// 高频模式下的阈值（更激进，需要其他信号支撑）
const HIGH_FREQ_THRESHOLD = 15;

export function detectPtbBreadthAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const calls = ctx.tx.calls;

  if (calls.length < SINGLE_FN_REPEAT_THRESHOLD) {
    return [];
  }

  // 统计每个函数名的调用次数
  const fnCallCounts = new Map<string, number>();
  for (const call of calls) {
    const key = `${call.module}::${call.function}`;
    fnCallCounts.set(key, (fnCallCounts.get(key) ?? 0) + 1);
  }

  // 找出超阈值的重复函数
  const highFreqFunctions = [...fnCallCounts.entries()]
    .filter(([, count]) => count >= SINGLE_FN_REPEAT_THRESHOLD)
    .sort(([, a], [, b]) => b - a);

  // 是否是 CLMM 相关函数（高置信度攻击特征）
  const isClmmRelated = highFreqFunctions.some(([fn]) =>
    ['add_liquidity', 'remove_liquidity', 'open_position', 'close_position', 'mint_position', 'burn_position'].some(
      (kw) => fn.toLowerCase().includes(kw),
    ),
  );

  // 超大 PTB（30+ moveCall），即使没有单个函数高频，也值得关注
  const isGiantPtb = calls.length >= TOTAL_CALLS_THRESHOLD;

  // 必须有高频函数或超大 PTB
  if (highFreqFunctions.length === 0 && !isGiantPtb) {
    return [];
  }

  // 需要价值提取信号（减少误报）
  const flow = ctx.derived.flowEvidence;
  const hasExtraction =
    ctx.derived.valueExtractionDetected ||
    flow?.attackPathFound === true ||
    BigInt(flow?.netProtectedOutflow ?? '0') > BigInt(0);

  // 超大 PTB + CLMM 即使没有提取信号也告警（Cetus 攻击前期）
  const skipExtractionCheck = isGiantPtb && isClmmRelated;

  if (!hasExtraction && !skipExtractionCheck) {
    return [];
  }

  const maxRepeat = highFreqFunctions[0]?.[1] ?? calls.length;
  const topFn = highFreqFunctions[0]?.[0] ?? 'unknown';

  return [
    {
      attackType: 'ptb-breadth-attack',
      category: 'liquidity-drain',
      summary: isClmmRelated
        ? `检测到 PTB 内对 CLMM 函数 ${topFn} 的广度攻击（重复 ${maxRepeat} 次），这是 Cetus $223M 攻击的核心特征`
        : `检测到异常大型 PTB（${calls.length} 次 moveCall，函数 ${topFn} 重复 ${maxRepeat} 次），疑似批量广度攻击`,
      evidence: {
        sender: ctx.tx.sender,
        totalCallCount: calls.length,
        highFrequencyFunctions: Object.fromEntries(highFreqFunctions),
        isClmmRelated,
        isGiantPtb,
        netProtectedOutflow: flow?.netProtectedOutflow ?? '0',
        netAttackerGain: flow?.netAttackerGain ?? '0',
      },
      riskHints: {
        scoreDelta: isClmmRelated ? 40 : maxRepeat >= HIGH_FREQ_THRESHOLD ? 30 : 20,
        severityFloor: isClmmRelated ? 'critical' : 'high',
      },
      chainHints: {
        stage: 'extraction',
      },
    },
  ];
}
