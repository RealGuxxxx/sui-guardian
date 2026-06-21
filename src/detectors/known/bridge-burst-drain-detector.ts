import type { AttackDetectorContext, AttackFinding } from '../types.js';

/**
 * 桥接爆发性提款检测器
 *
 * Cetus $223M 攻击的资金转移阶段：
 * 攻击者以每 30 秒约 $100 万的速度，通过 Wormhole/CCTP 将 USDC 桥接到以太坊。
 * 爆发性的跨链转账是攻击者在链上价值提取后迅速将资金转出 Sui 网络的标志。
 *
 * 检测信号：
 * 1. 当前交易调用了桥接协议（Wormhole、CCTP、LayerZero 等）
 * 2. 同一发送方在短窗口内（依赖 recentAlerts 计数）已多次触发桥接告警
 * 3. 当前交易存在大额代币外流
 *
 * 注意：单次大额桥接可能是正常行为，需要结合频率和之前的资金来源判断。
 */

// 桥接协议函数关键词
const BRIDGE_FUNCTION_PATTERNS = [
  'transfer_tokens',         // Wormhole
  'deposit_for_burn',        // CCTP (Circle)
  'send_tokens',
  'bridge_out',
  'bridge_transfer',
  'cross_chain_transfer',
  'lock_and_mint',
  'burn_and_release',
  'send_message',            // LayerZero
  'lz_send',
  'portal_transfer',
  'outbound_transfer',
];

// 最小桥接金额阈值（MIST，约 $1000 等值）
const MIN_BRIDGE_AMOUNT_MIST = BigInt(1_000_000_000);

export function detectBridgeBurstDrainAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const callNames = ctx.tx.calls.map((c) => `${c.module}::${c.function}`.toLowerCase());

  // 检测当前交易是否调用了桥接函数
  const bridgeCalls = ctx.tx.calls.filter((call) =>
    BRIDGE_FUNCTION_PATTERNS.some((pattern) => call.function.toLowerCase().includes(pattern)),
  );

  if (bridgeCalls.length === 0) {
    return [];
  }

  // 检测是否有大额余额变化（外流）
  const largeOutflow = ctx.tx.balanceChanges.some((change) => {
    // 代币外流（负值）且超过阈值
    try {
      return BigInt(change.amount) < -MIN_BRIDGE_AMOUNT_MIST;
    } catch {
      return false;
    }
  });

  if (!largeOutflow) {
    return [];
  }

  // 检查最近是否已有来自相同发送方的桥接告警（短窗口重复行为）
  const sender = ctx.tx.sender;
  const recentBridgeAlerts = ctx.runtime.recentAlerts.filter((alert) => {
    const details = alert.details as Record<string, unknown>;
    return (
      (alert.ruleId.includes('bridge') || String(details['attackType'] ?? '').includes('bridge')) &&
      details['sender'] === sender
    );
  });

  // 第一次大额桥接：低置信度告警
  // 重复桥接（同一发送方在短窗口内 >= 2 次）：高置信度告警
  const isBurst = recentBridgeAlerts.length >= 1;

  // 计算总外流（所有代币）
  const totalOutflow = ctx.tx.balanceChanges
    .filter((change) => {
      try {
        return BigInt(change.amount) < BigInt(0);
      } catch {
        return false;
      }
    })
    .reduce((sum, change) => {
      try {
        return sum + (-BigInt(change.amount));
      } catch {
        return sum;
      }
    }, BigInt(0));

  return [
    {
      attackType: 'bridge-burst-drain',
      category: 'liquidity-drain',
      summary: isBurst
        ? `检测到同一地址短时间内连续多次大额跨链桥接（爆发性提款模式，共 ${recentBridgeAlerts.length + 1} 次），可能是攻击后资金快速转移`
        : '检测到大额跨链桥接，与近期告警结合可能是攻击资金转移的早期迹象',
      evidence: {
        sender,
        bridgeCallCount: bridgeCalls.length,
        bridgeCalls: bridgeCalls.map((c) => `${c.module}::${c.function}`),
        totalOutflowMist: totalOutflow.toString(),
        recentBridgeAlertCount: recentBridgeAlerts.length,
        isBurst,
        callSequence: callNames,
      },
      riskHints: {
        scoreDelta: isBurst ? 35 : 15,
        severityFloor: isBurst ? 'critical' : 'medium',
      },
      chainHints: {
        stage: 'extraction',
      },
    },
  ];
}
