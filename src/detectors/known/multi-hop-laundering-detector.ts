import type { AttackDetectorContext, AttackFinding } from '../types.js';

/**
 * 多跳资金混淆检测器
 *
 * 检测模式：资金通过 3 条以上连续中间节点（intermediate_hop）跳转后最终进入攻击者地址。
 * 这是典型的资金洗白/混淆路径，常见于攻击者试图掩盖资金来源。
 */
export function detectMultiHopLaunderingAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const flow = ctx.derived.flowEvidence;
  if (!flow) {
    return [];
  }

  // 需要有攻击者实际获利
  if (BigInt(flow.netAttackerGain) <= BigInt(0)) {
    return [];
  }

  const edges = flow.edges;

  // 统计 intermediate_hop 边数量
  const hopEdges = edges.filter((edge) => edge.role === 'intermediate_hop');
  if (hopEdges.length < 3) {
    return [];
  }

  // 确认最终存在 attacker_receipt 边（资金确实流向攻击者）
  const hasAttackerReceipt = edges.some((edge) => edge.role === 'attacker_receipt');
  if (!hasAttackerReceipt) {
    return [];
  }

  // 收集中间节点地址（去重）
  const intermediateAddresses = Array.from(
    new Set(hopEdges.flatMap((edge) => [edge.from, edge.to])),
  ).filter((addr) => !addr.startsWith('synthetic:'));

  return [
    {
      attackType: 'multi-hop-laundering',
      category: 'execution-abuse',
      summary: `检测到资金通过 ${hopEdges.length} 跳中间节点混淆后转入攻击者地址`,
      evidence: {
        hopCount: hopEdges.length,
        intermediateAddresses,
        netAttackerGain: flow.netAttackerGain,
        netProtectedOutflow: flow.netProtectedOutflow,
        sender: ctx.tx.sender,
        hopEdges: hopEdges.map((edge) => ({
          from: edge.from,
          to: edge.to,
          coinType: edge.coinType,
          amount: edge.amount,
        })),
      },
      riskHints: {
        scoreDelta: 25,
        severityFloor: 'high',
      },
      chainHints: {
        stage: 'extraction',
      },
    },
  ];
}
