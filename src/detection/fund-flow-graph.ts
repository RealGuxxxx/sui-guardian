import type { FundFlowGraph, ObservedTransaction } from '../types.js';
import { sameAddress } from '../utils.js';

interface FundFlowGraphContext {
  tx: ObservedTransaction;
  protectedAddresses: string[];
  attackerAddresses: string[];
}

export function buildFundFlowGraph(ctx: FundFlowGraphContext): FundFlowGraph {
  let netProtectedOutflow = 0n;
  let netAttackerGain = 0n;

  for (const change of ctx.tx.balanceChanges) {
    const amount = BigInt(change.amount);

    if (change.owner && ctx.protectedAddresses.some((address) => sameAddress(address, change.owner)) && amount < 0n) {
      netProtectedOutflow += amount * -1n;
    }

    if (change.owner && ctx.attackerAddresses.some((address) => sameAddress(address, change.owner)) && amount > 0n) {
      netAttackerGain += amount;
    }
  }

  return {
    nodes: [],
    edges: [],
    attackPathFound: netProtectedOutflow > 0n && netAttackerGain > 0n,
    pathRoles: netProtectedOutflow > 0n && netAttackerGain > 0n ? ['protected_outflow', 'attacker_receipt'] : [],
    netProtectedOutflow: netProtectedOutflow.toString(),
    netAttackerGain: netAttackerGain.toString(),
  };
}
