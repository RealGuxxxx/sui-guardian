import { describe, expect, it } from 'vitest';

import { buildFundFlowGraph } from '../src/detection/fund-flow-graph.js';
import type { ObservedTransaction } from '../src/types.js';

const TREASURY = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const ATTACKER = '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const SUI = '0x2::sui::SUI';

function buildTx(): ObservedTransaction {
  return {
    digest: 'tx-1',
    checkpoint: 1,
    timestamp: '2026-04-24T00:00:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [],
    balanceChanges: [
      { owner: TREASURY, coinType: SUI, amount: '-1000' },
      { owner: ATTACKER, coinType: SUI, amount: '1000' },
    ],
    objectChanges: [],
  };
}

describe('buildFundFlowGraph', () => {
  it('detects protected outflow and attacker receipt path', () => {
    const graph = buildFundFlowGraph({
      tx: buildTx(),
      protectedAddresses: [TREASURY],
      attackerAddresses: [ATTACKER],
    });

    expect(graph.attackPathFound).toBe(true);
    expect(graph.netProtectedOutflow).toBe('1000');
    expect(graph.netAttackerGain).toBe('1000');
  });
});
