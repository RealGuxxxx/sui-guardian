import { describe, expect, it } from 'vitest';

import { SuiGraphqlClient } from '../src/graphql-client.js';
import { collectWindowStats } from '../src/ai/chain-stats.js';

describe('collectWindowStats', () => {
  it('collects aggregated call counts from a sampled window', async () => {
    const client = new SuiGraphqlClient('https://graphql.testnet.sui.io/graphql') as unknown as SuiGraphqlClient & {
      getCheckpointHeadersAfter: (afterCheckpoint: number, limit: number) => Promise<Array<{ sequenceNumber: number; timestamp: string }>>;
      getCheckpointTransactions: (checkpoint: number, pageSize: number) => Promise<any[]>;
    };

    const now = new Date().toISOString();
    client.getCheckpointHeadersAfter = async () => [
      { sequenceNumber: 1, timestamp: now },
      { sequenceNumber: 2, timestamp: now },
    ];
    client.getCheckpointTransactions = async () => [
      {
        digest: 'd',
        checkpoint: 1,
        timestamp: now,
        sender: '0x1',
        status: 'SUCCESS',
        calls: [{ package: '0x1', module: 'm', function: 'f' }],
        balanceChanges: [],
        objectChanges: [],
      },
      {
        digest: 'e',
        checkpoint: 1,
        timestamp: now,
        sender: '0x2',
        status: 'FAILURE',
        calls: [{ package: '0x1', module: 'm', function: 'f' }],
        balanceChanges: [],
        objectChanges: [],
      },
    ];

    const stats = await collectWindowStats({
      client,
      latestCheckpoint: 100,
      windowDays: 7,
      maxSampledCheckpoints: 10,
      pageSize: 20,
    });

    expect(stats.windowDays).toBe(7);
    expect(stats.callCounts['0x1::m::f']?.txCount).toBe(2);
    expect(stats.callCounts['0x1::m::f']?.uniqueSenders).toBe(2);
    expect(stats.callCounts['0x1::m::f']?.failures).toBe(1);
  });
});

