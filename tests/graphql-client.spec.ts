import { describe, expect, it } from 'vitest';

import { SuiGraphqlClient } from '../src/graphql-client.js';

describe('SuiGraphqlClient', () => {
  it('handles null GraphQL nodes for balance and object changes', async () => {
    const client = new SuiGraphqlClient('https://example.invalid');

    const request = async () => ({
      checkpoint: {
        sequenceNumber: 123,
        timestamp: '2026-04-24T12:00:00.000Z',
        transactions: {
          pageInfo: {
            hasNextPage: false,
            endCursor: null,
          },
          nodes: [
            {
              digest: 'tx-1',
              sender: { address: '0x1' },
              gasInput: null,
              transactionJson: null,
              effects: {
                status: 'SUCCESS' as const,
                executionError: null,
                balanceChanges: null,
                objectChanges: null,
              },
            },
          ],
        },
      },
    });

    Object.assign(client, {
      request,
    });

    const transactions = await client.getCheckpointTransactions(123, 10);

    expect(transactions).toHaveLength(1);
    expect(transactions[0]?.balanceChanges).toEqual([]);
    expect(transactions[0]?.objectChanges).toEqual([]);
  });
});
