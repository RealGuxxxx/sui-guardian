import type { ObservedTransaction } from '../types.js';
import type { SuiGraphqlClient } from '../graphql-client.js';

export interface WindowStats {
  windowDays: number;
  sampledCheckpoints: number;
  sampledTransactions: number;
  callCounts: Record<string, { txCount: number; uniqueSenders: number; failures: number }>;
}

function keyForCall(call: { package: string; module: string; function: string }): string {
  return `${call.package}::${call.module}::${call.function}`;
}

export async function collectWindowStats(params: {
  client: SuiGraphqlClient & {
    getCheckpointHeadersAfter: (afterCheckpoint: number, limit: number) => Promise<Array<{ sequenceNumber: number; timestamp: string }>>;
    getCheckpointTransactions: (checkpoint: number, pageSize: number) => Promise<ObservedTransaction[]>;
  };
  latestCheckpoint: number;
  windowDays: number;
  maxSampledCheckpoints: number;
  pageSize: number;
}): Promise<WindowStats> {
  const sampleSize = 2000;
  const sampleStart = Math.max(0, params.latestCheckpoint - sampleSize);
  const headers = await params.client.getCheckpointHeadersAfter(sampleStart, sampleSize);
  const first = headers[0];
  const last = headers[headers.length - 1];
  const firstMs = first ? Date.parse(first.timestamp) : Date.now() - 2_000;
  const lastMs = last ? Date.parse(last.timestamp) : Date.now();
  const secondsPerCheckpoint = headers.length > 1
    ? Math.max(1, (lastMs - firstMs) / 1000 / (headers.length - 1))
    : 2;
  const needed = Math.ceil((params.windowDays * 24 * 3600) / secondsPerCheckpoint);
  const stride = Math.max(1, Math.ceil(needed / params.maxSampledCheckpoints));
  const startCheckpoint = Math.max(0, params.latestCheckpoint - needed);

  const callCounts: Record<string, { txCount: number; uniqueSenders: Set<string>; failures: number }> = {};
  let sampledTransactions = 0;
  let sampledCheckpoints = 0;

  for (let checkpoint = startCheckpoint; checkpoint <= params.latestCheckpoint; checkpoint += stride) {
    sampledCheckpoints += 1;
    const transactions = await params.client.getCheckpointTransactions(checkpoint, params.pageSize);
    sampledTransactions += transactions.length;
    for (const tx of transactions) {
      for (const call of tx.calls) {
        const key = keyForCall(call);
        const existing = callCounts[key] ?? { txCount: 0, uniqueSenders: new Set<string>(), failures: 0 };
        existing.txCount += 1;
        if (tx.sender) {
          existing.uniqueSenders.add(tx.sender);
        }
        if (tx.status === 'FAILURE') {
          existing.failures += 1;
        }
        callCounts[key] = existing;
      }
    }
  }

  return {
    windowDays: params.windowDays,
    sampledCheckpoints,
    sampledTransactions,
    callCounts: Object.fromEntries(Object.entries(callCounts).map(([key, value]) => [
      key,
      {
        txCount: value.txCount,
        uniqueSenders: value.uniqueSenders.size,
        failures: value.failures,
      },
    ])),
  };
}

