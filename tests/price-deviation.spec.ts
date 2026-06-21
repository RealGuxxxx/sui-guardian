import { describe, expect, it } from 'vitest';

import { detectPriceDeviation } from '../src/detection/price-deviation.js';
import type { MonitoringProjectConfig, ObservedTransaction, PriceReferenceProfile } from '../src/types.js';

const BASE_PROJECT: MonitoringProjectConfig = {
  id: 'demo',
  name: 'Demo',
  packages: [],
  protectedAddresses: [],
  functionGuards: [],
  trafficSpikes: [],
  failureSpikes: [],
  trackedObjects: [
    {
      label: 'oracle-feed',
      address: '0x1111111111111111111111111111111111111111111111111111111111111111',
    },
  ],
  suspiciousTargets: [],
  behaviorRules: {
    enabled: true,
    minRepeatedCalls: 2,
    minProtectedOutflow: '1',
    priceDeviationThresholdBps: 1500,
  },
  priceModels: [
    {
      label: 'oracle-price',
      trackedObjectLabel: 'oracle-feed',
      observedFieldPath: 'price',
      referenceMode: 'rolling_median',
      deviationThresholdBps: 1500,
    },
  ],
  objectBaselines: [],
  flowTracking: {
    enabled: true,
    minProtectedOutflow: '1',
    attackerGainThreshold: '1',
    shortWindowTxCount: 2,
  },
  suppression: {
    enabled: true,
    duplicateWindowSeconds: 600,
    weakSignalScoreThreshold: 35,
    maintenanceWindows: [],
  },
};

function buildTx(): ObservedTransaction {
  return {
    digest: 'tx-1',
    checkpoint: 1,
    timestamp: '2026-04-24T00:00:00.000Z',
    sender: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    status: 'SUCCESS',
    calls: [],
    balanceChanges: [{ owner: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', coinType: '0x2::sui::SUI', amount: '-10' }],
    objectChanges: [],
  };
}

describe('detectPriceDeviation', () => {
  it('computes deviation using rolling median when no external reference exists', () => {
    const priceProfiles: Record<string, PriceReferenceProfile> = {
      'oracle-price': {
        projectId: 'demo',
        label: 'oracle-price',
        recentObservedPrices: ['1000', '1020', '980'],
        medianPrice: '1000',
        updatedAt: '2026-04-24T00:00:00.000Z',
      },
    };

    const result = detectPriceDeviation({
      tx: buildTx(),
      project: BASE_PROJECT,
      trackedSnapshots: {
        'oracle-feed': { price: 5000 },
      },
      priceProfiles,
    });

    expect(result[0]?.deviationBps).toBe(40000);
    expect(result[0]?.referenceKind).toBe('rolling_median');
  });
});
