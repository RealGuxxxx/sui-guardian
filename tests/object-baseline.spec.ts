import { describe, expect, it } from 'vitest';

import { detectObjectBaselineAnomalies } from '../src/detection/object-baseline.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const ADMIN = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const ATTACKER = '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';

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
      label: 'admin-vault',
      address: '0x2222222222222222222222222222222222222222222222222222222222222222',
    },
  ],
  suspiciousTargets: [],
  behaviorRules: {
    enabled: true,
    minRepeatedCalls: 2,
    minProtectedOutflow: '1',
    priceDeviationThresholdBps: 1500,
  },
  priceModels: [],
  objectBaselines: [
    {
      label: 'vault-baseline',
      trackedObjectLabel: 'admin-vault',
      fields: [
        {
          path: 'admin',
          kind: 'permission',
          allowedSenders: [ADMIN],
        },
      ],
    },
  ],
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

function buildTx(sender: string): ObservedTransaction {
  return {
    digest: 'tx-1',
    checkpoint: 1,
    timestamp: '2026-04-24T00:00:00.000Z',
    sender,
    status: 'SUCCESS',
    calls: [],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectObjectBaselineAnomalies', () => {
  it('flags unauthorized permission field changes', () => {
    const result = detectObjectBaselineAnomalies({
      tx: buildTx(ATTACKER),
      project: BASE_PROJECT,
      previousSnapshots: {
        'admin-vault': { admin: ADMIN, vault: '1000' },
      },
      currentSnapshots: {
        'admin-vault': { admin: ATTACKER, vault: '1000' },
      },
    });

    expect(result[0]?.anomalyKind).toBe('permission_change');
    expect(result[0]?.senderAuthorized).toBe(false);
  });
});
