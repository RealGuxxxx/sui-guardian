import { describe, expect, it } from 'vitest';

import type { MonitoringProjectConfig } from '../src/types.js';
import { mergeProjectRules } from '../src/generated-rules.js';

function baseProject(): MonitoringProjectConfig {
  return {
    id: 'demo',
    name: 'Demo',
    packages: [{ label: 'p', address: '0x1', allowedUpgradeSenders: [] }],
    protectedAddresses: [
      {
        label: 'treasury',
        address: '0x2',
        outflowThresholds: { '0x2::sui::SUI': '100' },
        allowedSenders: ['0xa'],
      },
    ],
    functionGuards: [
      {
        label: 'withdraw',
        package: '0x1',
        module: 'vault',
        function: 'withdraw',
        allowedSenders: ['0xa'],
        severity: 'critical',
      },
    ],
    trafficSpikes: [],
    failureSpikes: [],
    trackedObjects: [],
    suspiciousTargets: [],
    behaviorRules: { enabled: true, minRepeatedCalls: 2, minProtectedOutflow: '1', priceDeviationThresholdBps: 1500 },
    priceModels: [],
    objectBaselines: [],
    flowTracking: { enabled: true, minProtectedOutflow: '1', attackerGainThreshold: '1', shortWindowTxCount: 2 },
    suppression: { enabled: true, duplicateWindowSeconds: 600, weakSignalScoreThreshold: 35, maintenanceWindows: [] },
  };
}

describe('mergeProjectRules', () => {
  it('does not delete base rules and unions allowlists', () => {
    const base = baseProject();
    const merged = mergeProjectRules(base, {
      functionGuards: [
        {
          label: 'withdraw',
          package: '0x1',
          module: 'vault',
          function: 'withdraw',
          allowedSenders: ['0xb'],
          severity: 'high',
        },
      ],
    });

    expect(merged.functionGuards).toHaveLength(1);
    expect(new Set(merged.functionGuards[0]!.allowedSenders)).toEqual(new Set(['0xa', '0xb']));
    expect(merged.functionGuards[0]!.severity).toBe('high');
    expect(merged.name).toBe('Demo');
    expect(merged.id).toBe('demo');
  });

  it('adds new rules by label', () => {
    const base = baseProject();
    const merged = mergeProjectRules(base, {
      trackedObjects: [
        {
          label: 'oracle',
          address: '0x99',
          watchFields: ['price'],
          criticalFields: [],
          numericDecreaseThresholds: {},
          severity: 'high',
        },
      ],
    });

    expect(merged.trackedObjects).toHaveLength(1);
    expect(merged.trackedObjects[0]!.label).toBe('oracle');
  });
});

