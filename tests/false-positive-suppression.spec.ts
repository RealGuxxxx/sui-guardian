import { describe, expect, it } from 'vitest';

import { applyFalsePositiveSuppression } from '../src/detection/false-positive-suppression.js';
import type { MonitoringProjectConfig } from '../src/types.js';

const ADMIN = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

const project: MonitoringProjectConfig = {
  id: 'demo',
  name: 'Demo',
  packages: [],
  protectedAddresses: [],
  functionGuards: [],
  trafficSpikes: [],
  failureSpikes: [],
  trackedObjects: [],
  suspiciousTargets: [],
  behaviorRules: {
    enabled: true,
    minRepeatedCalls: 2,
    minProtectedOutflow: '1',
    priceDeviationThresholdBps: 1500,
  },
  priceModels: [],
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
    maintenanceWindows: [
      {
        label: 'ops-window',
        allowedSenders: [ADMIN],
        startHourUtc: 1,
        endHourUtc: 3,
      },
    ],
  },
};

describe('applyFalsePositiveSuppression', () => {
  it('downgrades weak single signal events during maintenance window', () => {
    const decision = applyFalsePositiveSuppression({
      tx: {
        sender: ADMIN,
        timestamp: '2026-04-24T02:30:00.000Z',
      },
      project,
      risk: {
        riskScore: 30,
        confidence: 0.3,
        recommendedSeverity: 'medium',
      },
      evidenceSummary: ['baseline:oracle-feed.mode:state_flip'],
      senderAuthorized: true,
    });

    expect(decision.applied).toBe(true);
    expect(decision.finalSeverity).toBe('low');
  });
});
