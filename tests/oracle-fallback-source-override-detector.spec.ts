import { describe, expect, it } from 'vitest';

import { detectOracleFallbackSourceOverrideAttacks } from '../src/detectors/known/oracle-fallback-source-override-detector.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PACKAGE = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ATTACKER = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

function buildProject(): MonitoringProjectConfig {
  return {
    id: 'demo',
    name: 'Demo Project',
    packages: [{ address: PACKAGE, allowedUpgradeSenders: [] }],
    protectedAddresses: [],
    functionGuards: [],
    trafficSpikes: [],
    failureSpikes: [],
    trackedObjects: [],
    suspiciousTargets: [],
    behaviorRules: {
      enabled: true,
      minRepeatedCalls: 2,
      minProtectedOutflow: '100',
      priceDeviationThresholdBps: 1500,
    },
    priceModels: [],
    objectBaselines: [],
    flowTracking: {
      enabled: true,
      minProtectedOutflow: '100',
      attackerGainThreshold: '100',
      shortWindowTxCount: 2,
    },
    suppression: {
      enabled: true,
      duplicateWindowSeconds: 600,
      weakSignalScoreThreshold: 35,
      maintenanceWindows: [],
    },
  };
}

function buildTx(): ObservedTransaction {
  return {
    digest: 'tx-53',
    checkpoint: 53,
    timestamp: '2026-04-24T00:50:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [
      { package: PACKAGE, module: 'oracle', function: 'set_fallback_source' },
      { package: PACKAGE, module: 'lending', function: 'borrow' },
    ],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('detectOracleFallbackSourceOverrideAttacks', () => {
  it('emits oracle fallback source override finding when fallback price sources are rewritten before extraction', () => {
    const findings = detectOracleFallbackSourceOverrideAttacks({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'oracle-config',
            field: 'fallback_source',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '10500',
          netAttackerGain: '10100',
        },
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings[0]?.attackType).toBe('oracle-fallback-source-override');
    expect(findings[0]?.category).toBe('price-manipulation');
    expect(findings[0]?.chainHints?.stage).toBe('takeover');
  });
});
