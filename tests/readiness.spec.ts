import { describe, expect, it } from 'vitest';

import { buildSubmissionReadiness } from '../src/readiness.js';
import type { AppConfig, RuntimeState } from '../src/types.js';

const ADDRESS_1 = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ADDRESS_2 = '0x2222222222222222222222222222222222222222222222222222222222222222';
const ADDRESS_3 = '0x3333333333333333333333333333333333333333333333333333333333333333';

function emptyState(): RuntimeState {
  return {
    lastCheckpoint: 0,
    packageVersions: {},
    trackedObjectSnapshots: {},
    priceReferenceProfiles: {},
    objectBaselineProfiles: {},
    flowHistory: {},
    recentTransactionDigests: [],
    recentAlerts: [],
    scanHistory: [],
    updatedAt: '2026-05-15T00:00:00.000Z',
  };
}

function baseConfig(): AppConfig {
  return {
    network: {
      name: 'mainnet',
      graphqlEndpoint: 'https://graphql.mainnet.sui.io/graphql',
      pollIntervalMs: 3000,
      bootstrapLookbackCheckpoints: 10,
      checkpointOverlap: 3,
      maxCheckpointsPerTick: 10,
      maxTransactionsPerPage: 100,
    },
    storage: {
      stateFile: '.data/state.json',
      maxAlerts: 500,
    },
    server: {
      host: '0.0.0.0',
      port: 3000,
    },
    alerts: {
      console: true,
      webhookUrl: 'https://hooks.slack.com/services/test',
    },
    aiRules: {
      enabled: true,
      generatedDir: '.data/generated',
      reloadIntervalMs: 60_000,
      shadow: {
        enabled: true,
        notify: false,
        minMinutes: 60,
      },
      canary: {
        enabled: true,
        stage: 'shadow',
        promotionMinMinutes: 60,
      },
      generator: {
        enabled: true,
        sourceRoot: '/tmp/source',
        deploymentsDir: '.data/deployments',
        modelBaseUrl: 'https://api.openai.com',
        modelName: 'gpt-5.4',
        regenerateIntervalHours: 168,
      },
    },
    projects: [
      {
        id: 'defi-protocol',
        name: 'DeFi Protocol',
        packages: [
          {
            label: 'core',
            address: ADDRESS_1,
            allowedUpgradeSenders: [ADDRESS_3],
            deprecatedAddresses: [ADDRESS_2],
          },
        ],
        protectedAddresses: [
          {
            label: 'treasury',
            address: ADDRESS_2,
            outflowThresholds: {
              '0x2::sui::SUI': '1000000000',
            },
            allowedSenders: [ADDRESS_3],
          },
        ],
        functionGuards: [
          {
            label: 'emergency-withdraw',
            package: ADDRESS_1,
            module: 'vault',
            function: 'emergency_withdraw',
            allowedSenders: [ADDRESS_3],
            severity: 'critical',
          },
        ],
        trafficSpikes: [
          {
            label: 'hot-burst',
            package: ADDRESS_1,
            windowSeconds: 60,
            txCountThreshold: 20,
            uniqueSenderThreshold: 10,
            severity: 'high',
          },
        ],
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
          maintenanceWindows: [],
        },
      },
    ],
  };
}

describe('buildSubmissionReadiness', () => {
  it('blocks submission readiness when no real project is configured', () => {
    const config = {
      ...baseConfig(),
      projects: [],
    };

    const readiness = buildSubmissionReadiness(config, emptyState());

    expect(readiness.status).toBe('blocked');
    expect(readiness.checks.find((check) => check.id === 'real-project-config')?.status).toBe('fail');
    expect(readiness.criticalGaps.length).toBeGreaterThan(0);
  });

  it('marks a mainnet config with live scan evidence as ready', () => {
    const state = emptyState();
    state.lastCheckpoint = 100;
    state.scanHistory = [
      {
        id: 'scan-1',
        startedAt: '2026-05-15T00:00:00.000Z',
        finishedAt: '2026-05-15T00:00:02.000Z',
        latestCheckpoint: 100,
        checkpointsProcessed: 3,
        transactionsProcessed: 12,
        alertsTriggered: 1,
        durationMs: 2000,
        success: true,
      },
    ];

    const readiness = buildSubmissionReadiness(baseConfig(), state);

    expect(readiness.status).toBe('ready');
    expect(readiness.score).toBeGreaterThanOrEqual(80);
    expect(readiness.targetTrack).toBe('DeFi & Payments');
    expect(readiness.secondaryTrack).toBe('Agentic Web');
  });
});
