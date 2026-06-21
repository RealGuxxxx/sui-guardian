import { describe, expect, it, vi } from 'vitest';

import { renderDashboard } from '../src/dashboard.js';
import { MonitorService } from '../src/monitor-service.js';
import type { AppConfig, RuntimeState } from '../src/types.js';

const config: AppConfig = {
  network: {
    name: 'testnet',
    graphqlEndpoint: 'https://graphql.testnet.sui.io/graphql',
    pollIntervalMs: 5000,
    bootstrapLookbackCheckpoints: 10,
    checkpointOverlap: 2,
    maxCheckpointsPerTick: 5,
    maxTransactionsPerPage: 20,
  },
  storage: {
    stateFile: '.data/test-monitor-service-state.json',
    maxAlerts: 100,
  },
  server: {
    host: '127.0.0.1',
    port: 3000,
  },
  alerts: {
    console: true,
  },
  projects: [
    {
      id: 'demo',
      name: 'Demo',
      packages: [],
      protectedAddresses: [],
      functionGuards: [],
      trafficSpikes: [],
      failureSpikes: [],
      trackedObjects: [],
      suspiciousTargets: [
        {
          label: 'rogue-router',
          address: '0x1111111111111111111111111111111111111111111111111111111111111111',
        },
      ],
      behaviorRules: {
        enabled: true,
        minRepeatedCalls: 3,
        minProtectedOutflow: '250',
        priceDeviationThresholdBps: 1800,
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

const emptyConfig: AppConfig = {
  network: {
    name: 'mainnet',
    graphqlEndpoint: 'https://graphql.mainnet.sui.io/graphql',
    pollIntervalMs: 5000,
    bootstrapLookbackCheckpoints: 5,
    checkpointOverlap: 3,
    maxCheckpointsPerTick: 5,
    maxTransactionsPerPage: 20,
  },
  storage: {
    stateFile: '.data/test-empty-monitor-service-state.json',
    maxAlerts: 50,
  },
  server: {
    host: '127.0.0.1',
    port: 3001,
  },
  alerts: {
    console: false,
  },
  projects: [],
};

describe('MonitorService config summary', () => {
  it('includes behavior rule summary and suspicious targets', () => {
    const service = new MonitorService(config);
    const summary = service.getConfigSummary() as {
      projects: Array<{
        behaviorRules?: {
          enabled: boolean;
          minRepeatedCalls: number;
          minProtectedOutflow: string;
          priceDeviationThresholdBps: number;
        };
        suspiciousTargets?: Array<{ label: string; address: string }>;
        priceModelCount?: number;
        objectBaselineCount?: number;
        suppressionEnabled?: boolean;
      }>;
    };

    expect(summary.projects[0]?.behaviorRules?.enabled).toBe(true);
    expect(summary.projects[0]?.behaviorRules?.minRepeatedCalls).toBe(3);
    expect(summary.projects[0]?.behaviorRules?.priceDeviationThresholdBps).toBe(1800);
    expect(summary.projects[0]?.suspiciousTargets).toHaveLength(1);
    expect(summary.projects[0]?.priceModelCount).toBe(0);
    expect(summary.projects[0]?.objectBaselineCount).toBe(0);
    expect(summary.projects[0]?.suppressionEnabled).toBe(true);
  });

  it('renders dashboard copy for behavior rules', () => {
    const html = renderDashboard();
    expect(html).toContain('行为规则');
    expect(html).toContain('攻击行为态势');
    expect(html).toContain('受影响地址');
    expect(html).toContain('Digest');
    expect(html).toContain('字段变化');
    expect(html).toContain('资金路径');
    expect(html).toContain('风险评分');
    expect(html).toContain('抑制原因');
    expect(html).toContain('攻击者聚类');
    expect(html).toContain('剧本标签');
    expect(html).toContain('链首 Digest');
    expect(html).toContain('链尾 Digest');
    expect(html).toContain('攻击跨度');
    expect(html).toContain('关联置信度');
    expect(html).toContain('价格模型');
    expect(html).toContain('字段基线');
    expect(html).toContain('尚未配置真实监控项目');
    expect(html).toContain('暂无真实攻击事件');
    expect(html).toContain('暂无真实关键对象数据');
    expect(html).not.toContain('暂无项目配置');
    expect(html).not.toContain('尚未产生行为类告警');
  });

  it('returns empty real-data views when no project is configured', () => {
    const service = new MonitorService(emptyConfig) as unknown as {
      getIncidentTimeline: (limit?: number) => unknown[];
      getAssets: (projectId?: string) => unknown[];
      getAlerts: () => unknown[];
      getConfigSummary: () => {
        projects: unknown[];
      };
      state: RuntimeState;
    };

    service.state = {
      lastCheckpoint: 0,
      packageVersions: {},
      trackedObjectSnapshots: {},
      priceReferenceProfiles: {},
      objectBaselineProfiles: {},
      recentTransactionDigests: [],
      recentAlerts: [],
      scanHistory: [],
      updatedAt: '2026-04-24T00:00:00.000Z',
    };

    expect(service.getConfigSummary().projects).toEqual([]);
    expect(service.getIncidentTimeline()).toEqual([]);
    expect(service.getAssets()).toEqual([]);
    expect(service.getAlerts()).toEqual([]);
  });

  it('aggregates behavior alerts into metrics', () => {
    const service = new MonitorService(config) as unknown as {
      getMetrics: () => Record<string, unknown>;
      state: RuntimeState;
    };

    service.state = {
      lastCheckpoint: 123,
      packageVersions: {},
      trackedObjectSnapshots: {},
      priceReferenceProfiles: {},
      objectBaselineProfiles: {},
      recentTransactionDigests: [],
      recentAlerts: [
        {
          id: '1',
          createdAt: '2026-04-24T00:00:00.000Z',
          projectId: 'demo',
          projectName: 'Demo',
          ruleId: 'behavior:flashloan-like-attack',
          ruleName: '行为规则 / 闪电贷式攻击闭环',
          severity: 'critical',
          summary: 'flashloan-like',
          details: {},
          fingerprint: 'fp-1',
          status: 'open',
          firstSeenAt: '2026-04-24T00:00:00.000Z',
          lastSeenAt: '2026-04-24T00:00:01.000Z',
          updatedAt: '2026-04-24T00:00:01.000Z',
          occurrences: 2,
        },
        {
          id: '2',
          createdAt: '2026-04-24T00:00:02.000Z',
          projectId: 'demo',
          projectName: 'Demo',
          ruleId: 'behavior:flashloan-like-attack',
          ruleName: '行为规则 / 闪电贷式攻击闭环',
          severity: 'high',
          summary: 'flashloan-like',
          details: {},
          fingerprint: 'fp-2',
          status: 'acknowledged',
          firstSeenAt: '2026-04-24T00:00:02.000Z',
          lastSeenAt: '2026-04-24T00:00:03.000Z',
          updatedAt: '2026-04-24T00:00:03.000Z',
          occurrences: 1,
        },
        {
          id: '3',
          createdAt: '2026-04-24T00:00:04.000Z',
          projectId: 'demo',
          projectName: 'Demo',
          ruleId: 'address-outflow:demo',
          ruleName: '资金异常流出检测',
          severity: 'high',
          summary: 'outflow',
          details: {},
          fingerprint: 'fp-3',
          status: 'open',
          firstSeenAt: '2026-04-24T00:00:04.000Z',
          lastSeenAt: '2026-04-24T00:00:05.000Z',
          updatedAt: '2026-04-24T00:00:05.000Z',
          occurrences: 1,
        },
      ],
      scanHistory: [],
      updatedAt: '2026-04-24T00:00:06.000Z',
    };

    const metrics = service.getMetrics() as {
      behavior?: {
        total: number;
        openCritical: number;
        topRules: Array<{ ruleName: string; count: number }>;
      };
    };

    expect(metrics.behavior?.total).toBe(2);
    expect(metrics.behavior?.openCritical).toBe(1);
    expect(metrics.behavior?.topRules[0]).toEqual({
      ruleName: '行为规则 / 闪电贷式攻击闭环',
      count: 2,
    });
  });

  it('groups behavior alerts into timeline incidents', () => {
    const service = new MonitorService(config) as unknown as {
      getIncidentTimeline: (limit?: number) => Array<{
        incidentId: string;
        projectName: string;
        severity: string;
        status: string;
        alertCount: number;
        ruleNames: string[];
        digests: string[];
        senders: string[];
        affectedAddresses: string[];
        categories: string[];
        fieldChanges: Array<{
          address: string;
          field: string;
          previousValue: string;
          currentValue: string;
        }>;
        fundFlows: Array<{
          address: string;
          coinType: string;
          amount: string;
        }>;
        riskScore?: number;
        suppressionReasons?: string[];
        attackTypes?: string[];
        chainStages?: string[];
        chainPath?: string[];
        attackerClusterKey?: string;
        playbookLabels?: string[];
        chainStartDigest?: string;
        chainEndDigest?: string;
        chainWindowSeconds?: number;
        correlationConfidence?: number;
      }>;
      state: RuntimeState;
    };

    service.state = {
      lastCheckpoint: 200,
      packageVersions: {},
      trackedObjectSnapshots: {},
      priceReferenceProfiles: {},
      objectBaselineProfiles: {},
      recentTransactionDigests: [],
      recentAlerts: [
        {
          id: 'b1',
          createdAt: '2026-04-24T01:00:00.000Z',
          projectId: 'demo',
          projectName: 'Demo',
          ruleId: 'behavior:flashloan-like-attack',
          ruleName: '行为规则 / 闪电贷式攻击闭环',
          severity: 'critical',
          summary: 'flash attack',
          details: {
            digest: 'tx-1',
            sender: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            suspiciousTargets: ['0x1111111111111111111111111111111111111111111111111111111111111111'],
            riskScore: 91,
            suppressionReasons: ['weak_single_signal_suppression'],
            attackFindings: [
              {
                attackType: 'oracle-price-manipulation',
                category: 'price-manipulation',
                summary: 'price attack',
                evidence: {},
                chainHints: {
                  stage: 'manipulation',
                },
              },
              {
                attackType: 'flash-loan-sequence',
                category: 'liquidity-drain',
                summary: 'flash-funded manipulation chain',
                evidence: {},
                chainHints: {
                  stage: 'manipulation',
                },
              },
            ],
          },
          fingerprint: 'fp-b1',
          status: 'open',
          firstSeenAt: '2026-04-24T01:00:00.000Z',
          lastSeenAt: '2026-04-24T01:00:20.000Z',
          updatedAt: '2026-04-24T01:00:20.000Z',
          occurrences: 1,
        },
        {
          id: 'b2',
          createdAt: '2026-04-24T01:01:00.000Z',
          projectId: 'demo',
          projectName: 'Demo',
          ruleId: 'behavior:price-manipulation',
          ruleName: '行为规则 / 价格操纵后价值提取',
          severity: 'high',
          summary: 'price attack',
          details: {
            digest: 'tx-2',
            sender: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            address: '0x2222222222222222222222222222222222222222222222222222222222222222',
            riskScore: 82,
            suppressionReasons: [],
          },
          fingerprint: 'fp-b2',
          status: 'acknowledged',
          firstSeenAt: '2026-04-24T01:01:00.000Z',
          lastSeenAt: '2026-04-24T01:01:10.000Z',
          updatedAt: '2026-04-24T01:01:10.000Z',
          occurrences: 1,
        },
        {
          id: 'b3',
          createdAt: '2026-04-24T01:12:00.000Z',
          projectId: 'demo',
          projectName: 'Demo',
          ruleId: 'behavior:suspicious-target-call',
          ruleName: '行为规则 / 可疑外部目标调用',
          severity: 'medium',
          summary: 'target attack',
          details: {
            digest: 'tx-3',
            sender: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            suspiciousTargets: ['0x3333333333333333333333333333333333333333333333333333333333333333'],
          },
          fingerprint: 'fp-b3',
          status: 'resolved',
          firstSeenAt: '2026-04-24T01:12:00.000Z',
          lastSeenAt: '2026-04-24T01:12:10.000Z',
          updatedAt: '2026-04-24T01:12:10.000Z',
          occurrences: 1,
        },
        {
          id: 'o1',
          createdAt: '2026-04-24T01:01:30.000Z',
          projectId: 'demo',
          projectName: 'Demo',
          ruleId: 'tracked-object-critical:pool-1:price',
          ruleName: '关键对象字段异常变化',
          severity: 'critical',
          summary: 'pool price changed',
          details: {
            address: '0x4444444444444444444444444444444444444444444444444444444444444444',
            field: 'price',
            previousValue: '100',
            currentValue: '180',
          },
          fingerprint: 'fp-o1',
          status: 'open',
          firstSeenAt: '2026-04-24T01:01:30.000Z',
          lastSeenAt: '2026-04-24T01:01:50.000Z',
          updatedAt: '2026-04-24T01:01:50.000Z',
          occurrences: 1,
        },
        {
          id: 'f1',
          createdAt: '2026-04-24T01:01:40.000Z',
          projectId: 'demo',
          projectName: 'Demo',
          ruleId: 'address-outflow:0x5555555555555555555555555555555555555555555555555555555555555555:0x2::sui::SUI',
          ruleName: '资金异常流出检测',
          severity: 'high',
          summary: 'vault outflow',
          details: {
            address: '0x5555555555555555555555555555555555555555555555555555555555555555',
            coinType: '0x2::sui::SUI',
            rawOutflow: '9000000000',
            sender: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            digest: 'tx-4',
          },
          fingerprint: 'fp-f1',
          status: 'open',
          firstSeenAt: '2026-04-24T01:01:40.000Z',
          lastSeenAt: '2026-04-24T01:01:55.000Z',
          updatedAt: '2026-04-24T01:01:55.000Z',
          occurrences: 1,
        },
        {
          id: 'b4',
          createdAt: '2026-04-24T01:03:00.000Z',
          projectId: 'demo',
          projectName: 'Demo',
          ruleId: 'behavior:unauthorized-sensitive:emergency-withdraw',
          ruleName: '行为规则 / 非授权敏感函数调用',
          severity: 'critical',
          summary: 'other attacker',
          details: {
            digest: 'tx-5',
            sender: '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
            address: '0x6666666666666666666666666666666666666666666666666666666666666666',
          },
          fingerprint: 'fp-b4',
          status: 'open',
          firstSeenAt: '2026-04-24T01:03:00.000Z',
          lastSeenAt: '2026-04-24T01:03:10.000Z',
          updatedAt: '2026-04-24T01:03:10.000Z',
          occurrences: 1,
        },
      ],
      scanHistory: [],
      updatedAt: '2026-04-24T01:12:10.000Z',
    };

    const timeline = service.getIncidentTimeline();

    expect(timeline).toHaveLength(3);
    expect(timeline[0]?.alertCount).toBe(1);
    expect(timeline[1]?.alertCount).toBe(1);
    expect(timeline[1]?.senders).toEqual(['0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc']);
    expect(timeline[2]?.alertCount).toBe(4);
    expect(timeline[2]?.ruleNames).toContain('行为规则 / 闪电贷式攻击闭环');
    expect(timeline[2]?.ruleNames).toContain('行为规则 / 价格操纵后价值提取');
    expect(timeline[2]?.ruleNames).toContain('关键对象字段异常变化');
    expect(timeline[2]?.ruleNames).toContain('资金异常流出检测');
    expect(timeline[2]?.digests).toEqual(['tx-1', 'tx-2', 'tx-4']);
    expect(timeline[2]?.senders).toEqual(['0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']);
    expect(timeline[2]?.affectedAddresses).toContain('0x1111111111111111111111111111111111111111111111111111111111111111');
    expect(timeline[2]?.affectedAddresses).toContain('0x2222222222222222222222222222222222222222222222222222222222222222');
    expect(timeline[2]?.affectedAddresses).toContain('0x4444444444444444444444444444444444444444444444444444444444444444');
    expect(timeline[2]?.affectedAddresses).toContain('0x5555555555555555555555555555555555555555555555555555555555555555');
    expect(timeline[2]?.categories).toContain('behavior');
    expect(timeline[2]?.categories).toContain('tracked-object');
    expect(timeline[2]?.categories).toContain('fund-flow');
    expect(timeline[2]?.fieldChanges).toEqual([
      {
        address: '0x4444444444444444444444444444444444444444444444444444444444444444',
        field: 'price',
        previousValue: '100',
        currentValue: '180',
      },
    ]);
    expect(timeline[2]?.fundFlows).toEqual([
      {
        address: '0x5555555555555555555555555555555555555555555555555555555555555555',
        coinType: '0x2::sui::SUI',
        amount: '9000000000',
      },
    ]);
    expect(timeline[2]?.riskScore).toBe(91);
    expect(timeline[2]?.suppressionReasons).toEqual(['weak_single_signal_suppression']);
    expect(timeline[2]?.attackerClusterKey).toBe(
      'sender:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    );
    expect(timeline[2]?.attackTypes).toContain('oracle-price-manipulation');
    expect(timeline[2]?.attackTypes).toContain('flash-loan-sequence');
    expect(timeline[2]?.chainStages).toContain('manipulation');
    expect(timeline[2]?.chainStages).toContain('extraction');
    expect(timeline[2]?.chainPath).toEqual(['manipulation', 'extraction']);
    expect(timeline[2]?.playbookLabels).toContain('flash-loan-sequence');
    expect(timeline[2]?.playbookLabels).toContain('price-manipulation-drain');
    expect(timeline.some((item) => (item.chainStages ?? []).includes('takeover'))).toBe(true);
  });

  it('correlates multi-transaction attack chains across adjacent timeline buckets', () => {
    const service = new MonitorService(config) as unknown as {
      getIncidentTimeline: (limit?: number) => Array<{
        alertCount: number;
        digests: string[];
        senders: string[];
        attackTypes?: string[];
        chainStages?: string[];
        chainPath?: string[];
        attackerClusterKey?: string;
        playbookLabels?: string[];
        chainStartDigest?: string;
        chainEndDigest?: string;
        chainWindowSeconds?: number;
        correlationConfidence?: number;
      }>;
      state: RuntimeState;
    };

    service.state = {
      lastCheckpoint: 300,
      packageVersions: {},
      trackedObjectSnapshots: {},
      priceReferenceProfiles: {},
      objectBaselineProfiles: {},
      recentTransactionDigests: [],
      recentAlerts: [
        {
          id: 'm1',
          createdAt: '2026-04-24T01:08:00.000Z',
          projectId: 'demo',
          projectName: 'Demo',
          ruleId: 'behavior:price-manipulation',
          ruleName: '行为规则 / 价格操纵后价值提取',
          severity: 'critical',
          summary: 'stage 1',
          details: {
            digest: 'tx-m1',
            sender: '0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
            attackFindings: [
              {
                attackType: 'oracle-price-manipulation',
                category: 'price-manipulation',
                summary: 'oracle moved',
                evidence: {},
                chainHints: {
                  stage: 'manipulation',
                },
              },
            ],
          },
          fingerprint: 'fp-m1',
          status: 'open',
          firstSeenAt: '2026-04-24T01:08:00.000Z',
          lastSeenAt: '2026-04-24T01:08:10.000Z',
          updatedAt: '2026-04-24T01:08:10.000Z',
          occurrences: 1,
        },
        {
          id: 'm2',
          createdAt: '2026-04-24T01:12:00.000Z',
          projectId: 'demo',
          projectName: 'Demo',
          ruleId: 'address-outflow:demo',
          ruleName: '资金异常流出检测',
          severity: 'critical',
          summary: 'stage 2',
          details: {
            digest: 'tx-m2',
            sender: '0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
            attackFindings: [
              {
                attackType: 'attacker-profit-realization',
                category: 'liquidity-drain',
                summary: 'profit taken',
                evidence: {},
                chainHints: {
                  stage: 'extraction',
                },
              },
            ],
          },
          fingerprint: 'fp-m2',
          status: 'open',
          firstSeenAt: '2026-04-24T01:12:00.000Z',
          lastSeenAt: '2026-04-24T01:12:10.000Z',
          updatedAt: '2026-04-24T01:12:10.000Z',
          occurrences: 1,
        },
      ],
      scanHistory: [],
      updatedAt: '2026-04-24T01:12:10.000Z',
    };

    const timeline = service.getIncidentTimeline();

    expect(timeline).toHaveLength(1);
    expect(timeline[0]?.alertCount).toBe(2);
    expect(timeline[0]?.digests).toEqual(['tx-m1', 'tx-m2']);
    expect(timeline[0]?.senders).toEqual([
      '0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    ]);
    expect(timeline[0]?.attackerClusterKey).toBe(
      'sender:0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    );
    expect(timeline[0]?.attackTypes).toEqual(['attacker-profit-realization', 'oracle-price-manipulation']);
    expect(timeline[0]?.chainStages).toEqual(['extraction', 'manipulation']);
    expect(timeline[0]?.chainPath).toEqual(['manipulation', 'extraction']);
    expect(timeline[0]?.chainStartDigest).toBe('tx-m1');
    expect(timeline[0]?.chainEndDigest).toBe('tx-m2');
    expect(timeline[0]?.chainWindowSeconds).toBe(250);
    expect(timeline[0]?.correlationConfidence).toBe(0.95);
    expect(timeline[0]?.playbookLabels).toContain('multi-tx-attack-chain');
    expect(timeline[0]?.playbookLabels).toContain('price-manipulation-drain');
  });

  it('hydrates tracked snapshots and price profiles into project monitors during initialize', async () => {
    const trackedConfig: AppConfig = {
      ...config,
      projects: [
        {
          ...config.projects[0]!,
          trackedObjects: [
            {
              label: 'oracle-feed',
              address: '0x9999999999999999999999999999999999999999999999999999999999999999',
            },
          ],
          priceModels: [
            {
              label: 'oracle-price',
              trackedObjectLabel: 'oracle-feed',
              observedFieldPath: 'price',
              referenceMode: 'rolling_median',
              deviationThresholdBps: 1500,
            },
          ],
        },
      ],
    };

    const service = new MonitorService(trackedConfig) as unknown as {
      initialize: () => Promise<void>;
      monitors: Array<{
        trackedSnapshotContents: Map<string, Record<string, unknown>>;
        priceProfiles: Map<string, { medianPrice?: string }>;
      }>;
      stateStore: {
        load: () => Promise<RuntimeState>;
        save: (state: RuntimeState) => Promise<void>;
        setLastCheckpoint: (state: RuntimeState, checkpoint: number) => RuntimeState;
      };
      client: {
        getLatestCheckpoint: () => Promise<number>;
      };
    };

    const state: RuntimeState = {
      lastCheckpoint: 12,
      packageVersions: {},
      trackedObjectSnapshots: {
        '0x9999999999999999999999999999999999999999999999999999999999999999': {
          label: 'oracle-feed',
          address: '0x9999999999999999999999999999999999999999999999999999999999999999',
          projectId: 'demo',
          projectName: 'Demo',
          contents: { price: '1200' },
          updatedAt: '2026-04-24T00:00:00.000Z',
        },
      },
      priceReferenceProfiles: {
        'demo:oracle-price': {
          projectId: 'demo',
          label: 'oracle-price',
          recentObservedPrices: ['1000', '1100', '1200'],
          medianPrice: '1100',
          updatedAt: '2026-04-24T00:00:00.000Z',
        },
      },
      objectBaselineProfiles: {},
      recentTransactionDigests: [],
      recentAlerts: [],
      scanHistory: [],
      updatedAt: '2026-04-24T00:00:00.000Z',
    };

    service.stateStore = {
      load: vi.fn().mockResolvedValue(state),
      save: vi.fn().mockResolvedValue(undefined),
      setLastCheckpoint: vi.fn().mockImplementation((current, checkpoint) => ({ ...current, lastCheckpoint: checkpoint })),
    };
    service.client = {
      getLatestCheckpoint: vi.fn().mockResolvedValue(20),
    };

    await service.initialize();

    expect(service.monitors[0]?.trackedSnapshotContents.get('oracle-feed')).toEqual({ price: '1200' });
    expect(service.monitors[0]?.priceProfiles.get('oracle-price')?.medianPrice).toBe('1100');
  });

  it('includes learned profiles in asset views', () => {
    const profiledConfig: AppConfig = {
      ...config,
      projects: [
        {
          ...config.projects[0]!,
          trackedObjects: [
            {
              label: 'oracle-feed',
              address: '0x111',
            },
          ],
          priceModels: [
            {
              label: 'oracle-price',
              trackedObjectLabel: 'oracle-feed',
              observedFieldPath: 'price',
              referenceMode: 'rolling_median',
              deviationThresholdBps: 1500,
            },
          ],
        },
      ],
    };

    const service = new MonitorService(profiledConfig) as unknown as {
      getAssets: (projectId?: string) => Array<{
        label: string;
        address: string;
        priceProfiles?: Array<{ label: string; medianPrice?: string }>;
        baselineProfile?: {
          fields: Record<string, { lastValue?: string }>;
        };
      }>;
      state: RuntimeState;
    };

    service.state = {
      lastCheckpoint: 1,
      packageVersions: {},
      trackedObjectSnapshots: {
        '0x111': {
          label: 'oracle-feed',
          address: '0x111',
          projectId: 'demo',
          projectName: 'Demo',
          contents: { price: '1200' },
          updatedAt: '2026-04-24T00:00:00.000Z',
        },
      },
      priceReferenceProfiles: {
        'demo:oracle-price': {
          projectId: 'demo',
          label: 'oracle-price',
          recentObservedPrices: ['1000', '1100', '1200'],
          medianPrice: '1100',
          updatedAt: '2026-04-24T00:00:00.000Z',
        },
      },
      objectBaselineProfiles: {
        'demo:oracle-feed': {
          projectId: 'demo',
          objectLabel: 'oracle-feed',
          fields: {
            price: {
              lastValue: '1200',
            },
          },
        },
      },
      recentTransactionDigests: [],
      recentAlerts: [],
      scanHistory: [],
      updatedAt: '2026-04-24T00:00:00.000Z',
    };

    const assets = service.getAssets();

    expect(assets[0]?.priceProfiles?.[0]?.medianPrice).toBe('1100');
    expect(assets[0]?.baselineProfile?.fields.price?.lastValue).toBe('1200');
  });
});
