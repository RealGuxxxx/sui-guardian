import { describe, expect, it } from 'vitest';

import { MonitorService } from '../src/monitor-service.js';
import type { AppConfig, IncidentAlert } from '../src/types.js';

// 直接测试 getIncidentTimeline 中的分类逻辑：通过注入预存告警来验证
function makeConfig(): AppConfig {
  return {
    network: {
      name: 'testnet',
      graphqlEndpoint: 'http://localhost:9000',
      pollIntervalMs: 5000,
      bootstrapLookbackCheckpoints: 5,
      checkpointOverlap: 3,
      maxCheckpointsPerTick: 5,
      maxTransactionsPerPage: 50,
    },
    storage: {
      stateFile: '/tmp/test-state.json',
      maxAlerts: 200,
    },
    server: { host: '0.0.0.0', port: 3001 },
    alerts: { console: false },
    projects: [],
  };
}

function makeIncidentAlert(ruleId: string, overrides: Partial<IncidentAlert> = {}): IncidentAlert {
  const now = new Date().toISOString();
  return {
    id: `test-${ruleId}`,
    createdAt: now,
    projectId: 'demo',
    projectName: 'Demo',
    ruleId,
    ruleName: ruleId,
    severity: 'high',
    summary: `Test alert: ${ruleId}`,
    details: { sender: '0x1234' },
    fingerprint: `fp-${ruleId}`,
    status: 'open',
    firstSeenAt: now,
    lastSeenAt: now,
    updatedAt: now,
    occurrences: 1,
    ...overrides,
  };
}

describe('incident timeline classification', () => {
  it('includes all rule types in the incident timeline', () => {
    const service = new MonitorService(makeConfig());

    // 注入各种类型的告警到 state
    const state = service.getState();
    const alerts: IncidentAlert[] = [
      makeIncidentAlert('behavior:price-manipulation'),
      makeIncidentAlert('tracked-object-critical:0xabc:admin'),
      makeIncidentAlert('address-outflow:0xbb:0x2::sui::SUI'),
      makeIncidentAlert('function-guard:emergency-withdraw'),
      makeIncidentAlert('package-upgrade:0x1111'),
      makeIncidentAlert('traffic-spike:hot'),
      makeIncidentAlert('failure-spike:fails'),
      makeIncidentAlert('attack:liquidity-drain'),
      makeIncidentAlert('attack:rug-pull'),
    ];

    // 通过直接修改 state（白盒测试）
    (state as { recentAlerts: IncidentAlert[] }).recentAlerts = alerts;

    const timeline = service.getIncidentTimeline(50);

    // 所有 ruleId 都应出现在 timeline 中（每条 alert 在自己的 10min bucket 内）
    const timelineRuleNames = timeline.flatMap((incident) => incident.ruleNames);
    for (const alert of alerts) {
      expect(timelineRuleNames).toContain(alert.ruleId);
    }
  });

  it('assigns correct categories to attack: ruleIds', () => {
    const service = new MonitorService(makeConfig());
    const state = service.getState();
    const now = new Date().toISOString();

    (state as { recentAlerts: IncidentAlert[] }).recentAlerts = [
      makeIncidentAlert('attack:liquidity-drain', { firstSeenAt: now, lastSeenAt: now }),
    ];

    const timeline = service.getIncidentTimeline(10);
    expect(timeline.length).toBeGreaterThan(0);
    const incident = timeline.find((item) => item.ruleNames.includes('attack:liquidity-drain'));
    expect(incident).toBeDefined();
    expect(incident?.categories).toContain('attack');
  });

  it('assigns correct categories to function-guard: ruleIds', () => {
    const service = new MonitorService(makeConfig());
    const state = service.getState();

    (state as { recentAlerts: IncidentAlert[] }).recentAlerts = [
      makeIncidentAlert('function-guard:emergency-withdraw'),
    ];

    const timeline = service.getIncidentTimeline(10);
    const incident = timeline.find((item) => item.ruleNames.includes('function-guard:emergency-withdraw'));
    expect(incident).toBeDefined();
    expect(incident?.categories).toContain('access-control');
  });

  it('assigns correct categories to package-upgrade: ruleIds', () => {
    const service = new MonitorService(makeConfig());
    const state = service.getState();

    (state as { recentAlerts: IncidentAlert[] }).recentAlerts = [
      makeIncidentAlert('package-upgrade:0x1111'),
    ];

    const timeline = service.getIncidentTimeline(10);
    const incident = timeline.find((item) => item.ruleNames.includes('package-upgrade:0x1111'));
    expect(incident).toBeDefined();
    expect(incident?.categories).toContain('governance');
  });
});
