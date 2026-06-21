import { describe, expect, it } from 'vitest';

import { StateStore } from '../src/state-store.js';
import type { RuntimeState, ScanRecord } from '../src/types.js';
import { createAlert, nowIso } from '../src/utils.js';

function createState(): RuntimeState {
  return {
    lastCheckpoint: 0,
    packageVersions: {},
    trackedObjectSnapshots: {},
    priceReferenceProfiles: {},
    objectBaselineProfiles: {},
    recentTransactionDigests: [],
    recentAlerts: [],
    scanHistory: [],
    updatedAt: nowIso(),
  };
}

describe('StateStore', () => {
  it('merges alerts with the same projectId and ruleId into one incident', () => {
    const store = new StateStore('/tmp/test-state.json', 20);
    let state = createState();

    const first = createAlert({
      projectId: 'project-a',
      projectName: 'Project A',
      ruleId: 'traffic-spike:hot',
      ruleName: '交易热度突增检测',
      severity: 'high',
      summary: '第一次触发',
      details: { txCount: 100 },
    });
    const second = createAlert({
      projectId: 'project-a',
      projectName: 'Project A',
      ruleId: 'traffic-spike:hot',
      ruleName: '交易热度突增检测',
      severity: 'critical',
      summary: '第二次触发',
      details: { txCount: 120 },
    });

    state = store.pushAlert(state, first);
    state = store.pushAlert(state, second);

    expect(state.recentAlerts).toHaveLength(1);
    expect(state.recentAlerts[0]?.occurrences).toBe(2);
    expect(state.recentAlerts[0]?.severity).toBe('critical');
    expect(state.recentAlerts[0]?.summary).toBe('第二次触发');
  });

  it('updates alert status and reopens resolved incidents on recurrence', () => {
    const store = new StateStore('/tmp/test-state.json', 20);
    let state = createState();

    const first = createAlert({
      projectId: 'project-a',
      projectName: 'Project A',
      ruleId: 'function-guard:withdraw',
      ruleName: '高危函数越权调用检测',
      severity: 'critical',
      summary: '第一次',
      details: {},
    });

    state = store.pushAlert(state, first);
    const incidentId = state.recentAlerts[0]!.id;
    state = store.updateAlertStatus(state, incidentId, 'resolved', '已处理');
    expect(state.recentAlerts[0]?.status).toBe('resolved');
    expect(state.recentAlerts[0]?.note).toBe('已处理');

    const second = createAlert({
      projectId: 'project-a',
      projectName: 'Project A',
      ruleId: 'function-guard:withdraw',
      ruleName: '高危函数越权调用检测',
      severity: 'critical',
      summary: '再次触发',
      details: {},
    });

    state = store.pushAlert(state, second);
    expect(state.recentAlerts[0]?.status).toBe('open');
    expect(state.recentAlerts[0]?.occurrences).toBe(2);
  });

  it('appends scan history in reverse chronological order', () => {
    const store = new StateStore('/tmp/test-state.json', 20);
    let state = createState();

    const first: ScanRecord = {
      id: 'scan-1',
      startedAt: '2026-04-23T18:37:00.000Z',
      finishedAt: '2026-04-23T18:37:01.000Z',
      latestCheckpoint: 10,
      checkpointsProcessed: 2,
      transactionsProcessed: 20,
      alertsTriggered: 1,
      durationMs: 1000,
      success: true,
    };
    const second: ScanRecord = {
      id: 'scan-2',
      startedAt: '2026-04-23T18:38:00.000Z',
      finishedAt: '2026-04-23T18:38:01.000Z',
      latestCheckpoint: 12,
      checkpointsProcessed: 2,
      transactionsProcessed: 40,
      alertsTriggered: 0,
      durationMs: 1000,
      success: true,
    };

    state = store.appendScanRecord(state, first);
    state = store.appendScanRecord(state, second);

    expect(state.scanHistory).toHaveLength(2);
    expect(state.scanHistory[0]?.id).toBe('scan-2');
    expect(state.scanHistory[1]?.id).toBe('scan-1');
  });

  it('loads persisted price reference and baseline profiles', async () => {
    const file = `/tmp/test-state-${Date.now()}.json`;
    const store = new StateStore(file, 20);

    await store.save({
      ...createState(),
      priceReferenceProfiles: {
        'demo:oracle-price': {
          projectId: 'demo',
          label: 'oracle-price',
          recentObservedPrices: ['1000', '1100'],
          medianPrice: '1050',
          updatedAt: '2026-04-24T00:00:00.000Z',
        },
      },
      objectBaselineProfiles: {
        'demo:oracle-feed': {
          projectId: 'demo',
          objectLabel: 'oracle-feed',
          fields: {
            price: {
              lastValue: '1100',
              minValue: '1000',
              maxValue: '1200',
            },
          },
        },
      },
    });

    const loaded = await store.load();

    expect(loaded.priceReferenceProfiles['demo:oracle-price']?.medianPrice).toBe('1050');
    expect(loaded.objectBaselineProfiles['demo:oracle-feed']?.fields.price?.lastValue).toBe('1100');
  });

  // ── SLA tracking ──────────────────────────────────────────────────────────

  it('records acknowledgedAt timestamp on first acknowledge', () => {
    const store = new StateStore('/tmp/test-state.json', 20);
    let state = createState();

    const alert = createAlert({
      projectId: 'p', projectName: 'P', ruleId: 'r', ruleName: 'R',
      severity: 'high', summary: 'test', details: {},
    });

    state = store.pushAlert(state, alert);
    const id = state.recentAlerts[0]!.id;
    state = store.updateAlertStatus(state, id, 'acknowledged');

    expect(state.recentAlerts[0]?.acknowledgedAt).toBeDefined();
    expect(typeof state.recentAlerts[0]?.acknowledgedAt).toBe('string');
  });

  it('records resolvedAt timestamp on first resolve', () => {
    const store = new StateStore('/tmp/test-state.json', 20);
    let state = createState();

    const alert = createAlert({
      projectId: 'p', projectName: 'P', ruleId: 'r', ruleName: 'R',
      severity: 'high', summary: 'test', details: {},
    });

    state = store.pushAlert(state, alert);
    const id = state.recentAlerts[0]!.id;
    state = store.updateAlertStatus(state, id, 'resolved');

    expect(state.recentAlerts[0]?.resolvedAt).toBeDefined();
  });

  it('computes ackResponseSeconds from firstSeenAt to acknowledgedAt', () => {
    const store = new StateStore('/tmp/test-state.json', 20);
    let state = createState();

    // Manually inject an alert with a known firstSeenAt 5 minutes ago
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const alert = createAlert({
      projectId: 'p', projectName: 'P', ruleId: 'r', ruleName: 'R',
      severity: 'high', summary: 'test', details: {},
    });

    state = store.pushAlert(state, alert);
    // Patch firstSeenAt to simulate an alert from 5 min ago
    state = {
      ...state,
      recentAlerts: state.recentAlerts.map((a) => ({ ...a, firstSeenAt: fiveMinutesAgo })),
    };

    const id = state.recentAlerts[0]!.id;
    state = store.updateAlertStatus(state, id, 'acknowledged');

    const seconds = state.recentAlerts[0]?.ackResponseSeconds;
    expect(seconds).toBeDefined();
    // Should be approximately 300 seconds (5 min), allow ±10s for test timing
    expect(seconds).toBeGreaterThan(290);
    expect(seconds).toBeLessThan(320);
  });

  it('does NOT overwrite acknowledgedAt on second acknowledge', () => {
    const store = new StateStore('/tmp/test-state.json', 20);
    let state = createState();

    const alert = createAlert({
      projectId: 'p', projectName: 'P', ruleId: 'r', ruleName: 'R',
      severity: 'high', summary: 'test', details: {},
    });

    state = store.pushAlert(state, alert);
    const id = state.recentAlerts[0]!.id;
    state = store.updateAlertStatus(state, id, 'acknowledged');
    const firstAckAt = state.recentAlerts[0]?.acknowledgedAt;

    // Acknowledge again — should NOT overwrite
    state = store.updateAlertStatus(state, id, 'acknowledged');
    expect(state.recentAlerts[0]?.acknowledgedAt).toBe(firstAckAt);
  });

  it('does NOT overwrite ackResponseSeconds on subsequent status changes', () => {
    const store = new StateStore('/tmp/test-state.json', 20);
    let state = createState();

    const alert = createAlert({
      projectId: 'p', projectName: 'P', ruleId: 'r', ruleName: 'R',
      severity: 'high', summary: 'test', details: {},
    });

    state = store.pushAlert(state, alert);
    const id = state.recentAlerts[0]!.id;
    state = store.updateAlertStatus(state, id, 'acknowledged');
    const firstSeconds = state.recentAlerts[0]?.ackResponseSeconds;

    // Resolve after acknowledging — ackResponseSeconds should remain unchanged
    state = store.updateAlertStatus(state, id, 'resolved');
    expect(state.recentAlerts[0]?.ackResponseSeconds).toBe(firstSeconds);
  });

  it('does not set ackResponseSeconds when only resolving (not acknowledging)', () => {
    const store = new StateStore('/tmp/test-state.json', 20);
    let state = createState();

    const alert = createAlert({
      projectId: 'p', projectName: 'P', ruleId: 'r', ruleName: 'R',
      severity: 'high', summary: 'test', details: {},
    });

    state = store.pushAlert(state, alert);
    const id = state.recentAlerts[0]!.id;
    // Resolve directly without acknowledging first
    state = store.updateAlertStatus(state, id, 'resolved');

    // resolvedAt is set, but ackResponseSeconds is undefined (no acknowledgedAt)
    expect(state.recentAlerts[0]?.resolvedAt).toBeDefined();
    expect(state.recentAlerts[0]?.ackResponseSeconds).toBeUndefined();
  });
});
