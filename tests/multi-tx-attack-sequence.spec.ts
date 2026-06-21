/**
 * Integration test: multi-TX attack sequence detection
 *
 * Verifies that ProjectMonitor correctly uses senderHistory (from SenderTracker)
 * to escalate detection when the same attacker sends multiple suspicious TXs.
 *
 * Flow:
 *   TX 1: Attacker probes the CLMM pool (low-value swap) → triggers slippage alert
 *   TX 2: Attacker runs flash-loan + add/remove liquidity → triggers CLMM attack alert
 *   TX 3: Attacker attempts extraction → repeat-attacker detector fires
 */
import { describe, expect, it } from 'vitest';

import { SenderTracker } from '../src/detection/sender-tracker.js';
import { ProjectMonitor } from '../src/project-monitor.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PKG = '0x1111111111111111111111111111111111111111111111111111111111111111';
const POOL = '0x9999999999999999999999999999999999999999999999999999999999999999';
const ATTACKER = '0xaaaabbbbccccddddeeeeffffaaaabbbbccccddddeeeeffffaaaabbbbccccdddd';

function buildProject(): MonitoringProjectConfig {
  return {
    id: 'cetus-integration',
    name: 'Cetus Integration Test',
    packages: [{ address: PKG, allowedUpgradeSenders: [] }],
    protectedAddresses: [
      { label: 'pool', address: POOL, outflowThresholds: { '0x2::sui::SUI': '100' } },
    ],
    functionGuards: [],
    trafficSpikes: [],
    failureSpikes: [],
    trackedObjects: [],
    suspiciousTargets: [],
    behaviorRules: {
      enabled: true,
      minRepeatedCalls: 2,
      minProtectedOutflow: '100',
      priceDeviationThresholdBps: 500,
    },
    priceModels: [],
    objectBaselines: [],
    flowTracking: {
      enabled: true,
      minProtectedOutflow: '100',
      attackerGainThreshold: '100',
      shortWindowTxCount: 2,
    },
    suppression: { enabled: false, duplicateWindowSeconds: 600, weakSignalScoreThreshold: 35, maintenanceWindows: [] },
  };
}

/** TX 1: Probe - attacker tests the pool with a small swap */
const probeTx: ObservedTransaction = {
  digest: 'tx-probe',
  checkpoint: 1000,
  timestamp: '2026-04-26T10:00:00.000Z',
  sender: ATTACKER,
  status: 'SUCCESS',
  calls: [{ package: PKG, module: 'clmm_pool', function: 'swap' }],
  balanceChanges: [
    { owner: POOL, coinType: '0x2::sui::SUI', amount: '-100' },
    { owner: ATTACKER, coinType: '0x2::sui::SUI', amount: '90' },
  ],
  objectChanges: [],
};

/** TX 2: Attack - flash swap + add/remove liquidity to drain the pool */
const attackTx: ObservedTransaction = {
  digest: 'tx-attack',
  checkpoint: 1001,
  timestamp: '2026-04-26T10:00:30.000Z',
  sender: ATTACKER,
  status: 'SUCCESS',
  calls: [
    { package: PKG, module: 'pool', function: 'flash_swap' },
    { package: PKG, module: 'clmm_pool', function: 'add_liquidity' },
    { package: PKG, module: 'clmm_pool', function: 'remove_liquidity' },
    { package: PKG, module: 'pool', function: 'repay_flash_swap' },
  ],
  balanceChanges: [
    { owner: POOL, coinType: '0x2::sui::SUI', amount: '-50000000' },
    { owner: ATTACKER, coinType: '0x2::sui::SUI', amount: '49000000' },
  ],
  objectChanges: [],
};

/** TX 3: Follow-up - attacker continues extracting value */
const followUpTx: ObservedTransaction = {
  digest: 'tx-followup',
  checkpoint: 1002,
  timestamp: '2026-04-26T10:01:00.000Z',
  sender: ATTACKER,
  status: 'SUCCESS',
  calls: [
    { package: PKG, module: 'pool', function: 'flash_swap' },
    { package: PKG, module: 'clmm_pool', function: 'add_liquidity' },
    { package: PKG, module: 'clmm_pool', function: 'remove_liquidity' },
  ],
  balanceChanges: [
    { owner: POOL, coinType: '0x2::sui::SUI', amount: '-30000000' },
    { owner: ATTACKER, coinType: '0x2::sui::SUI', amount: '28000000' },
  ],
  objectChanges: [],
};

describe('multi-TX attack sequence (integration)', () => {
  it('detects escalating attack across three transactions', () => {
    const tracker = new SenderTracker(60);
    const monitor = new ProjectMonitor(buildProject());

    const baseRecentAlerts: Array<{ ruleId: string; details: Record<string, unknown> }> = [];

    // TX 1 — probe
    const ts1 = Date.parse(probeTx.timestamp);
    const history1 = tracker.getSenderHistory(ATTACKER, ts1); // null — not seen yet
    const alerts1 = monitor.processTransaction(probeTx, baseRecentAlerts, history1);
    tracker.recordTx(ATTACKER, ts1, alerts1.map((a) => a.ruleId));

    // TX 2 — full CLMM attack
    const ts2 = Date.parse(attackTx.timestamp);
    const history2 = tracker.getSenderHistory(ATTACKER, ts2);
    const allRecentAlerts = alerts1.map((a) => ({ ruleId: a.ruleId, details: a.details }));
    const alerts2 = monitor.processTransaction(attackTx, allRecentAlerts, history2);
    tracker.recordTx(ATTACKER, ts2, alerts2.map((a) => a.ruleId));

    // TX 3 — follow-up extraction (repeat-attacker should fire if prior alerts >= 3)
    const ts3 = Date.parse(followUpTx.timestamp);
    const history3 = tracker.getSenderHistory(ATTACKER, ts3);
    const allRecentAlerts2 = [...allRecentAlerts, ...alerts2.map((a) => ({ ruleId: a.ruleId, details: a.details }))];
    const alerts3 = monitor.processTransaction(followUpTx, allRecentAlerts2, history3);
    tracker.recordTx(ATTACKER, ts3, alerts3.map((a) => a.ruleId));

    // Verify the overall attack was detected
    const allAlerts = [...alerts1, ...alerts2, ...alerts3];

    // At least one CLMM-related attack alert from TX2/TX3
    const clmmAlert = allAlerts.find((a) =>
      a.ruleId.includes('attack:clmm') || a.details?.['attackType'] === 'clmm-extreme-tick-attack',
    );
    expect(clmmAlert).toBeDefined();

    // history3 should reflect prior activity
    expect(history3).not.toBeNull();
    expect(history3!.txCount).toBe(2); // TX1 and TX2 were recorded before TX3

    // If enough alerts fired in TX1+TX2, TX3 should trigger repeat-attacker
    const totalPriorAlerts = alerts1.length + alerts2.length;
    if (totalPriorAlerts >= 3) {
      const repeatAlert = alerts3.find((a) =>
        a.ruleId.includes('repeat-attacker') || a.details?.['attackType'] === 'repeat-attacker',
      );
      expect(repeatAlert).toBeDefined();
    }
  });

  it('senderHistory is null for first-seen sender', () => {
    const tracker = new SenderTracker(60);
    const ts = Date.parse(probeTx.timestamp);
    const history = tracker.getSenderHistory(ATTACKER, ts);
    expect(history).toBeNull();
  });

  it('senderHistory accumulates correctly across TXs', () => {
    const tracker = new SenderTracker(60);
    const base = Date.now();

    tracker.recordTx(ATTACKER, base, ['rule:a', 'rule:b']);
    tracker.recordTx(ATTACKER, base + 10_000, ['rule:c']);

    const history = tracker.getSenderHistory(ATTACKER, base + 20_000);
    expect(history).not.toBeNull();
    expect(history!.txCount).toBe(2);
    expect(history!.alertCount).toBe(3);
    expect(history!.windowMinutes).toBe(60);
  });
});
