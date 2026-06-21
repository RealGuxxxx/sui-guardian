import { describe, expect, it } from 'vitest';

import { detectBridgeBurstDrainAttacks } from '../src/detectors/known/bridge-burst-drain-detector.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PACKAGE = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ATTACKER = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const WORMHOLE = '0xaaaa111111111111111111111111111111111111111111111111111111111111';

function buildProject(): MonitoringProjectConfig {
  return {
    id: 'bridge-burst-test',
    name: 'Bridge Burst Test',
    packages: [{ address: PACKAGE, allowedUpgradeSenders: [] }],
    protectedAddresses: [],
    functionGuards: [],
    trafficSpikes: [],
    failureSpikes: [],
    trackedObjects: [],
    suspiciousTargets: [],
    behaviorRules: { enabled: true, minRepeatedCalls: 2, minProtectedOutflow: '100', priceDeviationThresholdBps: 500 },
    priceModels: [],
    objectBaselines: [],
    flowTracking: { enabled: true, minProtectedOutflow: '100', attackerGainThreshold: '100', shortWindowTxCount: 2 },
    suppression: { enabled: true, duplicateWindowSeconds: 600, weakSignalScoreThreshold: 35, maintenanceWindows: [] },
  };
}

function buildBridgeTx(): ObservedTransaction {
  return {
    digest: 'tx-bridge-1',
    checkpoint: 400,
    timestamp: '2025-05-22T13:00:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [
      { package: WORMHOLE, module: 'token_bridge', function: 'transfer_tokens' },
    ],
    balanceChanges: [
      // Large USDC outflow (> 1_000_000_000 MIST threshold)
      { owner: ATTACKER, coinType: '0xusdc::usdc::USDC', amount: '-2000000000' },
    ],
    objectChanges: [],
  };
}

describe('detectBridgeBurstDrainAttacks', () => {
  it('fires medium severity alert on first large bridge transfer', () => {
    const findings = detectBridgeBurstDrainAttacks({
      project: buildProject(),
      tx: buildBridgeTx(),
      derived: {},
      runtime: { recentAlerts: [] }, // No prior alerts
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.attackType).toBe('bridge-burst-drain');
    expect(findings[0]?.riskHints?.severityFloor).toBe('medium');
    expect(findings[0]?.evidence['isBurst']).toBe(false);
  });

  it('escalates to critical on repeat bridge transfers from same sender', () => {
    const findings = detectBridgeBurstDrainAttacks({
      project: buildProject(),
      tx: buildBridgeTx(),
      derived: {},
      runtime: {
        recentAlerts: [
          // Prior bridge alert from same sender
          {
            ruleId: 'bridge-burst-drain:cetus-test',
            details: { attackType: 'bridge-burst-drain', sender: ATTACKER },
          },
        ],
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.attackType).toBe('bridge-burst-drain');
    expect(findings[0]?.riskHints?.severityFloor).toBe('critical');
    expect(findings[0]?.evidence['isBurst']).toBe(true);
    expect(findings[0]?.evidence['recentBridgeAlertCount']).toBe(1);
  });

  it('does not fire without bridge function call', () => {
    const tx = buildBridgeTx();
    tx.calls = [
      { package: PACKAGE, module: 'swap', function: 'swap_exact_tokens' },
    ];

    const findings = detectBridgeBurstDrainAttacks({
      project: buildProject(),
      tx,
      derived: {},
      runtime: { recentAlerts: [] },
    });

    expect(findings).toHaveLength(0);
  });

  it('does not fire without large outflow', () => {
    const tx = buildBridgeTx();
    tx.balanceChanges = [
      // Small amount — below threshold
      { owner: ATTACKER, coinType: '0xusdc::usdc::USDC', amount: '-100' },
    ];

    const findings = detectBridgeBurstDrainAttacks({
      project: buildProject(),
      tx,
      derived: {},
      runtime: { recentAlerts: [] },
    });

    expect(findings).toHaveLength(0);
  });

  it('detects CCTP deposit_for_burn pattern', () => {
    const tx = buildBridgeTx();
    tx.calls = [
      { package: WORMHOLE, module: 'cctp', function: 'deposit_for_burn' },
    ];

    const findings = detectBridgeBurstDrainAttacks({
      project: buildProject(),
      tx,
      derived: {},
      runtime: { recentAlerts: [] },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.attackType).toBe('bridge-burst-drain');
  });
});
