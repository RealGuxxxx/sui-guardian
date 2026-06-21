import { describe, expect, it } from 'vitest';

import { detectSpoofTokenPoolInjectionAttacks } from '../src/detectors/known/spoof-token-pool-injection-detector.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PACKAGE = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ATTACKER = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const NEW_PKG = '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';

function buildProject(): MonitoringProjectConfig {
  return {
    id: 'spoof-test',
    name: 'Spoof Token Test',
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

describe('detectSpoofTokenPoolInjectionAttacks', () => {
  it('detects newly published package immediately injected into liquidity pool', () => {
    const tx: ObservedTransaction = {
      digest: 'tx-spoof-inject',
      checkpoint: 300,
      timestamp: '2025-05-22T11:00:00.000Z',
      sender: ATTACKER,
      status: 'SUCCESS',
      calls: [
        // Attacker publishes worthless coin package (BULLA pattern)
        // Then immediately adds to CLMM pool
        { package: NEW_PKG, module: 'bulla', function: 'mint' },
        { package: PACKAGE, module: 'clmm_pool', function: 'create_pool' },
        { package: PACKAGE, module: 'clmm_pool', function: 'add_liquidity' },
      ],
      balanceChanges: [],
      objectChanges: [
        // Newly published package (no inputVersion = brand new)
        { address: NEW_PKG, idCreated: true, idDeleted: false, outputVersion: 1, isPackage: true },
      ],
    };

    const findings = detectSpoofTokenPoolInjectionAttacks({
      project: buildProject(),
      tx,
      derived: {},
      runtime: { recentAlerts: [] },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.attackType).toBe('spoof-token-pool-injection');
    expect(findings[0]?.category).toBe('liquidity-drain');
    expect(findings[0]?.chainHints?.stage).toBe('manipulation');
    expect(findings[0]?.evidence['hasMintCall']).toBe(true);
  });

  it('does not fire when new package is not followed by pool injection', () => {
    const tx: ObservedTransaction = {
      digest: 'tx-legit-publish',
      checkpoint: 301,
      timestamp: '2025-05-22T11:30:00.000Z',
      sender: ATTACKER,
      status: 'SUCCESS',
      calls: [
        // Normal contract deployment — no pool injection
        { package: NEW_PKG, module: 'my_nft', function: 'mint_nft' },
      ],
      balanceChanges: [],
      objectChanges: [
        { address: NEW_PKG, idCreated: true, idDeleted: false, outputVersion: 1, isPackage: true },
      ],
    };

    const findings = detectSpoofTokenPoolInjectionAttacks({
      project: buildProject(),
      tx,
      derived: {},
      runtime: { recentAlerts: [] },
    });

    expect(findings).toHaveLength(0);
  });

  it('does not fire when pool injection has no newly published package', () => {
    const tx: ObservedTransaction = {
      digest: 'tx-legit-add-liquidity',
      checkpoint: 302,
      timestamp: '2025-05-22T12:00:00.000Z',
      sender: ATTACKER,
      status: 'SUCCESS',
      calls: [
        { package: PACKAGE, module: 'clmm_pool', function: 'add_liquidity' },
      ],
      balanceChanges: [],
      objectChanges: [
        // This is an upgrade, not a new publish (has inputVersion)
        { address: PACKAGE, idCreated: false, idDeleted: false, inputVersion: 1, outputVersion: 2, isPackage: true },
      ],
    };

    const findings = detectSpoofTokenPoolInjectionAttacks({
      project: buildProject(),
      tx,
      derived: {},
      runtime: { recentAlerts: [] },
    });

    expect(findings).toHaveLength(0);
  });
});
