import { describe, expect, it } from 'vitest';

import { detectUpgradeCapMisuseAttacks } from '../src/detectors/known/upgrade-cap-misuse-detector.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PACKAGE = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ATTACKER = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

function buildProject(): MonitoringProjectConfig {
  return {
    id: 'pawtato-test',
    name: 'UpgradeCap Test',
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

describe('detectUpgradeCapMisuseAttacks', () => {
  it('detects Pawtato-style create_new_admin_cap misuse with upgrade object change', () => {
    const tx: ObservedTransaction = {
      digest: 'tx-pawtato',
      checkpoint: 200,
      timestamp: '2026-01-28T10:00:00.000Z',
      sender: ATTACKER,
      status: 'SUCCESS',
      calls: [
        // Attacker calls create_new_admin_cap with their UpgradeCap
        { package: PACKAGE, module: 'admin', function: 'create_new_admin_cap' },
      ],
      balanceChanges: [],
      objectChanges: [
        // UpgradeCap object change (attacker's package being referenced)
        { address: '0xaaa', idCreated: false, idDeleted: false, inputVersion: 1, outputVersion: 2, isPackage: true },
        // New AdminCap created
        { address: '0xbbb', idCreated: true, idDeleted: false, isPackage: false },
      ],
    };

    const findings = detectUpgradeCapMisuseAttacks({
      project: buildProject(),
      tx,
      derived: {},
      runtime: { recentAlerts: [] },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.attackType).toBe('upgrade-cap-misuse');
    expect(findings[0]?.category).toBe('permission');
    expect(findings[0]?.chainHints?.stage).toBe('takeover');
  });

  it('does not flag legitimate authorize_upgrade calls', () => {
    const tx: ObservedTransaction = {
      digest: 'tx-legit-upgrade',
      checkpoint: 201,
      timestamp: '2026-01-28T11:00:00.000Z',
      sender: ATTACKER,
      status: 'SUCCESS',
      calls: [
        { package: PACKAGE, module: 'package', function: 'authorize_upgrade' },
        { package: PACKAGE, module: 'package', function: 'commit_upgrade' },
      ],
      balanceChanges: [],
      objectChanges: [
        { address: '0xaaa', idCreated: false, idDeleted: false, inputVersion: 1, outputVersion: 2, isPackage: true },
      ],
    };

    const findings = detectUpgradeCapMisuseAttacks({
      project: buildProject(),
      tx,
      derived: {},
      runtime: { recentAlerts: [] },
    });

    expect(findings).toHaveLength(0);
  });

  it('does not flag create_new_admin_cap without any object changes', () => {
    const tx: ObservedTransaction = {
      digest: 'tx-no-changes',
      checkpoint: 202,
      timestamp: '2026-01-28T12:00:00.000Z',
      sender: ATTACKER,
      status: 'SUCCESS',
      calls: [
        { package: PACKAGE, module: 'admin', function: 'create_new_admin_cap' },
      ],
      balanceChanges: [],
      objectChanges: [], // No object changes at all — likely a failed dry run
    };

    const findings = detectUpgradeCapMisuseAttacks({
      project: buildProject(),
      tx,
      derived: {},
      runtime: { recentAlerts: [] },
    });

    // No upgrade object change and no new non-package object → no alert
    expect(findings).toHaveLength(0);
  });

  it('detects grant_admin pattern with new object creation', () => {
    const tx: ObservedTransaction = {
      digest: 'tx-grant-admin',
      checkpoint: 203,
      timestamp: '2026-01-28T13:00:00.000Z',
      sender: ATTACKER,
      status: 'SUCCESS',
      calls: [
        { package: PACKAGE, module: 'governance', function: 'grant_admin_from_upgrade_cap' },
      ],
      balanceChanges: [],
      objectChanges: [
        { address: '0xccc', idCreated: true, idDeleted: false, isPackage: false },
      ],
    };

    const findings = detectUpgradeCapMisuseAttacks({
      project: buildProject(),
      tx,
      derived: {},
      runtime: { recentAlerts: [] },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.attackType).toBe('upgrade-cap-misuse');
  });
});
