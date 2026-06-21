import { describe, expect, it } from 'vitest';

import { detectRepeatAttacker } from '../src/detectors/known/repeat-attacker-detector.js';
import type { AttackDetectorContext, AttackFinding } from '../src/detectors/types.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PKG = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ATTACKER = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

function buildProject(): MonitoringProjectConfig {
  return {
    id: 'test',
    name: 'Test',
    packages: [{ address: PKG, allowedUpgradeSenders: [] }],
    protectedAddresses: [],
    functionGuards: [],
    trafficSpikes: [],
    failureSpikes: [],
    trackedObjects: [],
    suspiciousTargets: [],
    behaviorRules: { enabled: false, minRepeatedCalls: 2, minProtectedOutflow: '100', priceDeviationThresholdBps: 500 },
    priceModels: [],
    objectBaselines: [],
    flowTracking: { enabled: false, minProtectedOutflow: '100', attackerGainThreshold: '100', shortWindowTxCount: 2 },
    suppression: { enabled: false, duplicateWindowSeconds: 600, weakSignalScoreThreshold: 35, maintenanceWindows: [] },
  };
}

function buildTx(): ObservedTransaction {
  return {
    digest: 'tx-test',
    checkpoint: 100,
    timestamp: '2026-04-26T10:00:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [{ package: PKG, module: 'pool', function: 'swap' }],
    balanceChanges: [],
    objectChanges: [],
  };
}

function buildCtx(senderHistory: AttackDetectorContext['runtime']['senderHistory']): AttackDetectorContext {
  return {
    project: buildProject(),
    tx: buildTx(),
    derived: {
      flashLikeFundingDetected: false,
      valueExtractionDetected: false,
      suspiciousTargets: [],
      sameSensitiveCallRepeats: {},
      priceEvidence: [],
      baselineEvidence: [],
      flowEvidence: { nodes: [] },
      risk: { score: 0, recommendedSeverity: 'info' },
      evidenceSummary: { categories: [], totalWeight: 0 },
    },
    runtime: {
      recentAlerts: [],
      senderHistory,
    },
  };
}

describe('detectRepeatAttacker', () => {
  it('does not fire when senderHistory is null', () => {
    const findings = detectRepeatAttacker(buildCtx(null));
    expect(findings).toHaveLength(0);
  });

  it('does not fire when alert count is below threshold (< 3)', () => {
    const findings = detectRepeatAttacker(buildCtx({
      txCount: 5,
      alertCount: 2,
      windowMinutes: 60,
      recentAlertRuleIds: ['rule:a', 'rule:b'],
    }));
    expect(findings).toHaveLength(0);
  });

  it('fires with high severity when alert count reaches threshold', () => {
    const findings = detectRepeatAttacker(buildCtx({
      txCount: 20,
      alertCount: 3,
      windowMinutes: 60,
      recentAlertRuleIds: ['rule:a', 'rule:b', 'rule:c'],
    }));
    expect(findings).toHaveLength(1);
    const finding = findings[0] as AttackFinding;
    expect(finding.attackType).toBe('repeat-attacker');
    expect(finding.riskHints?.severityFloor).toBe('high');
  });

  it('fires with critical severity for dense attack (high alert density)', () => {
    // 3 alerts in 4 TXs = 75% density (above 50% threshold)
    const findings = detectRepeatAttacker(buildCtx({
      txCount: 4,
      alertCount: 3,
      windowMinutes: 60,
      recentAlertRuleIds: ['clmm', 'bridge', 'slippage'],
    }));
    expect(findings).toHaveLength(1);
    const finding = findings[0] as AttackFinding;
    expect(finding.riskHints?.severityFloor).toBe('critical');
    expect(finding.riskHints?.scoreDelta).toBe(45);
  });

  it('includes evidence of alert history in finding', () => {
    const recentAlertRuleIds = ['attack:clmm', 'attack:slippage', 'deprecated-package-call'];
    const findings = detectRepeatAttacker(buildCtx({
      txCount: 6,
      alertCount: 3,
      windowMinutes: 60,
      recentAlertRuleIds,
    }));
    expect(findings[0]?.evidence['alertCount']).toBe(3);
    expect(findings[0]?.evidence['recentAlertRuleIds']).toEqual(recentAlertRuleIds);
  });
});
