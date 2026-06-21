import { describe, expect, it } from 'vitest';

import { detectRugPullAttacks } from '../src/detectors/known/rug-pull-detector.js';
import type { AttackDetectorContext } from '../src/detectors/types.js';
import type { ObservedTransaction } from '../src/types.js';

const PACKAGE = '0x1111111111111111111111111111111111111111111111111111111111111111';
const TREASURY = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const ATTACKER = '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';

function makeCtx(txOverrides: Partial<ObservedTransaction> = {}, derivedOverrides: Record<string, unknown> = {}): AttackDetectorContext {
  const tx: ObservedTransaction = {
    digest: 'D111',
    checkpoint: 1,
    timestamp: '2026-01-01T00:00:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [],
    balanceChanges: [],
    objectChanges: [],
    ...txOverrides,
  };

  return {
    project: {
      id: 'demo',
      name: 'Demo',
      packages: [],
      protectedAddresses: [{ label: 'treasury', address: TREASURY, outflowThresholds: {} }],
      functionGuards: [],
      trafficSpikes: [],
      failureSpikes: [],
      trackedObjects: [],
      suspiciousTargets: [],
      behaviorRules: { enabled: true, minRepeatedCalls: 2, minProtectedOutflow: '1', priceDeviationThresholdBps: 1500 },
      priceModels: [],
      objectBaselines: [],
      flowTracking: { enabled: true, minProtectedOutflow: '100', attackerGainThreshold: '100', shortWindowTxCount: 1 },
      suppression: { enabled: false, duplicateWindowSeconds: 0, weakSignalScoreThreshold: 35, maintenanceWindows: [] },
    },
    tx,
    derived: {
      flashLikeFundingDetected: false,
      valueExtractionDetected: true,
      suspiciousTargets: [],
      sameSensitiveCallRepeats: {},
      priceEvidence: [],
      baselineEvidence: [],
      flowEvidence: {
        nodes: [],
        edges: [],
        attackPathFound: true,
        pathRoles: ['protected_outflow', 'attacker_receipt'],
        netProtectedOutflow: '1000',
        netAttackerGain: '1000',
      },
      risk: { riskScore: 70, confidence: 0.7, recommendedSeverity: 'high' },
      evidenceSummary: [],
      ...derivedOverrides,
    },
    runtime: { recentAlerts: [] },
  } as AttackDetectorContext;
}

describe('detectRugPullAttacks', () => {
  it('fires when package upgrade + protected outflow occur in same tx', () => {
    const ctx = makeCtx({
      objectChanges: [
        {
          address: PACKAGE,
          idCreated: false,
          idDeleted: false,
          isPackage: true,
          inputVersion: 1,
          outputVersion: 2,
        },
      ],
      balanceChanges: [
        { owner: TREASURY, coinType: '0x2::sui::SUI', amount: '-1000' },
        { owner: ATTACKER, coinType: '0x2::sui::SUI', amount: '1000' },
      ],
    });

    const findings = detectRugPullAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.attackType).toBe('rug-pull');
    expect(findings[0]!.riskHints?.severityFloor).toBe('critical');
    expect(findings[0]!.chainHints?.stage).toBe('extraction');
    const evidence = findings[0]!.evidence as { upgradedPackages: unknown[] };
    expect(evidence.upgradedPackages).toHaveLength(1);
  });

  it('does NOT fire when there is a package upgrade but no protected outflow', () => {
    const ctx = makeCtx(
      {
        objectChanges: [
          {
            address: PACKAGE,
            idCreated: false,
            idDeleted: false,
            isPackage: true,
            inputVersion: 1,
            outputVersion: 2,
          },
        ],
      },
      {
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: false,
          pathRoles: [],
          netProtectedOutflow: '0',
          netAttackerGain: '0',
        },
        valueExtractionDetected: false,
      },
    );

    const findings = detectRugPullAttacks(ctx);
    expect(findings).toHaveLength(0);
  });

  it('does NOT fire when there is protected outflow but no package upgrade', () => {
    const ctx = makeCtx({
      objectChanges: [
        {
          address: TREASURY,
          idCreated: false,
          idDeleted: false,
          isPackage: false,
          inputVersion: 1,
          outputVersion: 2,
        },
      ],
    });

    const findings = detectRugPullAttacks(ctx);
    expect(findings).toHaveLength(0);
  });

  it('does NOT fire when package version is unchanged', () => {
    const ctx = makeCtx({
      objectChanges: [
        {
          address: PACKAGE,
          idCreated: false,
          idDeleted: false,
          isPackage: true,
          inputVersion: 2,
          outputVersion: 2,
        },
      ],
    });

    const findings = detectRugPullAttacks(ctx);
    expect(findings).toHaveLength(0);
  });
});
