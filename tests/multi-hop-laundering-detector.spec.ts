import { describe, expect, it } from 'vitest';

import { detectMultiHopLaunderingAttacks } from '../src/detectors/known/multi-hop-laundering-detector.js';
import type { AttackDetectorContext } from '../src/detectors/types.js';
import type { FundFlowGraph, ObservedTransaction } from '../src/types.js';

const ATTACKER = '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const TREASURY = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const HOP1 = '0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const HOP2 = '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const HOP3 = '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

function makeTx(): ObservedTransaction {
  return {
    digest: 'D111',
    checkpoint: 1,
    timestamp: '2026-01-01T00:00:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [],
    balanceChanges: [],
    objectChanges: [],
  };
}

function makeCtx(flow: Partial<FundFlowGraph>): AttackDetectorContext {
  return {
    project: {
      id: 'demo',
      name: 'Demo',
      packages: [],
      protectedAddresses: [],
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
    tx: makeTx(),
    derived: {
      flowEvidence: {
        nodes: [],
        edges: [],
        attackPathFound: true,
        pathRoles: ['intermediate_hop', 'attacker_receipt'],
        netProtectedOutflow: '1000',
        netAttackerGain: '1000',
        ...flow,
      },
      priceEvidence: [],
      baselineEvidence: [],
      risk: { riskScore: 60, confidence: 0.6, recommendedSeverity: 'high' },
      evidenceSummary: [],
    },
    runtime: { recentAlerts: [] },
  } as AttackDetectorContext;
}

describe('detectMultiHopLaunderingAttacks', () => {
  it('fires when 3+ intermediate hops + attacker_receipt are present', () => {
    const ctx = makeCtx({
      edges: [
        { from: TREASURY, to: HOP1, coinType: '0x2::sui::SUI', amount: '1000', role: 'intermediate_hop' },
        { from: HOP1, to: HOP2, coinType: '0x2::sui::SUI', amount: '1000', role: 'intermediate_hop' },
        { from: HOP2, to: HOP3, coinType: '0x2::sui::SUI', amount: '1000', role: 'intermediate_hop' },
        { from: HOP3, to: ATTACKER, coinType: '0x2::sui::SUI', amount: '1000', role: 'attacker_receipt' },
      ],
      netAttackerGain: '1000',
    });

    const findings = detectMultiHopLaunderingAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.attackType).toBe('multi-hop-laundering');
    expect(findings[0]!.riskHints?.severityFloor).toBe('high');
    const evidence = findings[0]!.evidence as { hopCount: number };
    expect(evidence.hopCount).toBe(3);
  });

  it('does NOT fire with only 2 intermediate hops', () => {
    const ctx = makeCtx({
      edges: [
        { from: TREASURY, to: HOP1, coinType: '0x2::sui::SUI', amount: '1000', role: 'intermediate_hop' },
        { from: HOP1, to: HOP2, coinType: '0x2::sui::SUI', amount: '1000', role: 'intermediate_hop' },
        { from: HOP2, to: ATTACKER, coinType: '0x2::sui::SUI', amount: '1000', role: 'attacker_receipt' },
      ],
      netAttackerGain: '1000',
    });

    const findings = detectMultiHopLaunderingAttacks(ctx);
    expect(findings).toHaveLength(0);
  });

  it('does NOT fire when attacker gain is 0', () => {
    const ctx = makeCtx({
      edges: [
        { from: TREASURY, to: HOP1, coinType: '0x2::sui::SUI', amount: '1000', role: 'intermediate_hop' },
        { from: HOP1, to: HOP2, coinType: '0x2::sui::SUI', amount: '1000', role: 'intermediate_hop' },
        { from: HOP2, to: HOP3, coinType: '0x2::sui::SUI', amount: '1000', role: 'intermediate_hop' },
        { from: HOP3, to: ATTACKER, coinType: '0x2::sui::SUI', amount: '1000', role: 'attacker_receipt' },
      ],
      netAttackerGain: '0',
    });

    const findings = detectMultiHopLaunderingAttacks(ctx);
    expect(findings).toHaveLength(0);
  });

  it('does NOT fire when there is no attacker_receipt edge', () => {
    const ctx = makeCtx({
      edges: [
        { from: TREASURY, to: HOP1, coinType: '0x2::sui::SUI', amount: '1000', role: 'intermediate_hop' },
        { from: HOP1, to: HOP2, coinType: '0x2::sui::SUI', amount: '1000', role: 'intermediate_hop' },
        { from: HOP2, to: HOP3, coinType: '0x2::sui::SUI', amount: '1000', role: 'intermediate_hop' },
      ],
      netAttackerGain: '1000',
    });

    const findings = detectMultiHopLaunderingAttacks(ctx);
    expect(findings).toHaveLength(0);
  });
});
