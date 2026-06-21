import { describe, expect, it } from 'vitest';

import { detectGovernanceFlashLoanVoteAttacks } from '../src/detectors/known/governance-flash-loan-vote-detector.js';
import type { AttackDetectorContext } from '../src/detectors/types.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PKG = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ATTACKER = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const GOV_TOKEN = '0xaaaa::govern::GOV';

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

function buildCtx(
  calls: ObservedTransaction['calls'],
  derivedOverrides: Partial<AttackDetectorContext['derived']> = {},
  balanceChanges: ObservedTransaction['balanceChanges'] = [],
): AttackDetectorContext {
  return {
    project: buildProject(),
    tx: {
      digest: 'tx-test',
      checkpoint: 100,
      timestamp: '2026-05-05T10:00:00.000Z',
      sender: ATTACKER,
      status: 'SUCCESS',
      calls,
      balanceChanges,
      objectChanges: [],
    },
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
      ...derivedOverrides,
    },
    runtime: {
      recentAlerts: [],
      senderHistory: null,
    },
  };
}

describe('detectGovernanceFlashLoanVoteAttacks', () => {
  it('does not fire when no governance vote call', () => {
    const ctx = buildCtx(
      [{ package: PKG, module: 'pool', function: 'borrow' }],
      { flashLikeFundingDetected: true },
    );
    expect(detectGovernanceFlashLoanVoteAttacks(ctx)).toHaveLength(0);
  });

  it('does not fire when governance vote present but no flash corroboration', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'dao', function: 'cast_vote' },
    ]);
    expect(detectGovernanceFlashLoanVoteAttacks(ctx)).toHaveLength(0);
  });

  it('fires when flash borrow + governance vote in same PTB (highest confidence)', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'lending', function: 'flash_borrow' },
      { package: PKG, module: 'dao', function: 'cast_vote' },
      { package: PKG, module: 'lending', function: 'repay' },
    ]);
    const findings = detectGovernanceFlashLoanVoteAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.attackType).toBe('governance-flash-loan-vote');
    expect(findings[0]?.category).toBe('governance');
    expect(findings[0]?.evidence['hasExplicitFlashBorrow']).toBe(true);
    expect(findings[0]?.riskHints?.scoreDelta).toBe(45);
    expect(findings[0]?.riskHints?.severityFloor).toBe('high');
  });

  it('fires when flashLikeFundingDetected + governance vote call', () => {
    const ctx = buildCtx(
      [{ package: PKG, module: 'governance', function: 'vote_for' }],
      { flashLikeFundingDetected: true },
    );
    const findings = detectGovernanceFlashLoanVoteAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['hasFlashFunding']).toBe(true);
    expect(findings[0]?.riskHints?.scoreDelta).toBe(30); // no explicit flash borrow
  });

  it('detects flash_loan prefix variants', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'protocol', function: 'take_flash_loan' },
      { package: PKG, module: 'gov', function: 'support_proposal' },
    ]);
    const findings = detectGovernanceFlashLoanVoteAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['flashBorrowFunctions']).toContain('protocol::take_flash_loan');
    expect(findings[0]?.evidence['governanceVoteFunctions']).toContain('gov::support_proposal');
  });

  it('detects delegate_vote as governance function', () => {
    const ctx = buildCtx(
      [{ package: PKG, module: 'dao', function: 'delegate_vote' }],
      { flashLikeFundingDetected: true },
    );
    const findings = detectGovernanceFlashLoanVoteAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['governanceVoteFunctions']).toContain('dao::delegate_vote');
  });

  it('assigns manipulation stage', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'flash', function: 'borrow' },
      { package: PKG, module: 'dao', function: 'vote_against' },
    ]);
    const findings = detectGovernanceFlashLoanVoteAttacks(ctx);
    expect(findings[0]?.chainHints?.stage).toBe('manipulation');
  });

  it('records sender address in evidence', () => {
    const ctx = buildCtx([
      { package: PKG, module: 'flash', function: 'flash_borrow' },
      { package: PKG, module: 'gov', function: 'execute_proposal' },
    ]);
    const findings = detectGovernanceFlashLoanVoteAttacks(ctx);
    expect(findings[0]?.evidence['sender']).toBe(ATTACKER);
  });
});
