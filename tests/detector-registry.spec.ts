import { describe, expect, it } from 'vitest';

import { runAttackDetectors } from '../src/detectors/registry.js';
import type { AttackFinding } from '../src/detectors/types.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PACKAGE = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ADMIN = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

function buildProject(): MonitoringProjectConfig {
  return {
    id: 'demo',
    name: 'Demo Project',
    packages: [{ address: PACKAGE, allowedUpgradeSenders: [ADMIN] }],
    protectedAddresses: [],
    functionGuards: [],
    trafficSpikes: [],
    failureSpikes: [],
    trackedObjects: [],
    suspiciousTargets: [],
    behaviorRules: {
      enabled: true,
      minRepeatedCalls: 2,
      minProtectedOutflow: '100',
      priceDeviationThresholdBps: 1500,
    },
    priceModels: [],
    objectBaselines: [],
    flowTracking: {
      enabled: true,
      minProtectedOutflow: '100',
      attackerGainThreshold: '100',
      shortWindowTxCount: 2,
    },
    suppression: {
      enabled: true,
      duplicateWindowSeconds: 600,
      weakSignalScoreThreshold: 35,
      maintenanceWindows: [],
    },
  };
}

function buildTx(): ObservedTransaction {
  return {
    digest: 'tx-1',
    checkpoint: 1,
    timestamp: '2026-04-24T00:00:00.000Z',
    sender: ADMIN,
    status: 'SUCCESS',
    calls: [],
    balanceChanges: [],
    objectChanges: [],
  };
}

describe('runAttackDetectors', () => {
  it('returns standardized findings from enabled detectors', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: buildTx(),
      derived: {
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(Array.isArray(findings)).toBe(true);
    expect(findings[0]).toHaveProperty('attackType');
    expect(findings[0]).toHaveProperty('category');
    expect(findings[0]).toHaveProperty('summary');
  });

  it('includes flash-loan sequence findings when funding, manipulation and extraction evidence align', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'flash_loan', function: 'borrow' },
          { package: PACKAGE, module: 'router', function: 'swap_exact' },
          { package: PACKAGE, module: 'vault', function: 'withdraw' },
        ],
      },
      derived: {
        flashLikeFundingDetected: true,
        valueExtractionDetected: true,
        priceEvidence: [
          {
            label: 'oracle-price',
            deviationBps: 2400,
            referenceKind: 'rolling_median',
            extractionCoupled: true,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['temporary_funding', 'protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '5000',
          netAttackerGain: '4500',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'flash-loan-sequence')).toBe(true);
  });

  it('includes privilege expansion and post-takeover drain findings when takeover signals align with outflow', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'governance', function: 'grant_operator_role' },
          { package: PACKAGE, module: 'vault', function: 'emergency_withdraw' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'admin-vault',
            field: 'admin',
            anomalyKind: 'permission_change',
            senderAuthorized: false,
          },
          {
            objectLabel: 'governance',
            field: 'operator',
            anomalyKind: 'permission_change',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '5000',
          netAttackerGain: '4500',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'privileged-role-expansion')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'drain-after-takeover')).toBe(true);
  });

  it('includes stale oracle exploitation and governance vote concentration findings when matching evidence exists', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'lending', function: 'borrow_using_oracle' },
          { package: PACKAGE, module: 'governance', function: 'vote' },
          { package: PACKAGE, module: 'governance', function: 'vote' },
          { package: PACKAGE, module: 'governance', function: 'vote' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        sameSensitiveCallRepeats: {
          'governance::vote': 3,
        },
        priceEvidence: [
          {
            label: 'oracle-price',
            referenceKind: 'rolling_median',
            extractionCoupled: true,
            incomplete: true,
          },
        ],
        baselineEvidence: [
          {
            objectLabel: 'governance',
            field: 'quorum_override',
            anomalyKind: 'permission_change',
            senderAuthorized: false,
          },
        ],
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-staleness-exploitation')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'governance-vote-concentration')).toBe(true);
  });

  it('includes cross-market manipulation and bridge drain findings when attack path spans market distortion and bridge claim extraction', () => {
    const findings = runAttackDetectors({
      project: {
        ...buildProject(),
        suspiciousTargets: [{ label: 'bridge-relayer', address: '0x999' }],
      },
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'amm_a', function: 'swap_exact' },
          { package: PACKAGE, module: 'amm_b', function: 'borrow' },
          { package: PACKAGE, module: 'bridge', function: 'claim' },
          { package: PACKAGE, module: 'vault', function: 'withdraw' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        suspiciousTargets: ['0x999'],
        priceEvidence: [
          {
            label: 'oracle-price',
            deviationBps: 2800,
            referenceKind: 'rolling_median',
            extractionCoupled: true,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['manipulation_target', 'protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '9000',
          netAttackerGain: '8100',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'cross-market-manipulation')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'bridge-drain-after-claim')).toBe(true);
  });

  it('includes flash-loan repay mismatch and governance execution after vote surge findings when repayment and governance execution signals are abnormal', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'flash_loan', function: 'borrow' },
          { package: PACKAGE, module: 'vault', function: 'withdraw' },
          { package: PACKAGE, module: 'flash_loan', function: 'repay' },
          { package: PACKAGE, module: 'governance', function: 'vote' },
          { package: PACKAGE, module: 'governance', function: 'execute_proposal' },
        ],
      },
      derived: {
        flashLikeFundingDetected: true,
        valueExtractionDetected: true,
        sameSensitiveCallRepeats: {
          'governance::vote': 4,
        },
        baselineEvidence: [
          {
            objectLabel: 'governance',
            field: 'proposal_executor',
            anomalyKind: 'permission_change',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['temporary_funding', 'protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '10000',
          netAttackerGain: '3200',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'flash-loan-repay-mismatch')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'governance-execution-after-vote-surge')).toBe(true);
  });

  it('includes privileged config flip and multi asset drain findings when config takeover is paired with multi-token extraction', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'config', function: 'set_pause' },
          { package: PACKAGE, module: 'vault', function: 'withdraw_all_assets' },
        ],
        balanceChanges: [
          { owner: '0x9999999999999999999999999999999999999999999999999999999999999999', coinType: '0x2::sui::SUI', amount: '-5000' },
          { owner: '0x9999999999999999999999999999999999999999999999999999999999999999', coinType: '0x2::usdc::USDC', amount: '-9000' },
          { owner: ADMIN, coinType: '0x2::sui::SUI', amount: '3000' },
          { owner: ADMIN, coinType: '0x2::usdc::USDC', amount: '7000' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'risk-engine',
            field: 'pause_guard',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '14000',
          netAttackerGain: '10000',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'privileged-config-flip')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'multi-asset-drain')).toBe(true);
  });

  it('includes sequenced probe then exploit and suspicious router hop findings when probe alerts precede routed extraction', () => {
    const findings = runAttackDetectors({
      project: {
        ...buildProject(),
        suspiciousTargets: [{ label: 'rogue-router', address: '0x999' }],
      },
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'router', function: 'multi_hop_swap' },
          { package: PACKAGE, module: 'external', function: 'invoke' },
          { package: PACKAGE, module: 'vault', function: 'withdraw' },
        ],
      },
      derived: {
        suspiciousTargets: ['0x999'],
        valueExtractionDetected: true,
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['intermediate_hop', 'protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '5000',
          netAttackerGain: '4200',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [
          { ruleId: 'failure-spike:demo', details: {} },
          { ruleId: 'behavior:suspicious-target-call', details: {} },
        ],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'sequenced-probe-then-exploit')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'suspicious-router-hop')).toBe(true);
  });

  it('includes reentry-like repeat extraction and timelock config disable findings when repeated withdrawals and timelock flips coexist', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'vault', function: 'withdraw' },
          { package: PACKAGE, module: 'vault', function: 'withdraw' },
          { package: PACKAGE, module: 'governance', function: 'disable_timelock' },
          { package: PACKAGE, module: 'config', function: 'set_executor' },
        ],
      },
      derived: {
        sameSensitiveCallRepeats: {
          'vault::withdraw': 3,
        },
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'governance',
            field: 'timelock_enabled',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '6000',
          netAttackerGain: '5200',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'reentry-like-repeat-extraction')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'timelock-config-disable')).toBe(true);
  });

  it('includes approval drain and collateral parameter flip findings when allowance-style extraction pairs with unauthorized lending risk changes', () => {
    const findings = runAttackDetectors({
      project: {
        ...buildProject(),
        suspiciousTargets: [{ label: 'rogue-spender', address: '0x999' }],
      },
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'token', function: 'approve_spender' },
          { package: PACKAGE, module: 'vault', function: 'transfer_from_vault' },
          { package: PACKAGE, module: 'lending', function: 'set_collateral_factor' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
        ],
      },
      derived: {
        suspiciousTargets: ['0x999'],
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'lending-risk',
            field: 'collateral_factor_bps',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '8000',
          netAttackerGain: '7600',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'approval-drain')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'collateral-parameter-flip')).toBe(true);
  });

  it('includes fee recipient hijack and risk limit bypass findings when fee routing and risk guards are hijacked before extraction', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'fee_manager', function: 'set_fee_recipient' },
          { package: PACKAGE, module: 'treasury', function: 'collect_fees' },
          { package: PACKAGE, module: 'risk_engine', function: 'disable_borrow_cap' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
          { package: PACKAGE, module: 'vault', function: 'withdraw' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'fee-manager',
            field: 'fee_recipient',
            anomalyKind: 'permission_change',
            senderAuthorized: false,
          },
          {
            objectLabel: 'risk-engine',
            field: 'borrow_cap_enabled',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '9500',
          netAttackerGain: '9200',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'fee-recipient-hijack')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'risk-limit-bypass')).toBe(true);
  });

  it('includes governance parameter poisoning and router approval reuse findings when governance thresholds and router approvals are weaponized', () => {
    const findings = runAttackDetectors({
      project: {
        ...buildProject(),
        suspiciousTargets: [{ label: 'rogue-router', address: '0x999' }],
      },
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'governance', function: 'set_vote_threshold' },
          { package: PACKAGE, module: 'governance', function: 'execute_proposal' },
          { package: PACKAGE, module: 'token', function: 'approve_router' },
          { package: PACKAGE, module: 'router', function: 'multi_hop_swap' },
        ],
      },
      derived: {
        suspiciousTargets: ['0x999'],
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'governance',
            field: 'vote_threshold_bps',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['intermediate_hop', 'protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '6700',
          netAttackerGain: '6400',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'governance-parameter-poisoning')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'router-approval-reuse')).toBe(true);
  });

  it('includes governance delay collapse and bridge router drain chain findings when collapsed delays and bridge-router extraction paths align', () => {
    const findings = runAttackDetectors({
      project: {
        ...buildProject(),
        suspiciousTargets: [{ label: 'bridge-router', address: '0x999' }],
      },
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'governance', function: 'set_execution_delay' },
          { package: PACKAGE, module: 'governance', function: 'execute_proposal_now' },
          { package: PACKAGE, module: 'bridge', function: 'claim_message' },
          { package: PACKAGE, module: 'router', function: 'multi_hop_swap' },
          { package: PACKAGE, module: 'vault', function: 'withdraw' },
        ],
      },
      derived: {
        suspiciousTargets: ['0x999'],
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'governance',
            field: 'execution_delay_seconds',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['intermediate_hop', 'protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '8300',
          netAttackerGain: '7900',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'governance-delay-collapse')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'bridge-router-drain-chain')).toBe(true);
  });

  it('includes approval probe then reuse and governance quorum collapse findings when probe signals, approval reuse and quorum collapse align', () => {
    const findings = runAttackDetectors({
      project: {
        ...buildProject(),
        suspiciousTargets: [{ label: 'rogue-router', address: '0x999' }],
      },
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'token', function: 'approve_router' },
          { package: PACKAGE, module: 'router', function: 'swap_exact' },
          { package: PACKAGE, module: 'governance', function: 'set_quorum_threshold' },
          { package: PACKAGE, module: 'governance', function: 'vote' },
          { package: PACKAGE, module: 'governance', function: 'execute_proposal' },
        ],
      },
      derived: {
        suspiciousTargets: ['0x999'],
        valueExtractionDetected: true,
        sameSensitiveCallRepeats: {
          'governance::vote': 4,
        },
        baselineEvidence: [
          {
            objectLabel: 'governance',
            field: 'quorum_threshold_bps',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['intermediate_hop', 'protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '7600',
          netAttackerGain: '7200',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [
          { ruleId: 'failure-spike:probe', details: {} },
          { ruleId: 'behavior:suspicious-target-call', details: {} },
        ],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'approval-probe-then-reuse')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'governance-quorum-collapse')).toBe(true);
  });

  it('includes treasury skim sequence and bridge proof replay drain findings when treasury skim and replayed bridge claims both produce extraction paths', () => {
    const findings = runAttackDetectors({
      project: {
        ...buildProject(),
        suspiciousTargets: [{ label: 'bridge-relayer', address: '0x999' }],
      },
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'treasury', function: 'skim_fees' },
          { package: PACKAGE, module: 'treasury', function: 'withdraw_treasury' },
          { package: PACKAGE, module: 'bridge', function: 'verify_proof' },
          { package: PACKAGE, module: 'bridge', function: 'claim_message' },
          { package: PACKAGE, module: 'vault', function: 'withdraw' },
        ],
      },
      derived: {
        suspiciousTargets: ['0x999'],
        valueExtractionDetected: true,
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '9100',
          netAttackerGain: '8800',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'treasury-skim-sequence')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'bridge-proof-replay-drain')).toBe(true);
  });

  it('includes router recipient flip and governance veto disable findings when router recipient changes and veto shutdown align with extraction and execution', () => {
    const findings = runAttackDetectors({
      project: {
        ...buildProject(),
        suspiciousTargets: [{ label: 'rogue-router', address: '0x999' }],
      },
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'router', function: 'set_recipient' },
          { package: PACKAGE, module: 'router', function: 'multi_hop_swap' },
          { package: PACKAGE, module: 'governance', function: 'disable_veto_guard' },
          { package: PACKAGE, module: 'governance', function: 'execute_proposal' },
        ],
      },
      derived: {
        suspiciousTargets: ['0x999'],
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'router-config',
            field: 'recipient',
            anomalyKind: 'permission_change',
            senderAuthorized: false,
          },
          {
            objectLabel: 'governance',
            field: 'veto_guard_enabled',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['intermediate_hop', 'protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '9300',
          netAttackerGain: '8900',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'router-recipient-flip')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'governance-veto-disable')).toBe(true);
  });

  it('includes liquidity cap release then drain and bridge proof probe then replay findings when cap loosening and bridge probe-replay extraction align', () => {
    const findings = runAttackDetectors({
      project: {
        ...buildProject(),
        suspiciousTargets: [{ label: 'bridge-relayer', address: '0x999' }],
      },
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'pool', function: 'set_liquidity_cap' },
          { package: PACKAGE, module: 'pool', function: 'withdraw_liquidity' },
          { package: PACKAGE, module: 'bridge', function: 'verify_proof' },
          { package: PACKAGE, module: 'bridge', function: 'claim_message' },
          { package: PACKAGE, module: 'vault', function: 'withdraw' },
        ],
      },
      derived: {
        suspiciousTargets: ['0x999'],
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'pool-risk',
            field: 'liquidity_cap',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '9800',
          netAttackerGain: '9300',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [
          { ruleId: 'traffic-spike:bridge-probe', details: {} },
          { ruleId: 'failure-spike:verify-proof', details: {} },
        ],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'liquidity-cap-release-then-drain')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'bridge-proof-probe-then-replay')).toBe(true);
  });

  it('includes governance emergency brake disable and router fee skim chain findings when brake shutdown and router fee extraction align', () => {
    const findings = runAttackDetectors({
      project: {
        ...buildProject(),
        suspiciousTargets: [{ label: 'rogue-router', address: '0x999' }],
      },
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'governance', function: 'disable_emergency_brake' },
          { package: PACKAGE, module: 'governance', function: 'execute_proposal' },
          { package: PACKAGE, module: 'router', function: 'set_fee_recipient' },
          { package: PACKAGE, module: 'router', function: 'collect_router_fee' },
          { package: PACKAGE, module: 'router', function: 'multi_hop_swap' },
        ],
      },
      derived: {
        suspiciousTargets: ['0x999'],
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'governance',
            field: 'emergency_brake_enabled',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
          {
            objectLabel: 'router-config',
            field: 'fee_recipient',
            anomalyKind: 'permission_change',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['intermediate_hop', 'protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '9700',
          netAttackerGain: '9200',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'governance-emergency-brake-disable')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'router-fee-skim-chain')).toBe(true);
  });

  it('includes oracle heartbeat disable then borrow and oracle recency bypass then liquidate findings when oracle freshness guards are disabled before extraction', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'oracle', function: 'disable_heartbeat_guard' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
          { package: PACKAGE, module: 'oracle', function: 'disable_recency_check' },
          { package: PACKAGE, module: 'liquidation', function: 'liquidate_position' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'oracle-config',
            field: 'heartbeat_enabled',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
          {
            objectLabel: 'oracle-config',
            field: 'recency_check_enabled',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '10200',
          netAttackerGain: '9800',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-heartbeat-disable-then-borrow')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-recency-bypass-then-liquidate')).toBe(true);
  });

  it('includes oracle twap window collapse and oracle price band disable findings when oracle smoothing and guardrails are disabled before extraction', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'oracle', function: 'set_twap_window' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
          { package: PACKAGE, module: 'oracle', function: 'disable_price_band_guard' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'oracle-config',
            field: 'twap_window_seconds',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
          {
            objectLabel: 'oracle-config',
            field: 'price_band_enabled',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '10700',
          netAttackerGain: '10300',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-twap-window-collapse')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-price-band-disable')).toBe(true);
  });

  it('includes oracle admin rotation then borrow and oracle fallback freeze then liquidate findings when oracle control and fallback paths are hijacked before extraction', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'oracle', function: 'rotate_admin' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
          { package: PACKAGE, module: 'oracle', function: 'freeze_fallback_price' },
          { package: PACKAGE, module: 'liquidation', function: 'liquidate_position' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'oracle-admin',
            field: 'admin',
            anomalyKind: 'permission_change',
            senderAuthorized: false,
          },
          {
            objectLabel: 'oracle-config',
            field: 'fallback_price_frozen',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '11100',
          netAttackerGain: '10700',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-admin-rotation-then-borrow')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-fallback-freeze-then-liquidate')).toBe(true);
  });

  it('includes oracle observation cardinality drop and oracle anchor override then borrow findings when oracle sampling depth and anchor references are weakened before extraction', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'oracle', function: 'set_observation_cardinality' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
          { package: PACKAGE, module: 'oracle', function: 'set_price_anchor' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'oracle-config',
            field: 'observation_cardinality',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
          {
            objectLabel: 'oracle-config',
            field: 'anchor_price_source',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '11500',
          netAttackerGain: '11100',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-observation-cardinality-drop')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-anchor-override-then-borrow')).toBe(true);
  });

  it('includes oracle sequencer gate disable and oracle deviation threshold collapse findings when oracle safety gates and deviation limits are weakened before extraction', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'oracle', function: 'disable_sequencer_gate' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
          { package: PACKAGE, module: 'oracle', function: 'set_max_deviation_bps' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'oracle-config',
            field: 'sequencer_gate_enabled',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
          {
            objectLabel: 'oracle-config',
            field: 'max_deviation_bps',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '11800',
          netAttackerGain: '11400',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-sequencer-gate-disable')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-deviation-threshold-collapse')).toBe(true);
  });

  it('includes oracle updater quorum collapse and oracle fallback source override findings when oracle updater consensus and fallback routing are weakened before extraction', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'oracle', function: 'set_updater_quorum' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
          { package: PACKAGE, module: 'oracle', function: 'set_fallback_source' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'oracle-config',
            field: 'updater_quorum',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
          {
            objectLabel: 'oracle-config',
            field: 'fallback_source',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '12000',
          netAttackerGain: '11600',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-updater-quorum-collapse')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-fallback-source-override')).toBe(true);
  });

  it('includes oracle primary source disable and oracle signer set rotation findings when primary feeds and signer authority are weakened before extraction', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'oracle', function: 'disable_primary_source' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
          { package: PACKAGE, module: 'oracle', function: 'rotate_signer_set' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'oracle-config',
            field: 'primary_source_enabled',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
          {
            objectLabel: 'oracle-admin',
            field: 'signer_set',
            anomalyKind: 'permission_change',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '12200',
          netAttackerGain: '11800',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-primary-source-disable')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-signer-set-rotation')).toBe(true);
  });

  it('includes oracle round id reset and oracle heartbeat threshold collapse findings when oracle round metadata and stale windows are weakened before extraction', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'oracle', function: 'reset_round_id' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
          { package: PACKAGE, module: 'oracle', function: 'set_heartbeat_threshold' },
          { package: PACKAGE, module: 'liquidation', function: 'liquidate_position' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'oracle-config',
            field: 'latest_round_id',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
          {
            objectLabel: 'oracle-config',
            field: 'heartbeat_threshold_seconds',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '12800',
          netAttackerGain: '12300',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-round-id-reset')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-heartbeat-threshold-collapse')).toBe(true);
  });

  it('includes oracle answer decimals flip and oracle min update interval bypass findings when price interpretation and update cadence guards are weakened before extraction', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'oracle', function: 'set_answer_decimals' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
          { package: PACKAGE, module: 'oracle', function: 'set_min_update_interval' },
          { package: PACKAGE, module: 'liquidation', function: 'liquidate_position' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'oracle-config',
            field: 'answer_decimals',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
          {
            objectLabel: 'oracle-config',
            field: 'min_update_interval_seconds',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '13400',
          netAttackerGain: '12900',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-answer-decimals-flip')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-min-update-interval-bypass')).toBe(true);
  });

  it('includes oracle observation delay bypass and oracle fallback decimals mismatch findings when sampling delay and fallback scale handling are weakened before extraction', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'oracle', function: 'set_observation_delay' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
          { package: PACKAGE, module: 'oracle', function: 'set_fallback_decimals' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'oracle-config',
            field: 'observation_delay_seconds',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
          {
            objectLabel: 'oracle-config',
            field: 'fallback_decimals',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '14000',
          netAttackerGain: '13500',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-observation-delay-bypass')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-fallback-decimals-mismatch')).toBe(true);
  });

  it('includes oracle anchor decimals mismatch and oracle sequencer grace period collapse findings when anchor scale handling and L2 grace windows are weakened before extraction', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'oracle', function: 'set_anchor_decimals' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
          { package: PACKAGE, module: 'oracle', function: 'set_sequencer_grace_period' },
          { package: PACKAGE, module: 'liquidation', function: 'liquidate_position' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'oracle-config',
            field: 'anchor_decimals',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
          {
            objectLabel: 'oracle-config',
            field: 'sequencer_grace_period_seconds',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '14600',
          netAttackerGain: '14100',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-anchor-decimals-mismatch')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-sequencer-grace-period-collapse')).toBe(true);
  });

  it('includes oracle anchor staleness bypass and oracle sequencer uptime feed override findings when anchor freshness and L2 uptime feed paths are weakened before extraction', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'oracle', function: 'disable_anchor_stale_check' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
          { package: PACKAGE, module: 'oracle', function: 'set_sequencer_uptime_feed' },
          { package: PACKAGE, module: 'liquidation', function: 'liquidate_position' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'oracle-config',
            field: 'anchor_staleness_check_enabled',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
          {
            objectLabel: 'oracle-config',
            field: 'sequencer_uptime_feed',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '15200',
          netAttackerGain: '14700',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-anchor-staleness-bypass')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-sequencer-uptime-feed-override')).toBe(true);
  });

  it('includes oracle anchor heartbeat collapse and oracle sequencer status inversion findings when anchor freshness windows and L2 status semantics are weakened before extraction', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'oracle', function: 'set_anchor_heartbeat_window' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
          { package: PACKAGE, module: 'oracle', function: 'set_sequencer_status_inverted' },
          { package: PACKAGE, module: 'liquidation', function: 'liquidate_position' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'oracle-config',
            field: 'anchor_heartbeat_window_seconds',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
          {
            objectLabel: 'oracle-config',
            field: 'sequencer_status_inverted',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '15800',
          netAttackerGain: '15300',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-anchor-heartbeat-collapse')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-sequencer-status-inversion')).toBe(true);
  });

  it('includes oracle anchor round reset and oracle sequencer heartbeat collapse findings when anchor rounds and L2 heartbeat windows are weakened before extraction', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'oracle', function: 'reset_anchor_round_id' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
          { package: PACKAGE, module: 'oracle', function: 'set_sequencer_heartbeat_window' },
          { package: PACKAGE, module: 'liquidation', function: 'liquidate_position' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'oracle-config',
            field: 'anchor_round_id',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
          {
            objectLabel: 'oracle-config',
            field: 'sequencer_heartbeat_window_seconds',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '16400',
          netAttackerGain: '15900',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-anchor-round-reset')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-sequencer-heartbeat-collapse')).toBe(true);
  });

  it('includes oracle anchor deviation threshold collapse and oracle sequencer round reset findings when anchor deviation guards and L2 round metadata are weakened before extraction', () => {
    const findings = runAttackDetectors({
      project: buildProject(),
      tx: {
        ...buildTx(),
        calls: [
          { package: PACKAGE, module: 'oracle', function: 'set_anchor_deviation_threshold' },
          { package: PACKAGE, module: 'lending', function: 'borrow' },
          { package: PACKAGE, module: 'oracle', function: 'reset_sequencer_round_id' },
          { package: PACKAGE, module: 'liquidation', function: 'liquidate_position' },
        ],
      },
      derived: {
        valueExtractionDetected: true,
        baselineEvidence: [
          {
            objectLabel: 'oracle-config',
            field: 'anchor_max_deviation_bps',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
          {
            objectLabel: 'oracle-config',
            field: 'sequencer_round_id',
            anomalyKind: 'state_flip',
            senderAuthorized: false,
          },
        ],
        flowEvidence: {
          nodes: [],
          edges: [],
          attackPathFound: true,
          pathRoles: ['protected_outflow', 'attacker_receipt'],
          netProtectedOutflow: '17000',
          netAttackerGain: '16500',
        },
        evidenceSummary: [],
      },
      runtime: {
        recentAlerts: [],
      },
    });

    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-anchor-deviation-threshold-collapse')).toBe(true);
    expect(findings.some((item: AttackFinding) => item.attackType === 'oracle-sequencer-round-reset')).toBe(true);
  });
});
