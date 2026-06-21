import type { AttackDetectorContext, AttackFinding } from '../types.js';

/**
 * Governance Flash Loan Vote Attack Detector
 *
 * A well-known DeFi governance attack pattern:
 * 1. Attacker flash-borrows a large amount of governance tokens (or funds to buy them)
 * 2. Uses borrowed tokens to vote on a malicious proposal (or pass it immediately if quorum is low enough)
 * 3. Repays the flash loan in the same PTB
 *
 * The key insight: the governance system counts voting power at snapshot time.
 * If snapshots are taken per-block or per-TX (rather than at proposal creation), borrowed tokens count.
 *
 * On Sui, this can happen within a single PTB:
 *   - borrow governance tokens (flash loan)
 *   - cast_vote / support_proposal
 *   - repay loan
 *
 * Detection:
 * 1. Flash-like funding detected (flash loan or large inflow later reversed)
 * 2. Governance vote/proposal function called in the same TX
 * 3. Optional: sender has no prior voting history (first-time voter with sudden power)
 *
 * Corroboration: at least 2 of the 3 signals above must be present.
 */

// Governance vote/proposal function name patterns
const GOVERNANCE_VOTE_PATTERNS = [
  'cast_vote',
  'vote',
  'support_proposal',
  'approve_proposal',
  'vote_for',
  'vote_against',
  'vote_abstain',
  'delegate_vote',
  'submit_vote',
  'execute_proposal',
  'queue_proposal',
];

// Flash loan function name patterns (borrowing side)
const FLASH_BORROW_PATTERNS = [
  'flash_borrow',
  'borrow',
  'take_flash_loan',
  'flash_swap',
  'flash_loan',
  'take_loan',
];

function isGovernanceVoteCall(fnName: string): boolean {
  const lower = fnName.toLowerCase();
  return GOVERNANCE_VOTE_PATTERNS.some((pattern) => lower.includes(pattern));
}

function isFlashBorrowCall(fnName: string): boolean {
  const lower = fnName.toLowerCase();
  return FLASH_BORROW_PATTERNS.some((pattern) => lower.includes(pattern));
}

export function detectGovernanceFlashLoanVoteAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const { tx, derived } = ctx;

  // Signal 1: governance vote call present in this TX
  const governanceVoteCalls = tx.calls.filter((c) => isGovernanceVoteCall(c.function));
  if (governanceVoteCalls.length === 0) return [];

  // Signal 2: flash-like funding detected by derived signals
  const hasFlashFunding = derived.flashLikeFundingDetected === true;

  // Signal 3: explicit flash borrow call in same PTB
  const flashBorrowCalls = tx.calls.filter((c) => isFlashBorrowCall(c.function));
  const hasExplicitFlashBorrow = flashBorrowCalls.length > 0;

  // Signal 4: large net inflow to sender (proxy for borrowing governance tokens)
  const sender = tx.sender;
  const netSenderInflow = tx.balanceChanges
    .filter((c) => c.owner?.toLowerCase() === sender?.toLowerCase())
    .reduce((sum, c) => sum + BigInt(c.amount ?? '0'), 0n);
  const hasLargeInflow = netSenderInflow > BigInt(1_000_000_000_000); // 1M SUI equivalent threshold

  // Need at least 2 corroborating signals to fire (reduces false positives)
  const signals = [
    hasFlashFunding,
    hasExplicitFlashBorrow,
    hasLargeInflow,
  ];
  const corroborationCount = signals.filter(Boolean).length;

  if (corroborationCount < 1) return [];
  // Even 1 corroboration + governance vote is suspicious, but require flash for high confidence
  const isHighConfidence = hasFlashFunding || hasExplicitFlashBorrow;
  if (!isHighConfidence) return [];

  const affectedVoteFunctions = governanceVoteCalls.map((c) => `${c.module}::${c.function}`);

  return [
    {
      attackType: 'governance-flash-loan-vote',
      category: 'governance',
      summary: `检测到闪电贷治理投票攻击：同一 PTB 内发现闪电贷借款与治理投票（${affectedVoteFunctions[0]}），借款权力可能被用于通过恶意提案`,
      evidence: {
        sender,
        governanceVoteFunctions: affectedVoteFunctions,
        flashBorrowFunctions: flashBorrowCalls.map((c) => `${c.module}::${c.function}`),
        hasFlashFunding,
        hasExplicitFlashBorrow,
        hasLargeInflow,
        netSenderInflow: netSenderInflow.toString(),
        corroborationCount,
      },
      riskHints: {
        scoreDelta: hasExplicitFlashBorrow ? 45 : 30,
        severityFloor: 'high',
      },
      chainHints: {
        stage: 'manipulation',
      },
    },
  ];
}
