/**
 * Maps attack types to immediate remediation steps for on-call operators.
 * These are shown in alert details to make alerts actionable.
 */

export interface RemediationGuide {
  /** 1–2 sentence description of the threat. */
  threat: string;
  /** Ordered list of immediate actions to take. */
  immediateActions: string[];
  /** Links or references for follow-up investigation. */
  references?: string[];
}

const GUIDES: Record<string, RemediationGuide> = {
  'clmm-extreme-tick-attack': {
    threat: 'Cetus $223M pattern: flash-loan + add/remove liquidity in same PTB, likely exploiting CLMM integer overflow to drain pool reserves.',
    immediateActions: [
      'PAUSE: Trigger the protocol emergency pause if available to halt all pool interactions.',
      'BLOCK: If validators can emergency-freeze the contract, escalate immediately.',
      'NOTIFY: Alert core team via emergency channel — this is a live active exploit.',
      'MONITOR: Track the attacker address for cross-chain bridge activity (funds likely bridged via Wormhole/CCTP within minutes).',
      'REVIEW: Check pool reserves for all monitored pools — compare on-chain vs expected balances.',
    ],
    references: ['Cetus May 2025 post-mortem', 'https://suiscan.xyz'],
  },
  'ptb-breadth-attack': {
    threat: 'Attacker is calling the same function against many pools in a single PTB — signature of a mass-drain campaign.',
    immediateActions: [
      'PAUSE: Halt all pool operations immediately if a pause function exists.',
      'ALERT: Notify protocol team — this pattern typically precedes or accompanies fund drainage.',
      'ENUMERATE: Identify all pools affected by checking which pool addresses appear in the TX object changes.',
    ],
  },
  'bridge-burst-drain': {
    threat: 'Attacker is moving funds cross-chain at high velocity, likely post-exploit exfiltration via Wormhole or CCTP.',
    immediateActions: [
      'CONTACT: Immediately contact Wormhole/CCTP security teams to freeze in-flight transfers.',
      'BLACKLIST: Report the attacker address to CEXs for monitoring.',
      'EVIDENCE: Preserve all TX digests and bridge message IDs for law enforcement.',
      'CHECK: Verify whether on-chain funds can still be recovered (e.g., validator freeze).',
    ],
  },
  'upgrade-cap-misuse': {
    threat: 'Pawtato pattern: UpgradeCap passed to an admin function without proper validation — attacker may gain elevated privileges.',
    immediateActions: [
      'REVOKE: If admin roles were granted, revoke them immediately via the protocol admin panel.',
      'AUDIT: Check which capabilities were created in this transaction (objectChanges).',
      'ROTATE: Rotate all admin keys and capabilities as a precaution.',
      'DISABLE: If possible, disable the affected function until a patch is deployed.',
    ],
  },
  'spoof-token-pool-injection': {
    threat: 'New worthless token published and immediately injected into a liquidity pool — likely setup for a flash-loan drain.',
    immediateActions: [
      'BLOCK: Remove or block the new spoof pool before it accumulates liquidity.',
      'ALERT: Warn liquidity providers not to add to the new pool.',
      'PAUSE: Pause the affected pool if possible.',
      'MONITOR: The attacker may follow up with a flash-loan exploit within minutes.',
    ],
  },
  'deprecated-package-call': {
    threat: 'Scallop pattern: attacker is calling an old (deprecated) contract version that may have unpatched vulnerabilities or uninitialized state.',
    immediateActions: [
      'IDENTIFY: Determine which deprecated package was called and what function.',
      'ASSESS: Check if the deprecated package has a known vulnerability (uninitialized state, missing access control).',
      'ALERT: Notify the protocol team — this may indicate an active exploit attempt.',
    ],
    references: ['Scallop April 2026 post-mortem'],
  },
  'known-bad-actor': {
    threat: 'A known exploit address from a previous Sui incident is interacting with this protocol.',
    immediateActions: [
      'HIGH ALERT: This is an extremely high-confidence signal — treat as an active attack.',
      'PAUSE: Halt protocol operations immediately if possible.',
      'MONITOR: Track all TX chains from this address — may be reconnaissance for a new exploit.',
      'BLOCK: Submit the address to on-chain blocklist if the protocol supports it.',
    ],
  },
  'repeat-attacker': {
    threat: 'Same address has triggered multiple security alerts in the last hour — indicates sustained attack campaign.',
    immediateActions: [
      'ESCALATE: Treat all subsequent activity from this address as hostile.',
      'PAUSE: Consider pausing affected protocol components.',
      'TRACE: Review the history of alerts from this sender to understand attack vector.',
      'COORDINATE: Check if this sender is also attacking other monitored protocols.',
    ],
  },
  'package-upgrade-hijack': {
    threat: 'An unauthorized address has upgraded a monitored package — potential rug pull or backdoor insertion.',
    immediateActions: [
      'CRITICAL: This is one of the highest-severity events possible.',
      'FREEZE: Advise all users to stop interacting with the protocol immediately.',
      'AUDIT: Analyze the upgrade diff to understand what was changed.',
      'PAUSE: If a pause function still works post-upgrade, trigger it.',
      'NOTIFY: Alert all LPs and users to withdraw funds if possible.',
    ],
  },
  'flash-loan-sequence': {
    threat: 'Flash loan borrow detected without corresponding repayment in the same TX — potential broken hot-potato exploit.',
    immediateActions: [
      'VERIFY: Check if the TX actually succeeded — a failed TX may indicate the exploit was blocked.',
      'AUDIT: Review the flash loan receipt struct for the drop ability (broken hot-potato).',
      'MONITOR: Watch for follow-up TXs from the same sender.',
    ],
  },
  'sandwich-attack': {
    threat: 'MEV sandwich attack: attacker front-ran and back-ran a swap in the same PTB or across sequential TXs, profiting from price impact at victim\'s expense.',
    immediateActions: [
      'ASSESS: Determine the scale of the loss — check victim TX slippage vs market price.',
      'LOG: Record the attacker address and all TX digests for evidence.',
      'EVALUATE: Consider adding anti-sandwich protection (commit-reveal, private mempools, TWAP-based slippage).',
      'NOTIFY: Alert affected users if funds were extracted from their pending TXs.',
    ],
  },
  'multi-vault-rapid-drain': {
    threat: 'Volo Protocol $3.5M pattern: compromised admin key used by automated script to drain multiple vaults (WBTC, XAUm, USDC) in rapid succession.',
    immediateActions: [
      'CRITICAL: Immediately rotate all admin keys and revoke current admin capabilities.',
      'PAUSE: Trigger emergency pause on ALL protocol vaults — the script may not have finished.',
      'FREEZE: Contact security team to evaluate validator-level emergency freeze.',
      'INVESTIGATE: Determine how the admin key was compromised (phishing, infra breach, insider).',
      'NOTIFY: Alert all asset custodians, bridges, and CEXs to watch for the attacker address.',
    ],
    references: ['Volo Protocol April 2026 incident report'],
  },
  'perpetuals-fee-parameter-abuse': {
    threat: 'Aftermath Finance $1.14M pattern: integrator set extreme negative fee (u64 overflow), protocol treated fee credit as real collateral, allowing USDC withdrawal.',
    immediateActions: [
      'PAUSE: Immediately halt all perpetuals/collateral withdrawal operations.',
      'IDENTIFY: Find the integrator address that set the malicious fee parameter.',
      'REVOKE: Revoke integrator registration or reset fee to 0 for the attacker address.',
      'AUDIT: Review all positions opened after the fee was set — check for inflated collateral.',
      'PATCH: Add fee parameter bounds validation (0 ≤ fee ≤ max_fee_bps) before deploying fix.',
    ],
    references: ['Aftermath Finance April 2026 post-mortem'],
  },
  'unknown-coordinated-anomaly': {
    threat: 'Multiple independent anomaly signals detected simultaneously without matching a known attack pattern — novel or undocumented exploit attempt.',
    immediateActions: [
      'INVESTIGATE: Manually review the transaction to understand the anomaly.',
      'ASSESS: Compare current pool/vault balances against expected values.',
      'ESCALATE: If funds appear to be moving unexpectedly, treat as active exploit.',
      'PRESERVE: Screenshot and archive all relevant TX details before on-chain state changes.',
      'RESEARCH: Check Sui security channels (Immunefi, Twitter/X) for reports of similar activity.',
    ],
  },

  'dynamic-field-abuse': {
    threat: 'Attacker is using Sui dynamic_field::borrow_mut or remove to bypass the intended object API and modify/drain state directly — a pattern seen in shared-object exploits where access control is enforced at the entry function level only.',
    immediateActions: [
      'PAUSE: Activate emergency pause to stop all interactions with affected shared objects.',
      'AUDIT: Check all shared objects referenced in the TX for unauthorized field modifications.',
      'REVIEW: Ensure all write paths go through capability-gated entry functions, not raw dynamic_field.',
      'PATCH: Add assert!(ctx.sender() == owner, ENotAuthorized) guards inside dynamic field helpers.',
      'ESCALATE: Alert security team; check for follow-up extraction transactions from the same sender.',
    ],
  },

  'clock-manipulation': {
    threat: 'Attacker is abusing on-chain Clock timestamps to bypass time-locks, drain vesting schedules, or manipulate TWAP oracle windows — all calls in a single PTB observe the same timestamp, defeating per-interval guards.',
    immediateActions: [
      'PAUSE: Halt all time-sensitive operations (vest, unlock, redeem) immediately.',
      'AUDIT: Verify time-lock state is stored per-user and updated on each call, not just compared to Clock.',
      'REVIEW: Check if TWAP/oracle windows are being collapsed by rapid same-block updates.',
      'PATCH: Use epoch + stored timestamp to enforce minimum intervals; do not rely solely on clock comparison.',
      'ESCALATE: Check pending transactions from the same sender for follow-up extraction.',
    ],
  },
};

const DEFAULT_GUIDE: RemediationGuide = {
  threat: 'Suspicious on-chain activity detected matching known attack patterns.',
  immediateActions: [
    'INVESTIGATE: Review the transaction details and attacker address history.',
    'ASSESS: Determine if this is a false positive or active exploit.',
    'ESCALATE: If confirmed exploit, engage protocol emergency response.',
  ],
};

/**
 * Returns remediation guidance for a given attack type.
 * Falls back to a generic guide if the attack type is not specifically mapped.
 */
export function getRemediationGuide(attackType: string): RemediationGuide {
  // Try exact match first, then prefix match
  if (GUIDES[attackType]) return GUIDES[attackType];

  for (const [key, guide] of Object.entries(GUIDES)) {
    if (attackType.startsWith(key) || key.startsWith(attackType)) {
      return guide;
    }
  }

  return DEFAULT_GUIDE;
}
