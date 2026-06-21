/**
 * Known on-chain attacker / exploiter addresses from documented Sui incidents.
 *
 * Sources:
 * - Cetus Protocol $223M exploit (2025-05-22): integer overflow in checked_shlw
 *   Refs: Cyfrin, SlowMist, Merkle Science post-mortems; ZachXBT on X
 * - Scallop $142K exploit (2026-04-26): deprecated contract + uninitialized index
 *   Refs: ExVul Security Alert, CryptoTimes, Blockonomi
 * - Aftermath Finance Perpetuals $1.14M (2026-04-29): negative fee parameter abuse
 *   Refs: Aftermath post-mortem; BlockSec, Beosin alerts
 * - Volo Protocol $3.5M (2026-04-21): compromised admin key multi-vault drain
 *   Refs: Volo post-mortem; SlowMist analysis
 * - Pawtato GameFi exploit (2026-01-15): unvalidated UpgradeCap gate
 *
 * NOTE: Update this list as new incidents are documented. Addresses are stored
 * in canonical lowercase 0x-prefixed hex form.
 */

export interface KnownBadActor {
  /** Canonical Sui address (lowercase, full 64-char hex with 0x prefix). */
  address: string;
  /** Short label describing the actor or incident. */
  label: string;
  /** ISO-8601 date when the incident was first observed. */
  incidentDate: string;
  /** Estimated loss in USD, for display purposes. */
  estimatedLossUsd?: number;
}

/**
 * Documented exploiter addresses confirmed via block explorers and post-mortems.
 */
export const KNOWN_BAD_ACTORS: readonly KnownBadActor[] = [
  // ── Cetus Protocol (2025-05-22, $223M) ────────────────────────────────────
  // Exploited checked_shlw integer overflow in CLMM math library.
  // Drained 46+ pools via flash-swap + extreme tick manipulation.
  // ~$162M frozen by Sui validators; ~$60M bridged to Ethereum via Wormhole.
  // Sources: Cyfrin, SlowMist, Merkle Science post-mortems; ZachXBT on X.
  {
    address: '0xe28b50cef1d633ea43d3296a3f6b67ff0312a5f1a99f0af753c85b8b5de8ff06',
    label: 'Cetus $223M exploiter (primary)',
    incidentDate: '2025-05-22',
    estimatedLossUsd: 223_000_000,
  },
  {
    address: '0xcd8962dad278d8b50fa0f9eb0186bfa4cbdecc6d59377214c88d0286a0ac9562',
    label: 'Cetus $223M exploiter (secondary — also frozen)',
    incidentDate: '2025-05-22',
    estimatedLossUsd: 223_000_000,
  },

  // ── Scallop Protocol (2026-04-26, $142K) ──────────────────────────────────
  // Deprecated V2 sSUI spool contract (17 months old); uninitialized
  // last_index defaulted to 0 → repeated reward claims → 150K SUI drained.
  // Funds routed through Sui-native privacy mixer.
  // Source: ExVul Security Alert (confirmed via tx 6WNDjCX3W852hipq6yrHhpUaSFHSPWfTxuLKaQkgNfVL).
  {
    address: '0x27bc7a3c4f406cfa91551c32490ad7f5029414578c0649ab4ddbd232e76ef44e',
    label: 'Scallop deprecated-contract exploiter',
    incidentDate: '2026-04-26',
    estimatedLossUsd: 142_000,
  },

  // ── Aftermath Finance Perpetuals (2026-04-29, $1.14M) ─────────────────────
  // Negative fee parameter abuse: attacker set negative funding rates to
  // accumulate collateral from other traders' positions.
  // Source: Aftermath post-mortem; BlockSec and Beosin security alerts.
  {
    address: '0x1a65086c85114c1a3f8dc74140115c6e18438d48d33a21fd112311561112d41e',
    label: 'Aftermath Finance perpetuals fee-abuse exploiter',
    incidentDate: '2026-04-29',
    estimatedLossUsd: 1_140_000,
  },

  // ── Volo Protocol (2026-04-21, $3.5M) ────────────────────────────────────
  // Compromised admin key used to drain multiple liquid-staking vaults
  // in rapid succession. Funds laundered through cross-chain bridges.
  // Source: Volo post-mortem; SlowMist analysis.
  {
    address: '0xe76970bbf9b038974f6086009799772db5190f249ce7d065a581b1ac0adaef75',
    label: 'Volo Protocol admin-key exploiter',
    incidentDate: '2026-04-21',
    estimatedLossUsd: 3_500_000,
  },

  // ── Pawtato GameFi (2026-01-15) ───────────────────────────────────────────
  // Attacker passed a spoofed UpgradeCap to grant_admin_role, gaining minting
  // authority over the in-game token.
  // Address: not yet confirmed — update once post-mortem is published.
] as const;

/** O(1) lookup set built from KNOWN_BAD_ACTORS. */
export const KNOWN_BAD_ACTOR_ADDRESSES: ReadonlySet<string> = new Set(
  KNOWN_BAD_ACTORS.map((actor) => actor.address.toLowerCase()),
);

/**
 * Returns metadata for an address if it is a known bad actor, otherwise null.
 * Input address is normalised to lowercase before lookup.
 */
export function getKnownBadActor(address: string): KnownBadActor | null {
  const canonical = address.toLowerCase();
  return KNOWN_BAD_ACTORS.find((actor) => actor.address.toLowerCase() === canonical) ?? null;
}
