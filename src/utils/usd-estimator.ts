/**
 * Static USD price estimates for major Sui ecosystem assets.
 *
 * These are approximate reference prices used purely for financial impact
 * estimation in alerts. They do NOT drive any detection logic and should
 * not be used for trading or risk calculations.
 *
 * Operators can override these by setting ASSET_PRICES_JSON env variable:
 *   ASSET_PRICES_JSON='{"0x2::sui::SUI":4.5}'
 *
 * Prices are denominated in USD per base unit (e.g., per MIST for SUI,
 * per smallest unit for each coin).
 */

/** Coin type → price per smallest denomination unit (in USD) */
export type AssetPriceTable = Record<string, number>;

/**
 * Default price table. Keys are canonical Sui coin types.
 * Values are USD per smallest unit.
 *
 * SUI: 1 SUI = 1e9 MIST → 1 MIST = price/1e9
 * USDC/USDT: 6 decimals → 1 unit = price/1e6
 * WBTC: 8 decimals → 1 unit = price/1e8
 * WETH: 8 decimals → 1 unit = price/1e8
 */
const DEFAULT_PRICES: AssetPriceTable = {
  // Native SUI (9 decimals)
  '0x2::sui::SUI': 4.5 / 1e9,

  // Wrapped USDC — Wormhole (6 decimals)
  '0x5d4b302506645c37ff133b98c4b50a406ae2a9dd::coin::COIN': 1.0 / 1e6,
  // Bridged USDC — Circle CCTP (6 decimals)
  '0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC': 1.0 / 1e6,

  // Bridged USDT — Wormhole (6 decimals)
  '0xc060006111016b8a020ad5b33834984a437aaa7d3c74c18e09a95d48aceab08c::coin::COIN': 1.0 / 1e6,

  // Wrapped BTC — Wormhole (8 decimals)
  '0x027792d9fed7f9844eb4839566001bb6f6cb4804f66aa2da6fe1ee242d896881::coin::COIN': 95_000 / 1e8,

  // Wrapped ETH — Wormhole (8 decimals)
  '0xaf8cd5edc19c4512f4259f0bee101a40d41ebed738ade5874359610ef8eeced5::coin::COIN': 3_500 / 1e8,

  // Scallop SCA (9 decimals)
  '0x7016aae72cfc67f2fadf55769c0a7dd54291a583b63051a5ed71081cce836ac6::sca::SCA': 0.45 / 1e9,

  // Aftermath Finance (9 decimals)
  '0xf325ce1300e8dac124071d3152c5c5ee6174914f8bc2161e88329cf579246efc::afsui::AFSUI': 4.6 / 1e9,
};

let _priceTable: AssetPriceTable | null = null;

function getPriceTable(): AssetPriceTable {
  if (_priceTable) return _priceTable;

  const override = process.env['ASSET_PRICES_JSON'];
  if (override) {
    try {
      const parsed = JSON.parse(override) as Record<string, unknown>;
      _priceTable = { ...DEFAULT_PRICES };
      for (const [k, v] of Object.entries(parsed)) {
        if (typeof v === 'number') _priceTable[k] = v;
      }
      return _priceTable;
    } catch {
      // Fall through to defaults
    }
  }

  _priceTable = { ...DEFAULT_PRICES };
  return _priceTable;
}

/**
 * Estimates the USD value of `amount` units of `coinType`.
 * Returns undefined if the coin type is not in the price table.
 */
export function estimateUsd(coinType: string, amount: bigint): number | undefined {
  const prices = getPriceTable();

  // Try exact match first
  let pricePerUnit = prices[coinType];

  // Fall back to suffix match (handles versioned types like ...::coin::COIN)
  if (pricePerUnit === undefined) {
    const coinTypeLower = coinType.toLowerCase();
    for (const [key, price] of Object.entries(prices)) {
      if (coinTypeLower.endsWith(key.toLowerCase()) || key.toLowerCase().endsWith(coinTypeLower)) {
        pricePerUnit = price;
        break;
      }
    }
  }

  if (pricePerUnit === undefined) return undefined;

  const absAmount = amount < 0n ? -amount : amount;
  return Number(absAmount) * pricePerUnit;
}

/**
 * Formats a USD amount as a human-readable string.
 * e.g., 1_500_000 → "$1.50M", 2_300 → "$2.3K", 45 → "$45.00"
 */
export function formatUsd(usd: number): string {
  if (usd >= 1_000_000) return `$${(usd / 1_000_000).toFixed(2)}M`;
  if (usd >= 1_000) return `$${(usd / 1_000).toFixed(1)}K`;
  return `$${usd.toFixed(2)}`;
}

/**
 * Given an array of balance changes, estimates total USD outflow from a set of protected addresses.
 * Returns { totalUsd, breakdown } or null if no priced coins involved.
 */
export function estimateOutflowUsd(
  balanceChanges: Array<{ owner?: string; coinType: string; amount: string }>,
  protectedAddresses: string[],
): { totalUsd: number; breakdown: Array<{ coinType: string; amount: string; usd: number }> } | null {
  const protectedSet = new Set(protectedAddresses.map((a) => a.toLowerCase()));
  const breakdown: Array<{ coinType: string; amount: string; usd: number }> = [];

  for (const change of balanceChanges) {
    if (!change.owner || !protectedSet.has(change.owner.toLowerCase())) continue;
    const amount = BigInt(change.amount ?? '0');
    if (amount >= 0n) continue; // Only outflows

    const usd = estimateUsd(change.coinType, amount);
    if (usd !== undefined && usd > 0) {
      breakdown.push({ coinType: change.coinType, amount: change.amount, usd });
    }
  }

  if (breakdown.length === 0) return null;

  const totalUsd = breakdown.reduce((sum, b) => sum + b.usd, 0);
  return { totalUsd, breakdown };
}
