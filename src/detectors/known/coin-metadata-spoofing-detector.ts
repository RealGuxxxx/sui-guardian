import type { AttackDetectorContext, AttackFinding } from '../types.js';

/**
 * Coin Metadata Spoofing Detector
 *
 * Attackers create fake tokens whose `name` and `symbol` match well-known
 * assets (USDC, SUI, USDT, WBTC, etc.) to deceive wallets, UI frontends,
 * and unsuspecting users into approving transfers or adding liquidity.
 *
 * On Sui, `coin::create_currency` establishes the CoinMetadata object with
 * name, symbol, description, and icon. The pureInputs of this call contain
 * these string values.
 *
 * Attack variants:
 * 1. **Direct spoof**: name/symbol exactly matches a known asset (e.g., "USDC")
 * 2. **Look-alike**: name very similar (e.g., "USDC " with trailing space, "USDс" with Cyrillic с)
 * 3. **Inject immediately**: new fake token immediately added to a DEX pool in same PTB
 *    (variant already partially covered by spoof-token-pool-injection, but this adds metadata check)
 *
 * The existing `spoof-token-pool-injection` detector covers the timing pattern.
 * This detector specifically flags the metadata deception angle.
 */

// Well-known Sui asset names and symbols that should never be reissued
const KNOWN_ASSET_NAMES = new Set([
  'sui', 'usdc', 'usdt', 'tether', 'usd coin',
  'wbtc', 'wrapped bitcoin', 'bitcoin',
  'weth', 'wrapped ether', 'ethereum', 'ether',
  'wbnb', 'wrapped bnb',
  'dai', 'frax', 'busd',
  'sca', 'scallop',
  'cetus', 'cetus protocol',
  'turbos', 'turbos finance',
  'aftermath', 'afsui',
  'bucket', 'buck',
  'volo', 'vsui',
  'navi', 'navx',
  'deepbook',
]);

const KNOWN_ASSET_SYMBOLS = new Set([
  'sui', 'usdc', 'usdt', 'wbtc', 'weth', 'wbnb',
  'dai', 'frax', 'busd', 'usd',
  'sca', 'cetus', 'turbos', 'afsui', 'buck',
  'vsui', 'navx', 'deep',
]);

// Functions that create new coin types
const COIN_CREATE_PATTERNS = [
  'create_currency',
  'init',  // OTW pattern: coin is often created in module init
];

function isCoinCreateCall(mod: string, fn: string): boolean {
  const combined = `${mod}::${fn}`.toLowerCase();
  return (
    (combined.includes('coin') || combined.includes('token') || combined.includes('currency')) &&
    COIN_CREATE_PATTERNS.some((p) => fn.toLowerCase() === p || fn.toLowerCase().includes(p))
  );
}

/** Normalize a string for comparison: lowercase, trim, remove zero-width chars */
function normalize(s: string): string {
  return s
    .toLowerCase()
    .trim()
    .replace(/[\u200b-\u200f\u2028\u2029\ufeff]/g, '') // zero-width / invisible chars
    .replace(/\s+/g, ' ');
}

function isSpoofedMetadata(pureInputs: Array<string | boolean>): {
  isSpoofed: boolean;
  matchedName?: string;
  suspicious?: string;
} {
  for (const input of pureInputs) {
    if (typeof input !== 'string') continue;
    const normalized = normalize(input);
    if (KNOWN_ASSET_NAMES.has(normalized) || KNOWN_ASSET_SYMBOLS.has(normalized)) {
      return { isSpoofed: true, matchedName: input, suspicious: normalized };
    }
    // Check for common homoglyph substitutions (a→а Cyrillic, o→о, etc.)
    const dehomoglyphed = normalized
      .replace(/а/g, 'a').replace(/е/g, 'e').replace(/о/g, 'o')
      .replace(/р/g, 'p').replace(/с/g, 'c').replace(/х/g, 'x');
    if (dehomoglyphed !== normalized && (KNOWN_ASSET_NAMES.has(dehomoglyphed) || KNOWN_ASSET_SYMBOLS.has(dehomoglyphed))) {
      return { isSpoofed: true, matchedName: input, suspicious: `homoglyph: "${normalized}" → "${dehomoglyphed}"` };
    }
  }
  return { isSpoofed: false };
}

export function detectCoinMetadataSpoofingAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const { tx } = ctx;

  // Only fire if a new package was published (coin type requires a package)
  const hasNewPackage = tx.objectChanges.some((o) => o.isPackage && o.idCreated);
  if (!hasNewPackage) return [];

  const coinCreateCalls = tx.calls.filter((c) => isCoinCreateCall(c.module, c.function));
  if (coinCreateCalls.length === 0) return [];

  const spoofedCalls: Array<{ fn: string; matchedName: string; suspicious: string }> = [];

  for (const call of coinCreateCalls) {
    const result = isSpoofedMetadata(call.pureInputs ?? []);
    if (result.isSpoofed && result.matchedName && result.suspicious) {
      spoofedCalls.push({
        fn: `${call.module}::${call.function}`,
        matchedName: result.matchedName,
        suspicious: result.suspicious,
      });
    }
  }

  if (spoofedCalls.length === 0) return [];

  // Extra signal: immediately injected into a pool in same TX
  const hasPoolInjection = tx.calls.some((c) => {
    const fn = c.function.toLowerCase();
    return /add_liquidity|create_pool|register_pool|inject|deposit/.test(fn);
  });

  return [
    {
      attackType: 'coin-metadata-spoofing',
      category: 'execution-abuse',
      summary: `检测到伪造代币元数据：新发布包中 ${spoofedCalls[0]?.fn} 创建了名称与已知资产相同的代币（"${spoofedCalls[0]?.matchedName}"）${hasPoolInjection ? '，且立即注入流动性池' : ''}`,
      evidence: {
        sender: tx.sender,
        spoofedCalls,
        hasPoolInjection,
        hasNewPackage: true,
      },
      riskHints: {
        scoreDelta: hasPoolInjection ? 45 : 35,
        severityFloor: 'high',
      },
      chainHints: {
        stage: hasPoolInjection ? 'manipulation' : 'probe',
      },
    },
  ];
}
