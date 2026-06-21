import { describe, expect, it, beforeEach, afterEach } from 'vitest';

import { estimateUsd, formatUsd, estimateOutflowUsd } from '../src/utils/usd-estimator.js';

// Reset module price table between tests that touch env vars
beforeEach(() => {
  delete process.env['ASSET_PRICES_JSON'];
});

afterEach(() => {
  delete process.env['ASSET_PRICES_JSON'];
});

describe('estimateUsd', () => {
  it('estimates SUI correctly (9 decimals)', () => {
    // 1 SUI = 1e9 MIST, price ~$4.5 → 1e9 MIST = $4.5
    const usd = estimateUsd('0x2::sui::SUI', 1_000_000_000n);
    expect(usd).toBeCloseTo(4.5, 3);
  });

  it('estimates USDC correctly (6 decimals)', () => {
    // Wormhole USDC
    const coinType = '0x5d4b302506645c37ff133b98c4b50a406ae2a9dd::coin::COIN';
    const usd = estimateUsd(coinType, 1_000_000n); // 1 USDC
    expect(usd).toBeCloseTo(1.0, 6);
  });

  it('estimates WBTC correctly (8 decimals)', () => {
    const coinType = '0x027792d9fed7f9844eb4839566001bb6f6cb4804f66aa2da6fe1ee242d896881::coin::COIN';
    const usd = estimateUsd(coinType, 100_000_000n); // 1 WBTC
    expect(usd).toBeCloseTo(95_000, 0);
  });

  it('returns undefined for unknown coin type', () => {
    const usd = estimateUsd('0xdeadbeef::unknown::TOKEN', 1_000_000n);
    expect(usd).toBeUndefined();
  });

  it('handles negative amounts (outflows) by taking absolute value', () => {
    const usd = estimateUsd('0x2::sui::SUI', -1_000_000_000n);
    expect(usd).toBeCloseTo(4.5, 3);
  });

  it('returns 0 for amount of 0', () => {
    const usd = estimateUsd('0x2::sui::SUI', 0n);
    expect(usd).toBe(0);
  });

  it('estimates large SUI amounts correctly', () => {
    // 1000 SUI
    const usd = estimateUsd('0x2::sui::SUI', 1_000_000_000_000n);
    expect(usd).toBeCloseTo(4_500, 0);
  });
});

describe('formatUsd', () => {
  it('formats millions with 2 decimal places', () => {
    expect(formatUsd(1_500_000)).toBe('$1.50M');
    expect(formatUsd(223_000_000)).toBe('$223.00M');
  });

  it('formats thousands with 1 decimal place', () => {
    expect(formatUsd(2_300)).toBe('$2.3K');
    expect(formatUsd(142_000)).toBe('$142.0K');
  });

  it('formats small amounts with 2 decimal places', () => {
    expect(formatUsd(45)).toBe('$45.00');
    expect(formatUsd(0.5)).toBe('$0.50');
  });

  it('handles exactly $1000 as thousands', () => {
    expect(formatUsd(1_000)).toBe('$1.0K');
  });

  it('handles exactly $1M as millions', () => {
    expect(formatUsd(1_000_000)).toBe('$1.00M');
  });
});

describe('estimateOutflowUsd', () => {
  const SUI = '0x2::sui::SUI';
  const USDC = '0x5d4b302506645c37ff133b98c4b50a406ae2a9dd::coin::COIN';
  const VAULT = '0xvault0000000000000000000000000000000000000000000000000000000000';

  it('returns null when no balance changes', () => {
    const result = estimateOutflowUsd([], [VAULT]);
    expect(result).toBeNull();
  });

  it('returns null when no priced coins involved', () => {
    const changes = [
      { owner: VAULT, coinType: '0xdeadbeef::unknown::TOK', amount: '-1000000' },
    ];
    const result = estimateOutflowUsd(changes, [VAULT]);
    expect(result).toBeNull();
  });

  it('ignores inflows (positive amounts)', () => {
    const changes = [
      { owner: VAULT, coinType: SUI, amount: '1000000000' }, // positive → inflow
    ];
    const result = estimateOutflowUsd(changes, [VAULT]);
    expect(result).toBeNull();
  });

  it('ignores balance changes for non-protected addresses', () => {
    const changes = [
      { owner: '0xother000000000000000000000000000000000000000000000000000000000000', coinType: SUI, amount: '-1000000000' },
    ];
    const result = estimateOutflowUsd(changes, [VAULT]);
    expect(result).toBeNull();
  });

  it('estimates total USD outflow from protected vault', () => {
    const changes = [
      { owner: VAULT, coinType: SUI, amount: '-1000000000' }, // -1 SUI ≈ $4.5
      { owner: VAULT, coinType: USDC, amount: '-1000000' },   // -1 USDC = $1
    ];
    const result = estimateOutflowUsd(changes, [VAULT]);
    expect(result).not.toBeNull();
    expect(result!.totalUsd).toBeCloseTo(5.5, 1);
    expect(result!.breakdown).toHaveLength(2);
  });

  it('handles case-insensitive address comparison', () => {
    const changes = [
      { owner: VAULT.toUpperCase(), coinType: SUI, amount: '-1000000000' },
    ];
    const result = estimateOutflowUsd(changes, [VAULT.toLowerCase()]);
    expect(result).not.toBeNull();
    expect(result!.totalUsd).toBeCloseTo(4.5, 1);
  });

  it('handles missing owner field gracefully', () => {
    const changes = [
      { coinType: SUI, amount: '-1000000000' }, // no owner
    ];
    // TypeScript: owner is optional, we should not crash
    const result = estimateOutflowUsd(changes as Array<{ owner?: string; coinType: string; amount: string }>, [VAULT]);
    expect(result).toBeNull();
  });

  it('reports breakdown per coin type', () => {
    const changes = [
      { owner: VAULT, coinType: SUI, amount: '-2000000000' }, // -2 SUI ≈ $9
    ];
    const result = estimateOutflowUsd(changes, [VAULT]);
    expect(result!.breakdown[0]?.coinType).toBe(SUI);
    expect(result!.breakdown[0]?.amount).toBe('-2000000000');
    expect(result!.breakdown[0]?.usd).toBeCloseTo(9, 1);
  });
});
