import { describe, expect, it } from 'vitest';

import { detectCoinMetadataSpoofingAttacks } from '../src/detectors/known/coin-metadata-spoofing-detector.js';
import type { AttackDetectorContext } from '../src/detectors/types.js';
import type { MonitoringProjectConfig, ObservedTransaction } from '../src/types.js';

const PKG = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ATTACKER = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

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
  objectChanges: ObservedTransaction['objectChanges'] = [],
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
      balanceChanges: [],
      objectChanges,
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
    },
    runtime: {
      recentAlerts: [],
      senderHistory: null,
    },
  };
}

const NEW_PKG_CHANGE = [{ isPackage: true, idCreated: true, id: '0xnewpkg' }];

describe('detectCoinMetadataSpoofingAttacks', () => {
  it('returns empty when no new package published', () => {
    const ctx = buildCtx(
      [
        {
          package: PKG, module: 'coin', function: 'create_currency',
          pureInputs: ['USDC', 'USD Coin', 'Fake USDC'],
        },
      ],
      [], // no new package
    );
    expect(detectCoinMetadataSpoofingAttacks(ctx)).toHaveLength(0);
  });

  it('returns empty when no coin create call despite new package', () => {
    const ctx = buildCtx(
      [{ package: PKG, module: 'mymodule', function: 'init' }],
      NEW_PKG_CHANGE,
    );
    // 'init' without 'coin/token/currency' in module → not flagged as coin create
    expect(detectCoinMetadataSpoofingAttacks(ctx)).toHaveLength(0);
  });

  it('fires when create_currency uses known asset name "USDC"', () => {
    const ctx = buildCtx(
      [
        {
          package: PKG, module: 'coin', function: 'create_currency',
          pureInputs: ['USDC', 'USD Coin', 6, 'Some description'],
        },
      ],
      NEW_PKG_CHANGE,
    );
    const findings = detectCoinMetadataSpoofingAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.attackType).toBe('coin-metadata-spoofing');
    expect(findings[0]?.riskHints?.severityFloor).toBe('high');
    expect(findings[0]?.riskHints?.scoreDelta).toBe(35);
    expect(findings[0]?.evidence['hasPoolInjection']).toBe(false);
  });

  it('fires for known asset symbol "sui" (case-insensitive)', () => {
    const ctx = buildCtx(
      [
        {
          package: PKG, module: 'token', function: 'create_currency',
          pureInputs: ['SUI', 'Sui Token'],
        },
      ],
      NEW_PKG_CHANGE,
    );
    const findings = detectCoinMetadataSpoofingAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['spoofedCalls']).toHaveLength(1);
  });

  it('fires with higher scoreDelta when immediately injected into pool', () => {
    const ctx = buildCtx(
      [
        {
          package: PKG, module: 'coin', function: 'create_currency',
          pureInputs: ['USDT', 'Tether'],
        },
        { package: PKG, module: 'pool', function: 'add_liquidity' },
      ],
      NEW_PKG_CHANGE,
    );
    const findings = detectCoinMetadataSpoofingAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['hasPoolInjection']).toBe(true);
    expect(findings[0]?.riskHints?.scoreDelta).toBe(45);
  });

  it('detects homoglyph attack: Cyrillic "с" substituted for ASCII "c" in "usdc"', () => {
    // Cyrillic с (\u0441) looks identical to ASCII c
    const spoofedUsdc = 'usd\u0441'; // "usdc" with Cyrillic с
    const ctx = buildCtx(
      [
        {
          package: PKG, module: 'coin', function: 'create_currency',
          pureInputs: [spoofedUsdc],
        },
      ],
      NEW_PKG_CHANGE,
    );
    const findings = detectCoinMetadataSpoofingAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence['spoofedCalls'][0]?.suspicious).toContain('homoglyph');
  });

  it('does not fire for obviously different asset names', () => {
    const ctx = buildCtx(
      [
        {
          package: PKG, module: 'coin', function: 'create_currency',
          pureInputs: ['MYTOKEN', 'My Token', 'A new token'],
        },
      ],
      NEW_PKG_CHANGE,
    );
    expect(detectCoinMetadataSpoofingAttacks(ctx)).toHaveLength(0);
  });

  it('fires for "WBTC" symbol spoofing', () => {
    const ctx = buildCtx(
      [
        {
          package: PKG, module: 'coin', function: 'create_currency',
          pureInputs: ['WBTC', 'Wrapped Bitcoin'],
        },
      ],
      NEW_PKG_CHANGE,
    );
    const findings = detectCoinMetadataSpoofingAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.chainHints?.stage).toBe('probe');
  });

  it('pool injection sets stage to manipulation', () => {
    const ctx = buildCtx(
      [
        {
          package: PKG, module: 'currency', function: 'create_currency',
          pureInputs: ['cetus'],
        },
        { package: PKG, module: 'amm', function: 'create_pool' },
      ],
      NEW_PKG_CHANGE,
    );
    const findings = detectCoinMetadataSpoofingAttacks(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.chainHints?.stage).toBe('manipulation');
  });
});
