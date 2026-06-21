import { describe, expect, it } from 'vitest';

import { runBehaviorRules } from '../src/behavior-rules.ts';
import type { Alert, ObservedTransaction } from '../src/types.js';

const PACKAGE = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ADMIN = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const ATTACKER = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const VAULT = '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';

function buildTx(partial: Partial<ObservedTransaction>): ObservedTransaction {
  return {
    digest: 'tx-1',
    checkpoint: 1,
    timestamp: '2026-04-24T00:00:00.000Z',
    sender: ATTACKER,
    status: 'SUCCESS',
    calls: [],
    balanceChanges: [],
    objectChanges: [],
    ...partial,
  };
}

describe('runBehaviorRules', () => {
  it('detects unauthorized sensitive calls', () => {
    const alerts = runBehaviorRules({
      projectId: 'demo',
      projectName: 'Demo',
      tx: buildTx({
        calls: [{ package: PACKAGE, module: 'vault', function: 'emergency_withdraw' }],
      }),
      protectedAddresses: [],
      sensitiveCalls: [
        {
          label: 'emergency-withdraw',
          package: PACKAGE,
          module: 'vault',
          function: 'emergency_withdraw',
          allowedSenders: [ADMIN],
          severity: 'critical',
        },
      ],
      derived: {},
    });

    expect(alerts).toHaveLength(1);
    expect(alerts[0]?.ruleName).toContain('非授权');
  });

  it('detects repeated drain patterns', () => {
    const alerts = runBehaviorRules({
      projectId: 'demo',
      projectName: 'Demo',
      tx: buildTx({
        balanceChanges: [{ owner: VAULT, coinType: '0x2::sui::SUI', amount: '-500' }],
      }),
      protectedAddresses: [VAULT],
      sensitiveCalls: [],
      derived: {
        sameSensitiveCallRepeats: {
          'vault::withdraw': 3,
        },
      },
    });

    expect(alerts.some((alert: Alert) => alert.ruleName.includes('重复高危消耗'))).toBe(true);
  });

  it('detects flash-loan-like attack chains and price manipulation', () => {
    const alerts = runBehaviorRules({
      projectId: 'demo',
      projectName: 'Demo',
      tx: buildTx({
        calls: [
          { package: PACKAGE, module: 'flash', function: 'borrow' },
          { package: PACKAGE, module: 'dex', function: 'swap_exact' },
          { package: PACKAGE, module: 'lending', function: 'withdraw' },
          { package: PACKAGE, module: 'flash', function: 'repay' },
        ],
      }),
      protectedAddresses: [],
      sensitiveCalls: [],
      derived: {
        flashLikeFundingDetected: true,
        priceDeviationBps: 2200,
        valueExtractionDetected: true,
      },
    });

    expect(alerts.some((alert: Alert) => alert.ruleName.includes('闪电贷式攻击闭环'))).toBe(true);
    expect(alerts.some((alert: Alert) => alert.ruleName.includes('价格操纵后价值提取'))).toBe(true);
  });

  it('detects suspicious external targets', () => {
    const alerts = runBehaviorRules({
      projectId: 'demo',
      projectName: 'Demo',
      tx: buildTx({}),
      protectedAddresses: [],
      sensitiveCalls: [],
      derived: {
        suspiciousTargets: ['0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'],
      },
    });

    expect(alerts).toHaveLength(1);
    expect(alerts[0]?.severity).toBe('high');
  });

  it('emits price manipulation alert from evidence-backed critical score', () => {
    const alerts = runBehaviorRules({
      projectId: 'demo',
      projectName: 'Demo',
      tx: buildTx({}),
      protectedAddresses: [],
      sensitiveCalls: [],
      derived: {
        valueExtractionDetected: true,
        priceEvidence: [
          {
            label: 'oracle-price',
            deviationBps: 40000,
            referenceKind: 'rolling_median',
            extractionCoupled: true,
          },
        ],
        risk: {
          riskScore: 90,
          confidence: 0.9,
          recommendedSeverity: 'critical',
        },
        evidenceSummary: ['price:oracle-price:40000'],
      },
    });

    expect(alerts.some((alert: Alert) => alert.ruleId === 'behavior:price-manipulation')).toBe(true);
  });
});
