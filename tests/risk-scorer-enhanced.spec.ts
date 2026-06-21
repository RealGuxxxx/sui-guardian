import { describe, expect, it } from 'vitest';

import { scoreRisk } from '../src/detection/risk-scorer.js';

describe('scoreRisk (enhanced)', () => {
  it('adds score for flash loan + extraction combo', () => {
    const risk = scoreRisk({
      priceEvidence: [],
      baselineEvidence: [],
      flowEvidence: undefined,
      flashLikeFundingDetected: true,
      valueExtractionDetected: true,
    });

    // flash loan + extraction = +20
    expect(risk.riskScore).toBe(20);
    expect(risk.recommendedSeverity).toBe('low');
  });

  it('adds score for inventory drop (unauthorized)', () => {
    const risk = scoreRisk({
      priceEvidence: [],
      baselineEvidence: [
        {
          objectLabel: 'vault',
          field: 'balance',
          anomalyKind: 'inventory_drop',
          senderAuthorized: false,
        },
      ],
      flowEvidence: undefined,
    });

    // 15 分低于 'low' 阈值（20），映射为 'info'
    expect(risk.riskScore).toBe(15);
    expect(risk.recommendedSeverity).toBe('info');
  });

  it('ignores inventory drop when sender is authorized', () => {
    const risk = scoreRisk({
      priceEvidence: [],
      baselineEvidence: [
        {
          objectLabel: 'vault',
          field: 'balance',
          anomalyKind: 'inventory_drop',
          senderAuthorized: true,
        },
      ],
      flowEvidence: undefined,
    });

    expect(risk.riskScore).toBe(0);
  });

  it('adds score for state flip (unauthorized)', () => {
    const risk = scoreRisk({
      priceEvidence: [],
      baselineEvidence: [
        {
          objectLabel: 'config',
          field: 'paused',
          anomalyKind: 'state_flip',
          senderAuthorized: false,
        },
      ],
      flowEvidence: undefined,
    });

    expect(risk.riskScore).toBe(10);
  });

  it('adds score when 2+ unique attack types are found', () => {
    const risk = scoreRisk({
      priceEvidence: [],
      baselineEvidence: [],
      flowEvidence: undefined,
      attackFindings: [
        { attackType: 'oracle-poisoning', category: 'price-manipulation', summary: '', evidence: {} },
        { attackType: 'liquidity-drain', category: 'liquidity-drain', summary: '', evidence: {} },
      ],
    });

    expect(risk.riskScore).toBe(10);
  });

  it('does not double-count same attack type', () => {
    const risk = scoreRisk({
      priceEvidence: [],
      baselineEvidence: [],
      flowEvidence: undefined,
      attackFindings: [
        { attackType: 'oracle-poisoning', category: 'price-manipulation', summary: '', evidence: {} },
        { attackType: 'oracle-poisoning', category: 'price-manipulation', summary: '', evidence: {} },
      ],
    });

    // Only 1 unique type → no bonus
    expect(risk.riskScore).toBe(0);
  });

  it('caps total score at 100', () => {
    const risk = scoreRisk({
      priceEvidence: [
        {
          label: 'oracle',
          deviationBps: 50000,
          referenceKind: 'rolling_median',
          extractionCoupled: true,
          thresholdBps: 1500,
        },
      ],
      baselineEvidence: [
        { objectLabel: 'vault', field: 'admin', anomalyKind: 'permission_change', senderAuthorized: false },
        { objectLabel: 'vault', field: 'balance', anomalyKind: 'inventory_drop', senderAuthorized: false },
        { objectLabel: 'config', field: 'paused', anomalyKind: 'state_flip', senderAuthorized: false },
      ],
      flowEvidence: {
        nodes: [],
        edges: [],
        attackPathFound: true,
        pathRoles: ['protected_outflow', 'attacker_receipt'],
        netProtectedOutflow: '1000',
        netAttackerGain: '1000',
      },
      flashLikeFundingDetected: true,
      valueExtractionDetected: true,
      attackFindings: [
        { attackType: 'oracle-poisoning', category: 'price-manipulation', summary: '', evidence: {} },
        { attackType: 'liquidity-drain', category: 'liquidity-drain', summary: '', evidence: {} },
      ],
    });

    expect(risk.riskScore).toBeLessThanOrEqual(100);
    expect(risk.recommendedSeverity).toBe('critical');
  });
});
