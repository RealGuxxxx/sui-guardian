import { describe, expect, it } from 'vitest';

import { scoreRisk } from '../src/detection/risk-scorer.js';

describe('scoreRisk', () => {
  it('elevates severity when price deviation, baseline anomaly and attack path align', () => {
    const risk = scoreRisk({
      priceEvidence: [
        {
          label: 'oracle-price',
          deviationBps: 40000,
          referenceKind: 'rolling_median',
          extractionCoupled: true,
        },
      ],
      baselineEvidence: [
        {
          objectLabel: 'admin-vault',
          field: 'admin',
          anomalyKind: 'permission_change',
          senderAuthorized: false,
        },
      ],
      flowEvidence: {
        nodes: [],
        edges: [],
        attackPathFound: true,
        pathRoles: ['protected_outflow', 'attacker_receipt'],
        netProtectedOutflow: '1000',
        netAttackerGain: '1000',
      },
    });

    expect(risk.riskScore).toBeGreaterThanOrEqual(80);
    expect(risk.recommendedSeverity).toBe('critical');
  });
});
