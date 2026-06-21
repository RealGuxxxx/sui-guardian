import type { AttackDetectorContext, AttackFinding } from '../types.js';

/**
 * Detects repeat attackers: the same sender has triggered 3 or more alerts
 * within the rolling 60-minute window, indicating a sustained attack campaign.
 *
 * This catches the probe → position-build → exploit pattern where an attacker
 * sends multiple suspicious transactions before the main exploit.
 *
 * Threshold is 3 (not 2) to avoid false positives for legitimate MEV bots that
 * may occasionally trigger slippage or traffic-spike detectors.
 */
export function detectRepeatAttacker(ctx: AttackDetectorContext): AttackFinding[] {
  const { senderHistory } = ctx.runtime;
  if (!senderHistory) return [];

  const { alertCount, windowMinutes, txCount, recentAlertRuleIds } = senderHistory;

  // Require at least 3 prior alerts to reduce false positives
  if (alertCount < 3) return [];

  // Calculate alert density: alerts per tx
  const alertDensity = txCount > 0 ? alertCount / txCount : alertCount;

  // Higher score if the attack pattern is dense (many alerts in few TXs)
  const isDenseAttack = alertDensity >= 0.5; // ≥50% of TXs triggered alerts

  return [
    {
      attackType: 'repeat-attacker',
      category: 'unknown',
      summary: `Repeat attacker: ${alertCount} alerts in ${windowMinutes}min window (${txCount} TXs, density ${(alertDensity * 100).toFixed(0)}%)`,
      evidence: {
        alertCount,
        txCount,
        alertDensity: Number.parseFloat(alertDensity.toFixed(3)),
        windowMinutes,
        recentAlertRuleIds,
      },
      riskHints: {
        scoreDelta: isDenseAttack ? 45 : 30,
        severityFloor: isDenseAttack ? 'critical' : 'high',
      },
      chainHints: {
        stage: 'probe',
      },
    },
  ];
}
