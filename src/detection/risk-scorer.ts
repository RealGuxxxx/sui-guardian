import type { DerivedEvidence, RiskScore } from '../types.js';

export function scoreRisk(input: Partial<DerivedEvidence>): RiskScore {
  let score = 0;

  const highDeviation = (input.priceEvidence ?? []).some((item) => (item.deviationBps ?? 0) >= 1500 && item.extractionCoupled);
  const permissionChange = (input.baselineEvidence ?? []).some(
    (item) => item.anomalyKind === 'permission_change' && !item.senderAuthorized,
  );
  const inventoryDrop = (input.baselineEvidence ?? []).some(
    (item) => item.anomalyKind === 'inventory_drop' && !item.senderAuthorized,
  );
  const stateFlip = (input.baselineEvidence ?? []).some(
    (item) => item.anomalyKind === 'state_flip' && !item.senderAuthorized,
  );
  const attackPath = input.flowEvidence?.attackPathFound ?? false;
  const flashLoanExtraction = Boolean(input.flashLikeFundingDetected && input.valueExtractionDetected);
  const uniqueAttackTypes = new Set((input.attackFindings ?? []).map((finding) => finding.attackType)).size;

  if (highDeviation) {
    score += 35;
  }
  if (permissionChange) {
    score += 30;
  }
  if (attackPath) {
    score += 35;
  }
  if (flashLoanExtraction) {
    score += 20;
  }
  if (inventoryDrop) {
    score += 15;
  }
  if (stateFlip) {
    score += 10;
  }
  if (uniqueAttackTypes >= 2) {
    score += 10;
  }

  score = Math.min(100, score);

  const recommendedSeverity =
    score >= 80 ? 'critical' :
    score >= 60 ? 'high' :
    score >= 40 ? 'medium' :
    score >= 20 ? 'low' :
    'info';

  return {
    riskScore: score,
    confidence: Math.min(1, score / 100),
    recommendedSeverity,
  };
}
