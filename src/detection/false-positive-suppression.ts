import type {
  MonitoringProjectConfig,
  RiskScore,
  SuppressionDecision,
} from '../types.js';
import { sameAddress } from '../utils.js';

interface SuppressionContext {
  tx: {
    sender?: string;
    timestamp: string;
  };
  project: MonitoringProjectConfig;
  risk: RiskScore;
  evidenceSummary: string[];
  senderAuthorized: boolean;
}

export function applyFalsePositiveSuppression(ctx: SuppressionContext): SuppressionDecision {
  let finalSeverity = ctx.risk.recommendedSeverity;
  let confidencePenalty = 0;
  const reasons: string[] = [];

  const hour = new Date(ctx.tx.timestamp).getUTCHours();
  const inMaintenanceWindow = ctx.project.suppression.maintenanceWindows.some((window) =>
    window.allowedSenders.some((sender) => sameAddress(sender, ctx.tx.sender)) &&
    hour >= window.startHourUtc &&
    hour <= window.endHourUtc,
  );

  const weakSingleSignal =
    ctx.evidenceSummary.length <= 1 && ctx.risk.riskScore <= ctx.project.suppression.weakSignalScoreThreshold;

  if (inMaintenanceWindow) {
    reasons.push('maintenance_window_suppression');
    confidencePenalty += 0.2;
  }

  if (ctx.senderAuthorized && weakSingleSignal) {
    reasons.push('authorized_sender_suppression');
    confidencePenalty += 0.2;
  }

  if (reasons.length > 0) {
    finalSeverity =
      finalSeverity === 'critical'
        ? 'high'
        : finalSeverity === 'high'
          ? 'medium'
          : finalSeverity === 'medium'
            ? 'low'
            : finalSeverity;
  }

  return {
    applied: reasons.length > 0,
    reasons,
    originalSeverity: ctx.risk.recommendedSeverity,
    finalSeverity,
    confidencePenalty,
  };
}
