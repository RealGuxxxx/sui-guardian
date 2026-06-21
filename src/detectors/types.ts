import type { SenderHistory } from '../detection/sender-tracker.js';
import type { DerivedEvidence, MonitoringProjectConfig, ObservedTransaction, Severity } from '../types.js';

export type AttackCategory =
  | 'permission'
  | 'governance'
  | 'price-manipulation'
  | 'liquidation'
  | 'liquidity-drain'
  | 'execution-abuse'
  | 'unknown';

export interface AttackFinding {
  attackType: string;
  category: AttackCategory;
  summary: string;
  evidence: Record<string, unknown>;
  riskHints?: {
    scoreDelta?: number;
    severityFloor?: Severity;
  };
  chainHints?: {
    stage?: 'probe' | 'manipulation' | 'takeover' | 'extraction';
  };
}

export interface AttackDetectorContext {
  project: MonitoringProjectConfig;
  tx: ObservedTransaction;
  derived: DerivedEvidence;
  runtime: {
    recentAlerts: Array<{ ruleId: string; details: Record<string, unknown> }>;
    senderHistory?: SenderHistory | null;
  };
}
