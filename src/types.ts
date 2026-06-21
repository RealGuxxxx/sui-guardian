export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type AlertStatus = 'open' | 'acknowledged' | 'resolved';

export interface PackageWatchConfig {
  label?: string;
  address: string;
  allowedUpgradeSenders?: string[];
  /** Known deprecated/superseded addresses for this package.
   *  Any transaction calling one of these addresses triggers a high-severity alert
   *  (Scallop pattern: attacker calls old contract still live on-chain). */
  deprecatedAddresses?: string[];
}

export interface ProtectedAddressConfig {
  label: string;
  address: string;
  outflowThresholds: Record<string, string>;
  allowedSenders?: string[];
}

export interface FunctionGuardConfig {
  label: string;
  package: string;
  module: string;
  function: string;
  allowedSenders: string[];
  severity?: Severity;
}

export interface TrafficSpikeConfig {
  label: string;
  package: string;
  windowSeconds: number;
  txCountThreshold: number;
  uniqueSenderThreshold: number;
  severity?: Severity;
  cooldownSeconds?: number;
}

export interface FailureSpikeConfig {
  label: string;
  package: string;
  windowSeconds: number;
  failedTxThreshold: number;
  severity?: Severity;
  cooldownSeconds?: number;
}

export interface TrackedObjectConfig {
  label: string;
  address: string;
  watchFields?: string[];
  criticalFields?: string[];
  numericDecreaseThresholds?: Record<string, string>;
  severity?: Severity;
}

export interface SuspiciousTargetConfig {
  label: string;
  address: string;
}

export interface BehaviorRuleConfig {
  enabled: boolean;
  minRepeatedCalls: number;
  minProtectedOutflow: string;
  priceDeviationThresholdBps: number;
}

export interface AttackDetectorConfig {
  enabled: boolean;
}

export interface PriceModelConfig {
  label: string;
  trackedObjectLabel: string;
  observedFieldPath: string;
  referenceMode: 'tracked_field' | 'rolling_median' | 'fixed_range';
  referenceObjectLabel?: string;
  referenceFieldPath?: string;
  fixedLowerBound?: string;
  fixedUpperBound?: string;
  deviationThresholdBps: number;
}

export interface ObjectBaselineFieldConfig {
  path: string;
  kind: 'permission' | 'price' | 'inventory' | 'state';
  allowedSenders?: string[];
  maxDeltaBps?: number;
  maxAbsoluteDecrease?: string;
}

export interface ObjectBaselineConfig {
  label: string;
  trackedObjectLabel: string;
  fields: ObjectBaselineFieldConfig[];
}

export interface FlowTrackingConfig {
  enabled: boolean;
  minProtectedOutflow: string;
  attackerGainThreshold: string;
  shortWindowTxCount: number;
}

export interface MaintenanceWindowConfig {
  label: string;
  allowedSenders: string[];
  startHourUtc: number;
  endHourUtc: number;
}

export interface SuppressionConfig {
  enabled: boolean;
  duplicateWindowSeconds: number;
  weakSignalScoreThreshold: number;
  maintenanceWindows: MaintenanceWindowConfig[];
}

export interface PriceDeviationEvidence {
  label: string;
  observedPrice?: string;
  referencePrice?: string;
  deviationBps?: number;
  thresholdBps?: number;
  thresholdExceeded?: boolean;
  referenceKind: 'tracked_field' | 'rolling_median' | 'fixed_range';
  extractionCoupled: boolean;
  incomplete?: boolean;
}

export interface ObjectBaselineEvidence {
  objectLabel: string;
  field: string;
  previousValue?: string;
  currentValue?: string;
  expectedRange?: string;
  anomalyKind: 'permission_change' | 'price_shift' | 'inventory_drop' | 'state_flip';
  senderAuthorized: boolean;
}

export interface FundFlowNode {
  address: string;
  role: 'sender' | 'gas_sponsor' | 'protected' | 'attacker' | 'intermediate';
}

export interface FundFlowEdge {
  from: string;
  to: string;
  coinType: string;
  amount: string;
  role: 'temporary_funding' | 'manipulation_target' | 'protected_outflow' | 'attacker_receipt' | 'intermediate_hop';
}

export interface FundFlowGraph {
  nodes: FundFlowNode[];
  edges: FundFlowEdge[];
  attackPathFound: boolean;
  pathRoles: string[];
  netProtectedOutflow: string;
  netAttackerGain: string;
  windowEntryCount?: number;
  windowDigests?: string[];
  windowStartAt?: string;
  windowEndAt?: string;
}

export interface FlowHistoryEntry {
  projectId: string;
  digest: string;
  timestamp: string;
  sender?: string;
  flashLikeFundingDetected: boolean;
  manipulationDetected: boolean;
  netProtectedOutflow: string;
  netAttackerGain: string;
}

export interface SuppressionDecision {
  applied: boolean;
  reasons: string[];
  originalSeverity: Severity;
  finalSeverity: Severity;
  confidencePenalty: number;
}

export interface RiskScore {
  riskScore: number;
  confidence: number;
  recommendedSeverity: Severity;
}

export interface DerivedEvidence {
  flashLikeFundingDetected?: boolean;
  priceDeviationBps?: number;
  suspiciousTargets?: string[];
  sameSensitiveCallRepeats?: Record<string, number>;
  valueExtractionDetected?: boolean;
  priceEvidence?: PriceDeviationEvidence[];
  baselineEvidence?: ObjectBaselineEvidence[];
  flowEvidence?: FundFlowGraph;
  suppression?: SuppressionDecision;
  risk?: RiskScore;
  evidenceSummary?: string[];
  attackFindings?: import('./detectors/types.js').AttackFinding[];
}

export interface ObjectBaselineProfile {
  projectId: string;
  objectLabel: string;
  fields: Record<string, {
    lastValue?: string;
    minValue?: string;
    maxValue?: string;
    lastSender?: string;
    lastUpdatedAt?: string;
  }>;
}

export interface PriceReferenceProfile {
  projectId: string;
  label: string;
  recentObservedPrices: string[];
  medianPrice?: string;
  updatedAt: string;
}

export interface AddressBehaviorProfile {
  projectId: string;
  address: string;
  lastSeenAt: string;
  recentIncidentFingerprints: string[];
}

export interface MonitoringProjectConfig {
  id: string;
  name: string;
  packages: PackageWatchConfig[];
  protectedAddresses: ProtectedAddressConfig[];
  functionGuards: FunctionGuardConfig[];
  trafficSpikes: TrafficSpikeConfig[];
  failureSpikes: FailureSpikeConfig[];
  trackedObjects: TrackedObjectConfig[];
  suspiciousTargets: SuspiciousTargetConfig[];
  behaviorRules: BehaviorRuleConfig;
  attackDetectors?: AttackDetectorConfig;
  priceModels: PriceModelConfig[];
  objectBaselines: ObjectBaselineConfig[];
  flowTracking: FlowTrackingConfig;
  suppression: SuppressionConfig;
}

export interface AiRulesShadowConfig {
  enabled: boolean;
  notify: boolean;
  minMinutes: number;
}

export interface AiRulesCanaryConfig {
  enabled: boolean;
  stage: 'shadow' | 'traffic_failure' | 'objects_prices' | 'full';
  promotionMinMinutes: number;
}

export interface AiRulesGeneratorConfig {
  enabled: boolean;
  sourceRoot: string;
  deploymentsDir: string;
  modelBaseUrl: string;
  modelName: string;
  regenerateIntervalHours: number;
}

export interface AiRulesConfig {
  enabled: boolean;
  generatedDir: string;
  reloadIntervalMs: number;
  shadow: AiRulesShadowConfig;
  canary: AiRulesCanaryConfig;
  generator: AiRulesGeneratorConfig;
}

export interface AppConfig {
  network: {
    name: string;
    graphqlEndpoint: string;
    pollIntervalMs: number;
    bootstrapLookbackCheckpoints: number;
    checkpointOverlap: number;
    maxCheckpointsPerTick: number;
    maxTransactionsPerPage: number;
  };
  storage: {
    stateFile: string;
    maxAlerts: number;
  };
  server: {
    host: string;
    port: number;
  };
  alerts: {
    console: boolean;
    webhookUrl?: string;
  };
  aiRules?: AiRulesConfig;
  projects: MonitoringProjectConfig[];
}

export interface SubmissionReadinessCheck {
  id: string;
  label: string;
  status: 'pass' | 'warn' | 'fail';
  required: boolean;
  evidence: string;
  action: string;
}

export interface SubmissionReadiness {
  generatedAt: string;
  targetTrack: string;
  secondaryTrack: string;
  handbookUrl: string;
  score: number;
  status: 'ready' | 'needs-work' | 'blocked';
  summary: string;
  checks: SubmissionReadinessCheck[];
  criticalGaps: string[];
  submissionAssets: Array<{
    label: string;
    path: string;
    purpose: string;
  }>;
}

export interface ObservedCall {
  package: string;
  module: string;
  function: string;
  /** Resolved pure (non-object) argument values for this call — u64/u128 as string, bool as boolean.
   *  Only populated when the argument is a direct Input reference to a pure value in the PTB inputs array.
   *  Enables detectors to check e.g. minAmountOut=0, dust liquidity amounts, zero tick ranges. */
  pureInputs?: Array<string | boolean>;
}

export interface ObservedBalanceChange {
  owner?: string;
  coinType: string;
  amount: string;
}

export interface ObservedObjectChange {
  address: string;
  idCreated: boolean;
  idDeleted: boolean;
  inputVersion?: number;
  outputVersion?: number;
  isPackage: boolean;
}

export interface ObservedTransaction {
  digest: string;
  checkpoint: number;
  timestamp: string;
  sender?: string;
  gasSponsor?: string;
  gasPrice?: string;
  gasBudget?: string;
  status: 'SUCCESS' | 'FAILURE';
  executionError?: string;
  calls: ObservedCall[];
  balanceChanges: ObservedBalanceChange[];
  objectChanges: ObservedObjectChange[];
}

export interface Alert {
  id: string;
  createdAt: string;
  projectId: string;
  projectName: string;
  ruleId: string;
  ruleName: string;
  severity: Severity;
  summary: string;
  details: Record<string, unknown>;
}

export interface IncidentAlert extends Alert {
  fingerprint: string;
  status: AlertStatus;
  firstSeenAt: string;
  lastSeenAt: string;
  updatedAt: string;
  occurrences: number;
  note?: string;
  /** ISO-8601 timestamp when the alert was first acknowledged */
  acknowledgedAt?: string;
  /** ISO-8601 timestamp when the alert was resolved */
  resolvedAt?: string;
  /** Seconds from firstSeenAt to acknowledgedAt (null if not yet acknowledged) */
  ackResponseSeconds?: number;
  /** Estimated USD value of the detected outflow (if calculable) */
  estimatedUsd?: number;
}

export interface PackageVersionSnapshot {
  packageAddress: string;
  version: number;
  digest?: string;
  sender?: string;
  updatedAt: string;
}

export interface ObjectSnapshot {
  label: string;
  address: string;
  projectId: string;
  projectName: string;
  version?: number;
  digest?: string;
  type?: string;
  contents: Record<string, unknown>;
  updatedAt: string;
}

export interface ScanRecord {
  id: string;
  startedAt: string;
  finishedAt: string;
  latestCheckpoint: number;
  checkpointsProcessed: number;
  transactionsProcessed: number;
  alertsTriggered: number;
  durationMs: number;
  success: boolean;
  error?: string;
}

export interface RuntimeState {
  lastCheckpoint: number;
  packageVersions: Record<string, PackageVersionSnapshot>;
  trackedObjectSnapshots: Record<string, ObjectSnapshot>;
  priceReferenceProfiles: Record<string, PriceReferenceProfile>;
  objectBaselineProfiles: Record<string, ObjectBaselineProfile>;
  flowHistory?: Record<string, FlowHistoryEntry[]>;
  recentTransactionDigests: string[];
  recentAlerts: IncidentAlert[];
  scanHistory: ScanRecord[];
  updatedAt: string;
}

export interface ScanSummary {
  latestCheckpoint: number;
  checkpointsProcessed: number;
  transactionsProcessed: number;
  alertsTriggered: number;
  durationMs: number;
  success: boolean;
  error?: string;
}

export interface AlertFilters {
  status?: AlertStatus;
  projectId?: string;
  severity?: Severity;
  limit?: number;
}
