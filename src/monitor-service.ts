import { randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import type {
  Alert,
  AlertFilters,
  AlertStatus,
  AppConfig,
  IncidentAlert,
  MonitoringProjectConfig,
  ObjectBaselineProfile,
  ObjectSnapshot,
  PriceReferenceProfile,
  RuntimeState,
  ScanRecord,
  ScanSummary,
  Severity,
  SubmissionReadiness,
} from './types.js';
import { AlertDispatcher } from './alert-dispatcher.js';
import { SenderTracker } from './detection/sender-tracker.js';
import { SuiGraphqlClient } from './graphql-client.js';
import { loadGeneratedProjectRules, mergeProjectRules } from './generated-rules.js';
import { ProjectMonitor } from './project-monitor.js';
import { buildSubmissionReadiness } from './readiness.js';
import { StateStore } from './state-store.js';
import { buildAlertFingerprint, canonicalizeSuiAddress, errorMessage, getValueAtPath, nowIso, severityRank } from './utils.js';

interface IncidentGroup {
  incidentId: string;
  projectId: string;
  bucket: number;
  projectName: string;
  severity: Severity;
  status: AlertStatus;
  alertCount: number;
  ruleNames: Set<string>;
  summaries: Set<string>;
  digests: Set<string>;
  senders: Set<string>;
  affectedAddresses: Set<string>;
  categories: Set<string>;
  fieldChanges: Map<string, {
    address: string;
    field: string;
    previousValue: string;
    currentValue: string;
  }>;
  fundFlows: Map<string, {
    address: string;
    coinType: string;
    amount: string;
  }>;
  riskScore?: number;
  suppressionReasons: Set<string>;
  attackTypes: Set<string>;
  chainStages: Set<string>;
  chainStartDigest?: string;
  chainEndDigest?: string;
  startedAt: string;
  updatedAt: string;
}

export class MonitorService {
  private readonly client: SuiGraphqlClient;
  private readonly stateStore: StateStore;
  private readonly alertDispatcher: AlertDispatcher;
  private readonly senderTracker = new SenderTracker(60); // 60-minute rolling window
  private monitors: ProjectMonitor[];
  private readonly baseProjects: AppConfig['projects'];
  private consecutiveScanFailures = 0;
  private state: RuntimeState = {
    lastCheckpoint: 0,
    packageVersions: {},
    trackedObjectSnapshots: {},
    priceReferenceProfiles: {},
    objectBaselineProfiles: {},
    flowHistory: {},
    recentTransactionDigests: [],
    recentAlerts: [],
    scanHistory: [],
    updatedAt: nowIso(),
  };
  private timer?: NodeJS.Timeout;
  private scanInFlight = false;
  private latestKnownCheckpoint = 0;
  private rulesReloadTimer?: NodeJS.Timeout;
  private lastRulesHash = '';
  private activeAiStage: NonNullable<AppConfig['aiRules']>['canary']['stage'] | 'full' = 'full';

  private readonly dynamicProjectsFile: string;

  constructor(private config: AppConfig) {
    this.client = new SuiGraphqlClient(config.network.graphqlEndpoint);
    this.stateStore = new StateStore(config.storage.stateFile, config.storage.maxAlerts);
    this.alertDispatcher = new AlertDispatcher(config.alerts.console, config.alerts.webhookUrl);
    this.monitors = config.projects.map((project) => new ProjectMonitor(project));
    this.baseProjects = config.projects.map((project) => project);
    this.dynamicProjectsFile = path.join(path.dirname(config.storage.stateFile), 'dynamic-projects.json');
  }

  async initialize(): Promise<void> {
    this.state = await this.stateStore.load();
    this.latestKnownCheckpoint = await this.client.getLatestCheckpoint();

    // Load dynamically added projects (from POST /api/projects) and merge them
    const dynamicProjects = await this.loadDynamicProjects();
    if (dynamicProjects.length > 0) {
      this.mergeDynamicProjectsIntoConfig(dynamicProjects);
    }

    if (this.config.projects.length === 0) {
      this.state = this.stateStore.setLastCheckpoint(this.state, this.latestKnownCheckpoint);
      await this.stateStore.save(this.state);
      return;
    }

    if (this.state.lastCheckpoint === 0) {
      const bootstrap = Math.max(0, this.latestKnownCheckpoint - this.config.network.bootstrapLookbackCheckpoints);
      this.state = this.stateStore.setLastCheckpoint(this.state, bootstrap);
    }

    for (const snapshot of Object.values(this.state.packageVersions)) {
      for (const monitor of this.monitors) {
        monitor.seedPackageVersion(snapshot);
      }
    }

    this.hydrateMonitorsFromState();

    await this.bootstrapPackageVersions();
    await this.bootstrapTrackedObjectSnapshots();
    this.syncFlowHistoryFromMonitors();
    await this.reloadGeneratedRulesOnce();
    await this.stateStore.save(this.state);
  }

  start(): void {
    this.timer = setInterval(() => {
      void this.scanOnce().catch((error) => {
        console.error(`[MONITOR] Scheduled scan failed: ${errorMessage(error)}`);
      });
    }, this.config.network.pollIntervalMs);

    const aiRules = this.config.aiRules;
    if (aiRules?.enabled) {
      this.rulesReloadTimer = setInterval(() => {
        void this.reloadGeneratedRulesOnce().catch((error) => {
          console.error(`[MONITOR] Generated rule reload failed: ${errorMessage(error)}`);
        });
      }, aiRules.reloadIntervalMs);
    }
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
    if (this.rulesReloadTimer) {
      clearInterval(this.rulesReloadTimer);
      this.rulesReloadTimer = undefined;
    }
  }

  async reloadGeneratedRulesOnce(): Promise<boolean> {
    const aiRules = this.config.aiRules;
    if (!aiRules?.enabled) {
      return false;
    }

    const generated = await loadGeneratedProjectRules(aiRules.generatedDir);
    const mergedProjects = this.baseProjects.map((project) => mergeProjectRules(project, generated[project.id]));
    const stage = aiRules.canary.enabled ? aiRules.canary.stage : 'full';
    this.activeAiStage = stage;
    const stageProjects = mergedProjects.map((project, index) =>
      this.selectRulesForStage(this.baseProjects[index]!, project, stage),
    );
    const hash = JSON.stringify(stageProjects);
    if (hash === this.lastRulesHash) {
      return false;
    }

    this.config = {
      ...this.config,
      projects: stageProjects,
    };
    this.monitors = stageProjects.map((project) => new ProjectMonitor(project));
    for (const snapshot of Object.values(this.state.packageVersions)) {
      for (const monitor of this.monitors) {
        monitor.seedPackageVersion(snapshot);
      }
    }
    this.hydrateMonitorsFromState();
    this.lastRulesHash = hash;
    return true;
  }

  private selectRulesForStage(
    base: AppConfig['projects'][number],
    merged: AppConfig['projects'][number],
    stage: NonNullable<AppConfig['aiRules']>['canary']['stage'] | 'full',
  ): AppConfig['projects'][number] {
    if (stage === 'full') {
      return merged;
    }
    if (stage === 'shadow') {
      return merged;
    }
    if (stage === 'traffic_failure') {
      return {
        ...base,
        trafficSpikes: merged.trafficSpikes,
        failureSpikes: merged.failureSpikes,
      };
    }
    return {
      ...base,
      trafficSpikes: merged.trafficSpikes,
      failureSpikes: merged.failureSpikes,
      trackedObjects: merged.trackedObjects,
      objectBaselines: merged.objectBaselines,
      priceModels: merged.priceModels,
    };
  }

  /** Hot-add or update a project config and immediately begin monitoring it. */
  async upsertProject(project: MonitoringProjectConfig): Promise<void> {
    // Normalize addresses
    const normalized = normalizeProjectAddresses(project);

    const existingIndex = this.config.projects.findIndex((p) => p.id === normalized.id);
    if (existingIndex >= 0) {
      this.config.projects[existingIndex] = normalized;
      this.monitors[existingIndex] = new ProjectMonitor(normalized);
    } else {
      this.config.projects.push(normalized);
      this.monitors.push(new ProjectMonitor(normalized));
    }

    // Hydrate the new monitor with existing state
    const newIndex = this.config.projects.findIndex((p) => p.id === normalized.id);
    if (newIndex >= 0) {
      for (const snapshot of Object.values(this.state.packageVersions)) {
        this.monitors[newIndex]?.seedPackageVersion(snapshot);
      }
      for (const snapshot of Object.values(this.state.trackedObjectSnapshots)) {
        if (snapshot.projectId === normalized.id) {
          this.seedMonitorFromTrackedSnapshot(newIndex, snapshot);
        }
      }
    }

    // Bootstrap packages and tracked objects for the new project
    await this.bootstrapProjectPackages(normalized);
    await this.bootstrapProjectTrackedObjects(normalized);

    await this.saveDynamicProject(normalized);
  }

  /** Remove a dynamically added project from monitoring. Base (config-file) projects cannot be removed. */
  async removeProject(projectId: string): Promise<boolean> {
    const isBase = this.baseProjects.some((p) => p.id === projectId);
    if (isBase) return false;

    const index = this.config.projects.findIndex((p) => p.id === projectId);
    if (index < 0) return false;

    this.config.projects.splice(index, 1);
    this.monitors.splice(index, 1);
    await this.deleteDynamicProject(projectId);
    return true;
  }

  /** Return summary of all monitored projects (base + dynamic). */
  listProjects(): Array<{ id: string; name: string; isDynamic: boolean; packageCount: number }> {
    const baseIds = new Set(this.baseProjects.map((p) => p.id));
    return this.config.projects.map((p) => ({
      id: p.id,
      name: p.name,
      isDynamic: !baseIds.has(p.id),
      packageCount: p.packages.length,
    }));
  }

  async scanOnce(): Promise<ScanSummary> {
    if (this.scanInFlight) {
      return {
        latestCheckpoint: this.latestKnownCheckpoint,
        checkpointsProcessed: 0,
        transactionsProcessed: 0,
        alertsTriggered: 0,
        durationMs: 0,
        success: false,
        error: 'scan already in progress',
      };
    }

    this.scanInFlight = true;
    const startedAt = nowIso();
    const startedMs = Date.now();
    let checkpointsProcessed = 0;
    let transactionsProcessed = 0;
    let alertsTriggered = 0;

    try {
      this.latestKnownCheckpoint = await this.client.getLatestCheckpoint();

      if (this.config.projects.length === 0) {
        this.state = this.stateStore.setLastCheckpoint(this.state, this.latestKnownCheckpoint);
        const summary: ScanSummary = {
          latestCheckpoint: this.latestKnownCheckpoint,
          checkpointsProcessed: 0,
          transactionsProcessed: 0,
          alertsTriggered: 0,
          durationMs: Date.now() - startedMs,
          success: true,
        };
        this.state = this.stateStore.appendScanRecord(this.state, this.toScanRecord(startedAt, summary));
        await this.stateStore.save(this.state);
        return summary;
      }

      const scanStartCheckpoint = Math.max(0, this.state.lastCheckpoint - this.config.network.checkpointOverlap);
      const checkpointNumbers = await this.client.getCheckpointsAfter(
        scanStartCheckpoint,
        this.config.network.maxCheckpointsPerTick + this.config.network.checkpointOverlap,
      );
      checkpointsProcessed = checkpointNumbers.length;

      for (const checkpointNumber of checkpointNumbers) {
        const transactions = await this.client.getCheckpointTransactions(
          checkpointNumber,
          this.config.network.maxTransactionsPerPage,
        );
        transactionsProcessed += transactions.length;

        const alerts: Alert[] = [];
        for (const tx of transactions) {
          if (this.state.recentTransactionDigests.includes(tx.digest)) {
            continue;
          }

          this.state = this.stateStore.pushProcessedDigest(this.state, tx.digest);
          // Pass the last 50 recent alerts so cross-TX detectors (e.g. bridge-burst) can see prior signals
          const recentAlertsForDetectors = this.state.recentAlerts
            .slice(-50)
            .map((a) => ({ ruleId: a.ruleId, details: a.details }));
          // Sender history from PRIOR TXs (tracker updated after this TX runs)
          const txTimestampMs = tx.timestamp ? Date.parse(tx.timestamp) : Date.now();
          const txSender = tx.sender ?? '';
          const senderHistory = txSender ? this.senderTracker.getSenderHistory(txSender, txTimestampMs) : null;
          const txAlerts: Alert[] = [];
          for (const monitor of this.monitors) {
            txAlerts.push(...monitor.processTransaction(tx, recentAlertsForDetectors, senderHistory));
          }
          // Record TX in tracker AFTER detectors ran (so history reflects prior alerts only)
          if (txSender) {
            this.senderTracker.recordTx(txSender, txTimestampMs, txAlerts.map((a) => a.ruleId));
          }
          alerts.push(...txAlerts);
        }

        for (const alert of alerts) {
          await this.recordAlert(alert);
          alertsTriggered += 1;
        }

        this.state = this.stateStore.setLastCheckpoint(this.state, checkpointNumber);
      }

      const packageAlerts = await this.refreshPackageVersions();
      for (const alert of packageAlerts) {
        await this.recordAlert(alert);
        alertsTriggered += 1;
      }

      const trackedObjectAlerts = await this.refreshTrackedObjects();
      for (const alert of trackedObjectAlerts) {
        await this.recordAlert(alert);
        alertsTriggered += 1;
      }

      const summary: ScanSummary = {
        latestCheckpoint: this.latestKnownCheckpoint,
        checkpointsProcessed,
        transactionsProcessed,
        alertsTriggered,
        durationMs: Date.now() - startedMs,
        success: true,
      };

      this.consecutiveScanFailures = 0; // reset on success
      this.syncFlowHistoryFromMonitors();
      this.state = this.stateStore.appendScanRecord(this.state, this.toScanRecord(startedAt, summary));
      await this.stateStore.save(this.state);
      return summary;
    } catch (error) {
      this.consecutiveScanFailures += 1;

      const summary: ScanSummary = {
        latestCheckpoint: this.latestKnownCheckpoint,
        checkpointsProcessed,
        transactionsProcessed,
        alertsTriggered,
        durationMs: Date.now() - startedMs,
        success: false,
        error: errorMessage(error),
      };

      this.state = this.stateStore.appendScanRecord(this.state, this.toScanRecord(startedAt, summary));
      await this.stateStore.save(this.state);

      // Self-monitoring: alert when the scanner is repeatedly failing
      if (this.consecutiveScanFailures >= 3) {
        console.error(
          `[MONITOR HEALTH] ${this.consecutiveScanFailures} consecutive scan failures. Last error: ${errorMessage(error)}`,
        );
        // Dispatch a synthetic alert so webhooks are notified
        try {
          await this.alertDispatcher.dispatch({
            id: `scanner-health-${Date.now()}`,
            createdAt: nowIso(),
            projectId: 'sui-guardian',
            projectName: 'Sui Guardian',
            ruleId: 'monitor:consecutive-scan-failures',
            ruleName: '监控健康检查 / 连续扫描失败',
            severity: 'critical',
            summary: `监控器健康告警：连续 ${this.consecutiveScanFailures} 次扫描失败。最后错误：${errorMessage(error)}`,
            details: {
              consecutiveFailures: this.consecutiveScanFailures,
              lastError: errorMessage(error),
              lastCheckpoint: this.latestKnownCheckpoint,
            },
          });
        } catch {
          // Don't let alert dispatch errors mask the underlying scan error
        }
      }

      throw error;
    } finally {
      this.scanInFlight = false;
    }
  }

  getState(): RuntimeState {
    return this.state;
  }

  getHealth(): { ok: boolean; lastCheckpoint: number; updatedAt: string; consecutiveScanFailures: number } {
    return {
      ok: this.consecutiveScanFailures < 3,
      lastCheckpoint: this.state.lastCheckpoint,
      updatedAt: this.state.updatedAt,
      consecutiveScanFailures: this.consecutiveScanFailures,
    };
  }

  getAlerts(filters: AlertFilters = {}): IncidentAlert[] {
    const filtered = this.state.recentAlerts.filter((alert) => {
      if (filters.status && alert.status !== filters.status) {
        return false;
      }
      if (filters.projectId && alert.projectId !== filters.projectId) {
        return false;
      }
      if (filters.severity && alert.severity !== filters.severity) {
        return false;
      }
      return true;
    });

    return filtered.slice(0, filters.limit ?? this.config.storage.maxAlerts);
  }

  getScanHistory(limit = 20): ScanRecord[] {
    return this.state.scanHistory.slice(0, limit);
  }

  getAssets(projectId?: string): Array<ObjectSnapshot & {
    priceProfiles: PriceReferenceProfile[];
    baselineProfile?: ObjectBaselineProfile;
  }> {
    const snapshots = Object.values(this.state.trackedObjectSnapshots);
    const filtered = projectId ? snapshots.filter((item) => item.projectId === projectId) : snapshots;
    return filtered
      .sort((left, right) => left.label.localeCompare(right.label, 'zh-CN'))
      .map((snapshot) => ({
        ...snapshot,
        priceProfiles: Object.values(this.state.priceReferenceProfiles).filter(
          (profile) =>
            profile.projectId === snapshot.projectId &&
            this.config.projects
              .find((project) => project.id === snapshot.projectId)
              ?.priceModels.some(
                (model) => model.label === profile.label && model.trackedObjectLabel === snapshot.label,
              ),
        ),
        baselineProfile: this.state.objectBaselineProfiles[`${snapshot.projectId}:${snapshot.label}`],
      }));
  }

  getIncidentTimeline(limit = 10): Array<{
    incidentId: string;
    projectId: string;
    projectName: string;
    severity: Severity;
    status: AlertStatus;
    alertCount: number;
    ruleNames: string[];
    summaries: string[];
    digests: string[];
    senders: string[];
    affectedAddresses: string[];
    categories: string[];
    fieldChanges: Array<{
      address: string;
      field: string;
      previousValue: string;
      currentValue: string;
    }>;
    fundFlows: Array<{
      address: string;
      coinType: string;
      amount: string;
    }>;
    riskScore?: number;
    suppressionReasons: string[];
    attackTypes: string[];
    chainStages: string[];
    chainPath: string[];
    attackerClusterKey?: string;
    playbookLabels: string[];
    chainStartDigest?: string;
    chainEndDigest?: string;
    chainWindowSeconds: number;
    correlationConfidence: number;
    startedAt: string;
    updatedAt: string;
  }> {
    const grouped: IncidentGroup[] = [];

    const alerts = [...this.state.recentAlerts].sort(
      (left, right) => Date.parse(left.firstSeenAt) - Date.parse(right.firstSeenAt),
    );

    for (const alert of alerts) {
      const category = classifyIncidentCategory(alert.ruleId);

      const bucket = Math.floor(Date.parse(alert.firstSeenAt) / (10 * 60 * 1000));
      const digests = extractTimelineDigests(alert.details);
      const senders = extractTimelineSenders(alert.details);
      const addresses = extractTimelineAddresses(alert.details);
      const fieldChanges = extractTimelineFieldChanges(alert.details);
      const fundFlows = extractTimelineFundFlows(alert.details);
      const riskScore = extractTimelineRiskScore(alert.details);
      const suppressionReasons = extractTimelineSuppressionReasons(alert.details);
      const attackFindings = extractAttackFindings(alert.ruleId, alert.details);
      let existing = findIncidentGroup(grouped, {
        projectId: alert.projectId,
        bucket,
        digests,
        senders,
        addresses,
      });

      if (!existing) {
        existing = {
          incidentId: `${alert.projectId}:${bucket}:${grouped.filter((item) => item.projectId === alert.projectId && item.bucket === bucket).length + 1}`,
          projectId: alert.projectId,
          bucket,
          projectName: alert.projectName,
          severity: alert.severity,
          status: alert.status,
          alertCount: 1,
          ruleNames: new Set([alert.ruleName]),
          summaries: new Set([alert.summary]),
          digests: new Set(digests),
          senders: new Set(senders),
          affectedAddresses: new Set(addresses),
          categories: new Set([category]),
          fieldChanges: new Map(fieldChanges.map((change) => [
            `${change.address}:${change.field}`,
            change,
          ])),
          fundFlows: new Map(fundFlows.map((flow) => [
            `${flow.address}:${flow.coinType}`,
            flow,
          ])),
          riskScore,
          suppressionReasons: new Set(suppressionReasons),
          attackTypes: new Set(attackFindings.map((item) => item.attackType)),
          chainStages: new Set(
            attackFindings
              .map((item) => item.chainHints?.stage)
              .filter((stage): stage is string => typeof stage === 'string' && stage.length > 0),
          ),
          chainStartDigest: selectPrimaryDigest(digests),
          chainEndDigest: selectPrimaryDigest(digests),
          startedAt: alert.firstSeenAt,
          updatedAt: alert.lastSeenAt,
        };
        grouped.push(existing);
        continue;
      }

      existing.alertCount += 1;
      existing.ruleNames.add(alert.ruleName);
      existing.summaries.add(alert.summary);
      for (const digest of digests) {
        existing.digests.add(digest);
      }
      for (const sender of senders) {
        existing.senders.add(sender);
      }
      for (const address of addresses) {
        existing.affectedAddresses.add(address);
      }
      existing.categories.add(category);
      for (const change of fieldChanges) {
        existing.fieldChanges.set(`${change.address}:${change.field}`, change);
      }
      for (const flow of fundFlows) {
        existing.fundFlows.set(`${flow.address}:${flow.coinType}`, flow);
      }
      if (riskScore !== undefined && (existing.riskScore === undefined || riskScore > existing.riskScore)) {
        existing.riskScore = riskScore;
      }
      for (const reason of suppressionReasons) {
        existing.suppressionReasons.add(reason);
      }
      for (const finding of attackFindings) {
        existing.attackTypes.add(finding.attackType);
        if (finding.chainHints?.stage) {
          existing.chainStages.add(finding.chainHints.stage);
        }
      }
      if (severityRank(alert.severity) > severityRank(existing.severity)) {
        existing.severity = alert.severity;
      }
      existing.status = mergeTimelineStatus(existing.status, alert.status);
      if (Date.parse(alert.firstSeenAt) < Date.parse(existing.startedAt)) {
        existing.startedAt = alert.firstSeenAt;
        existing.chainStartDigest = selectPrimaryDigest(digests) ?? existing.chainStartDigest;
      }
      if (Date.parse(alert.lastSeenAt) > Date.parse(existing.updatedAt)) {
        existing.updatedAt = alert.lastSeenAt;
        existing.chainEndDigest = selectPrimaryDigest(digests) ?? existing.chainEndDigest;
      }
    }

    return grouped
      .sort((left, right) => Date.parse(right.updatedAt) - Date.parse(left.updatedAt))
      .slice(0, limit)
      .map((item) => {
        const attackTypes = Array.from(item.attackTypes).sort();
        const chainStages = Array.from(item.chainStages).sort();
        const senders = Array.from(item.senders).sort();
        const affectedAddresses = Array.from(item.affectedAddresses).sort();

        return {
        incidentId: item.incidentId,
        projectId: item.projectId,
        projectName: item.projectName,
        severity: item.severity,
        status: item.status,
        alertCount: item.alertCount,
        ruleNames: Array.from(item.ruleNames),
        summaries: Array.from(item.summaries),
        digests: Array.from(item.digests).sort(),
        senders,
        affectedAddresses,
        categories: Array.from(item.categories).sort(),
        fieldChanges: Array.from(item.fieldChanges.values()).sort((left, right) =>
          `${left.address}:${left.field}`.localeCompare(`${right.address}:${right.field}`),
        ),
        fundFlows: Array.from(item.fundFlows.values()).sort((left, right) =>
          `${left.address}:${left.coinType}`.localeCompare(`${right.address}:${right.coinType}`),
        ),
        riskScore: item.riskScore,
        suppressionReasons: Array.from(item.suppressionReasons).sort(),
        attackTypes,
        chainStages,
        chainPath: buildOrderedChainPath(item.chainStages),
        attackerClusterKey: buildAttackerClusterKey(senders, affectedAddresses),
        playbookLabels: inferPlaybookLabels(attackTypes, chainStages),
        chainStartDigest: item.chainStartDigest,
        chainEndDigest: item.chainEndDigest,
        chainWindowSeconds: Math.max(0, Math.round((Date.parse(item.updatedAt) - Date.parse(item.startedAt)) / 1000)),
        correlationConfidence: computeCorrelationConfidence(item),
        startedAt: item.startedAt,
        updatedAt: item.updatedAt,
      };
      });
  }

  getBehaviorTimeline(limit = 10): Array<{
    incidentId: string;
    projectId: string;
    projectName: string;
    severity: Severity;
    status: AlertStatus;
    alertCount: number;
    ruleNames: string[];
    summaries: string[];
    digests: string[];
    senders: string[];
    affectedAddresses: string[];
    startedAt: string;
    updatedAt: string;
  }> {
    return this.getIncidentTimeline(limit)
      .filter((item) => item.categories.includes('behavior'))
      .map(({ categories: _categories, fieldChanges: _fieldChanges, ...rest }) => rest);
  }

  async updateAlertStatus(alertId: string, status: AlertStatus, note?: string): Promise<IncidentAlert | null> {
    const existing = this.state.recentAlerts.find((item) => item.id === alertId);
    if (!existing) {
      return null;
    }

    this.state = this.stateStore.updateAlertStatus(this.state, alertId, status, note);
    await this.stateStore.save(this.state);
    return this.state.recentAlerts.find((item) => item.id === alertId) ?? null;
  }

  getMetrics(): Record<string, unknown> {
    const statusCounts = {
      open: 0,
      acknowledged: 0,
      resolved: 0,
    };
    const severityCounts: Record<Severity, number> = {
      info: 0,
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    };

    for (const alert of this.state.recentAlerts) {
      statusCounts[alert.status] += 1;
      severityCounts[alert.severity] += 1;
    }

    const recentScans = this.state.scanHistory.slice(0, 20);
    const successfulScans = recentScans.filter((scan) => scan.success);
    const lastScan = this.state.scanHistory[0] ?? null;
    const lastSuccessfulScan = this.state.scanHistory.find((scan) => scan.success) ?? null;
    const behaviorAlerts = this.state.recentAlerts.filter((alert) => alert.ruleId.startsWith('behavior:'));
    const behaviorRuleCounts = new Map<string, number>();

    for (const alert of behaviorAlerts) {
      behaviorRuleCounts.set(alert.ruleName, (behaviorRuleCounts.get(alert.ruleName) ?? 0) + 1);
    }

    // Tally attack detector types from incident timeline
    const attackTypeCounts = new Map<string, number>();
    for (const incident of this.state.recentAlerts) {
      const attackTypes = (incident.details?.attackFindings as Array<{ attackType?: string }> | undefined) ?? [];
      for (const finding of attackTypes) {
        if (finding.attackType) {
          attackTypeCounts.set(finding.attackType, (attackTypeCounts.get(finding.attackType) ?? 0) + 1);
        }
      }
      // Also capture from ruleId for attack: prefixed alerts
      if (incident.ruleId.startsWith('attack:')) {
        const type = (incident.details?.attackType as string | undefined) ?? incident.ruleId.replace('attack:', '');
        attackTypeCounts.set(type, (attackTypeCounts.get(type) ?? 0) + 1);
      }
    }

    const averageDurationMs =
      recentScans.length > 0
        ? Math.round(recentScans.reduce((sum, scan) => sum + scan.durationMs, 0) / recentScans.length)
        : 0;

    return {
      runtime: {
        lastCheckpoint: this.state.lastCheckpoint,
        latestKnownCheckpoint: this.latestKnownCheckpoint,
        updatedAt: this.state.updatedAt,
        scanInFlight: this.scanInFlight,
      },
      monitoring: {
        projectCount: this.config.projects.length,
        packageCount: this.config.projects.reduce((sum, project) => sum + project.packages.length, 0),
        protectedAddressCount: this.config.projects.reduce((sum, project) => sum + project.protectedAddresses.length, 0),
        functionGuardCount: this.config.projects.reduce((sum, project) => sum + project.functionGuards.length, 0),
        trackedObjectCount: this.config.projects.reduce((sum, project) => sum + project.trackedObjects.length, 0),
        suspiciousTargetCount: this.config.projects.reduce((sum, project) => sum + project.suspiciousTargets.length, 0),
        behaviorRuleEnabledProjects: this.config.projects.filter((project) => project.behaviorRules.enabled).length,
      },
      alerts: {
        total: this.state.recentAlerts.length,
        byStatus: statusCounts,
        bySeverity: severityCounts,
        openCritical: this.state.recentAlerts.filter((alert) => alert.status === 'open' && alert.severity === 'critical').length,
        openHighOrAbove: this.state.recentAlerts.filter(
          (alert) => alert.status === 'open' && (alert.severity === 'high' || alert.severity === 'critical'),
        ).length,
      },
      scans: {
        total: this.state.scanHistory.length,
        last: lastScan,
        lastSuccessful: lastSuccessfulScan,
        successRateLast20: recentScans.length > 0 ? successfulScans.length / recentScans.length : 0,
        averageDurationMs,
      },
      behavior: {
        total: behaviorAlerts.length,
        openCritical: behaviorAlerts.filter((alert) => alert.status === 'open' && alert.severity === 'critical').length,
        openHighOrAbove: behaviorAlerts.filter(
          (alert) => alert.status === 'open' && (alert.severity === 'high' || alert.severity === 'critical'),
        ).length,
        topRules: Array.from(behaviorRuleCounts.entries())
          .map(([ruleName, count]) => ({ ruleName, count }))
          .sort((left, right) => right.count - left.count)
          .slice(0, 5),
      },
      attackDetectors: {
        topTypes: Array.from(attackTypeCounts.entries())
          .map(([attackType, count]) => ({ attackType, count }))
          .sort((left, right) => right.count - left.count)
          .slice(0, 8),
        totalDetectorFirings: Array.from(attackTypeCounts.values()).reduce((sum, n) => sum + n, 0),
        trackedSenders: this.senderTracker.senderCount,
      },
      assets: {
        total: Object.keys(this.state.trackedObjectSnapshots).length,
        items: this.getAssets(),
      },
    };
  }

  getConfigSummary(): Record<string, unknown> {
    return {
      network: this.config.network,
      storage: this.config.storage,
      alerts: {
        console: this.config.alerts.console,
        webhookEnabled: Boolean(this.config.alerts.webhookUrl),
      },
      projects: this.config.projects.map((project) => ({
        id: project.id,
        name: project.name,
        packageCount: project.packages.length,
        protectedAddressCount: project.protectedAddresses.length,
        functionGuardCount: project.functionGuards.length,
        trackedObjectCount: project.trackedObjects.length,
        suspiciousTargetCount: project.suspiciousTargets.length,
        priceModelCount: project.priceModels.length,
        objectBaselineCount: project.objectBaselines.length,
        suppressionEnabled: project.suppression.enabled,
        suspiciousTargets: project.suspiciousTargets.map((target) => ({
          label: target.label,
          address: target.address,
        })),
        behaviorRules: {
          enabled: project.behaviorRules.enabled,
          minRepeatedCalls: project.behaviorRules.minRepeatedCalls,
          minProtectedOutflow: project.behaviorRules.minProtectedOutflow,
          priceDeviationThresholdBps: project.behaviorRules.priceDeviationThresholdBps,
        },
        packages: project.packages.map((pkg) => ({
          label: pkg.label,
          address: pkg.address,
          allowedUpgradeSenderCount: pkg.allowedUpgradeSenders?.length ?? 0,
          deprecatedAddressCount: pkg.deprecatedAddresses?.length ?? 0,
        })),
        trackedObjects: project.trackedObjects.map((item) => ({
          label: item.label,
          address: item.address,
          watchFields: item.watchFields ?? [],
          criticalFields: item.criticalFields ?? [],
        })),
      })),
    };
  }

  getSubmissionReadiness(): SubmissionReadiness {
    return buildSubmissionReadiness(this.config, this.state);
  }

  private async recordAlert(alert: Alert): Promise<void> {
    const aiRules = this.config.aiRules;
    if (aiRules?.enabled && aiRules.shadow.enabled && this.activeAiStage === 'shadow' && !aiRules.shadow.notify) {
      this.state = this.stateStore.pushAlert(this.state, alert);
      return;
    }
    const shouldDispatch = this.shouldDispatchAlert(alert);
    this.state = this.stateStore.pushAlert(this.state, alert);
    if (!shouldDispatch) {
      return;
    }

    await this.alertDispatcher.dispatch(alert);
  }

  private shouldDispatchAlert(alert: Alert): boolean {
    const project = this.config.projects.find((item) => item.id === alert.projectId);
    if (!project?.suppression.enabled) {
      return true;
    }

    const duplicateWindowMs = project.suppression.duplicateWindowSeconds * 1_000;
    if (duplicateWindowMs <= 0) {
      return true;
    }

    const fingerprint = buildAlertFingerprint(alert);
    const existing = this.state.recentAlerts.find((item) => item.fingerprint === fingerprint);
    if (!existing) {
      return true;
    }

    const createdAtMs = Date.parse(alert.createdAt);
    const lastSeenAtMs = Date.parse(existing.lastSeenAt);
    if (!Number.isFinite(createdAtMs) || !Number.isFinite(lastSeenAtMs)) {
      return true;
    }

    return createdAtMs - lastSeenAtMs >= duplicateWindowMs;
  }

  private async bootstrapPackageVersions(): Promise<void> {
    for (const project of this.config.projects) {
      for (const pkg of project.packages) {
        if (this.state.packageVersions[pkg.address]) {
          continue;
        }

        const snapshot = await this.client.getPackageVersion(pkg.address);
        if (!snapshot) {
          continue;
        }

        for (const monitor of this.monitors) {
          monitor.seedPackageVersion(snapshot);
        }
        this.state = this.stateStore.upsertPackageVersion(this.state, snapshot);
      }
    }
  }

  private async refreshPackageVersions(): Promise<Alert[]> {
    const alerts: Alert[] = [];

    for (const project of this.config.projects) {
      for (const pkg of project.packages) {
        const snapshot = await this.client.getPackageVersion(pkg.address);
        if (!snapshot) {
          continue;
        }

        this.state = this.stateStore.upsertPackageVersion(this.state, snapshot);
        for (const monitor of this.monitors) {
          alerts.push(...monitor.processPackageVersion(snapshot));
        }
      }
    }

    return alerts;
  }

  private async bootstrapTrackedObjectSnapshots(): Promise<void> {
    for (const [index, project] of this.config.projects.entries()) {
      for (const trackedObject of project.trackedObjects) {
        if (this.state.trackedObjectSnapshots[trackedObject.address]) {
          this.seedMonitorFromTrackedSnapshot(index, this.state.trackedObjectSnapshots[trackedObject.address]!);
          continue;
        }

        const snapshot = await this.client.getMoveObjectSnapshot(
          project.id,
          project.name,
          trackedObject.label,
          trackedObject.address,
        );
        if (!snapshot) {
          continue;
        }

        this.state = this.stateStore.upsertTrackedObjectSnapshot(this.state, snapshot);
        this.seedMonitorFromTrackedSnapshot(index, snapshot);
        this.updateProfilesFromSnapshot(project, index, snapshot);
      }
    }
  }

  private async refreshTrackedObjects(): Promise<Alert[]> {
    const alerts: Alert[] = [];

    for (const [index, project] of this.config.projects.entries()) {
      for (const trackedObject of project.trackedObjects) {
        const snapshot = await this.client.getMoveObjectSnapshot(
          project.id,
          project.name,
          trackedObject.label,
          trackedObject.address,
        );
        if (!snapshot) {
          continue;
        }

        const previous = this.state.trackedObjectSnapshots[trackedObject.address];
        this.state = this.stateStore.upsertTrackedObjectSnapshot(this.state, snapshot);
        this.seedMonitorFromTrackedSnapshot(index, snapshot);
        this.updateProfilesFromSnapshot(project, index, snapshot);

        if (!previous) {
          continue;
        }

        alerts.push(...this.buildTrackedObjectAlerts(project.id, project.name, trackedObject, previous, snapshot));
      }
    }

    return alerts;
  }

  private buildTrackedObjectAlerts(
    projectId: string,
    projectName: string,
    trackedObject: AppConfig['projects'][number]['trackedObjects'][number],
    previous: ObjectSnapshot,
    current: ObjectSnapshot,
  ): Alert[] {
    const alerts: Alert[] = [];

    for (const field of trackedObject.criticalFields ?? []) {
      const previousValue = stringifyComparable(getValueAtPath(previous.contents, field));
      const currentValue = stringifyComparable(getValueAtPath(current.contents, field));
      if (previousValue === currentValue) {
        continue;
      }

      alerts.push({
        id: randomUUID(),
        createdAt: nowIso(),
        projectId,
        projectName,
        ruleId: `tracked-object-critical:${trackedObject.address}:${field}`,
        ruleName: '关键对象字段异常变化',
        severity: trackedObject.severity ?? 'high',
        summary: `${trackedObject.label} 的关键字段 ${field} 发生变化`,
        details: {
          label: trackedObject.label,
          address: trackedObject.address,
          field,
          previousValue,
          currentValue,
          version: current.version,
        },
      });
    }

    for (const [field, thresholdRaw] of Object.entries(trackedObject.numericDecreaseThresholds ?? {})) {
      const previousValue = toBigIntSafely(getValueAtPath(previous.contents, field));
      const currentValue = toBigIntSafely(getValueAtPath(current.contents, field));
      const threshold = BigInt(thresholdRaw);
      if (previousValue === null || currentValue === null || currentValue >= previousValue) {
        continue;
      }
      const delta = previousValue - currentValue;
      if (delta < threshold) {
        continue;
      }

      alerts.push({
        id: randomUUID(),
        createdAt: nowIso(),
        projectId,
        projectName,
        ruleId: `tracked-object-drop:${trackedObject.address}:${field}`,
        ruleName: '关键资产字段异常下降',
        severity: trackedObject.severity ?? 'critical',
        summary: `${trackedObject.label} 的 ${field} 在单轮扫描中下降 ${delta.toString()}`,
        details: {
          label: trackedObject.label,
          address: trackedObject.address,
          field,
          previousValue: previousValue.toString(),
          currentValue: currentValue.toString(),
          delta: delta.toString(),
          threshold: threshold.toString(),
          version: current.version,
        },
      });
    }

    return alerts;
  }

  private toScanRecord(startedAt: string, summary: ScanSummary): ScanRecord {
    return {
      id: randomUUID(),
      startedAt,
      finishedAt: nowIso(),
      latestCheckpoint: summary.latestCheckpoint,
      checkpointsProcessed: summary.checkpointsProcessed,
      transactionsProcessed: summary.transactionsProcessed,
      alertsTriggered: summary.alertsTriggered,
      durationMs: summary.durationMs,
      success: summary.success,
      error: summary.error,
    };
  }

  private hydrateMonitorsFromState(): void {
    for (const snapshot of Object.values(this.state.trackedObjectSnapshots)) {
      const projectIndex = this.config.projects.findIndex((project) => project.id === snapshot.projectId);
      if (projectIndex >= 0) {
        this.seedMonitorFromTrackedSnapshot(projectIndex, snapshot);
      }
    }

    for (const profile of Object.values(this.state.priceReferenceProfiles)) {
      const projectIndex = this.config.projects.findIndex((project) => project.id === profile.projectId);
      if (projectIndex >= 0) {
        this.monitors[projectIndex]?.seedPriceReferenceProfile(profile);
      }
    }

    for (const [projectId, entries] of Object.entries(this.state.flowHistory ?? {})) {
      const projectIndex = this.config.projects.findIndex((project) => project.id === projectId);
      if (projectIndex >= 0) {
        this.monitors[projectIndex]?.seedFlowHistory(entries);
      }
    }
  }

  private syncFlowHistoryFromMonitors(): void {
    if (typeof this.stateStore.replaceProjectFlowHistory !== 'function') {
      return;
    }

    for (const monitor of this.monitors) {
      this.state = this.stateStore.replaceProjectFlowHistory(
        this.state,
        monitor.getProject().id,
        monitor.getFlowHistory(),
      );
    }
  }

  private seedMonitorFromTrackedSnapshot(projectIndex: number, snapshot: ObjectSnapshot): void {
    this.monitors[projectIndex]?.seedTrackedObjectSnapshot(snapshot);
  }

  private updateProfilesFromSnapshot(
    project: AppConfig['projects'][number],
    projectIndex: number,
    snapshot: ObjectSnapshot,
  ): void {
    const baselineProfile = this.buildBaselineProfile(project, snapshot);
    this.state = this.stateStore.upsertObjectBaselineProfile(this.state, baselineProfile);

    for (const profile of this.buildPriceProfiles(project, snapshot)) {
      this.state = this.stateStore.upsertPriceReferenceProfile(this.state, profile);
      this.monitors[projectIndex]?.seedPriceReferenceProfile(profile);
    }
  }

  private buildBaselineProfile(
    project: AppConfig['projects'][number],
    snapshot: ObjectSnapshot,
  ): ObjectBaselineProfile {
    const profileKey = `${project.id}:${snapshot.label}`;
    const existing = this.state.objectBaselineProfiles[profileKey];
    const fields = { ...(existing?.fields ?? {}) };

    for (const [field, value] of Object.entries(snapshot.contents)) {
      const nextValue = stringifyComparable(value);
      const previousField = fields[field] ?? {};
      fields[field] = {
        ...previousField,
        lastValue: nextValue,
        minValue: previousField.minValue ? minComparableValue(previousField.minValue, nextValue) : nextValue,
        maxValue: previousField.maxValue ? maxComparableValue(previousField.maxValue, nextValue) : nextValue,
        lastUpdatedAt: snapshot.updatedAt,
      };
    }

    return {
      projectId: project.id,
      objectLabel: snapshot.label,
      fields,
    };
  }

  private buildPriceProfiles(
    project: AppConfig['projects'][number],
    snapshot: ObjectSnapshot,
  ): PriceReferenceProfile[] {
    return project.priceModels.flatMap((model) => {
      if (model.trackedObjectLabel !== snapshot.label) {
        return [];
      }

      const observed = getValueAtPath(snapshot.contents, model.observedFieldPath);
      if (observed === undefined || observed === null) {
        return [];
      }

      const profileKey = `${project.id}:${model.label}`;
      const previous = this.state.priceReferenceProfiles[profileKey];
      const recentObservedPrices = [...(previous?.recentObservedPrices ?? []), String(observed)].slice(-20);

      return [{
        projectId: project.id,
        label: model.label,
        recentObservedPrices,
        medianPrice: computeMedianString(recentObservedPrices),
        updatedAt: snapshot.updatedAt,
      }];
    });
  }

  // ── Dynamic project persistence ──────────────────────────────────────────

  private async loadDynamicProjects(): Promise<MonitoringProjectConfig[]> {
    try {
      const raw = await readFile(this.dynamicProjectsFile, 'utf8');
      const data = JSON.parse(raw) as unknown;
      if (!Array.isArray(data)) return [];
      return (data as MonitoringProjectConfig[]).filter(
        (item) => item && typeof item === 'object' && typeof item.id === 'string',
      );
    } catch {
      return [];
    }
  }

  private async saveDynamicProject(project: MonitoringProjectConfig): Promise<void> {
    const existing = await this.loadDynamicProjects();
    const baseIds = new Set(this.baseProjects.map((p) => p.id));
    const others = existing.filter((p) => p.id !== project.id && !baseIds.has(p.id));
    const next = [...others, project];
    await mkdir(path.dirname(this.dynamicProjectsFile), { recursive: true });
    await writeFile(this.dynamicProjectsFile, JSON.stringify(next, null, 2), 'utf8');
  }

  private async deleteDynamicProject(projectId: string): Promise<void> {
    const existing = await this.loadDynamicProjects();
    const next = existing.filter((p) => p.id !== projectId);
    await mkdir(path.dirname(this.dynamicProjectsFile), { recursive: true });
    await writeFile(this.dynamicProjectsFile, JSON.stringify(next, null, 2), 'utf8');
  }

  private mergeDynamicProjectsIntoConfig(dynamicProjects: MonitoringProjectConfig[]): void {
    const baseIds = new Set(this.baseProjects.map((p) => p.id));
    for (const dyn of dynamicProjects) {
      if (baseIds.has(dyn.id)) continue; // never overwrite base projects
      const idx = this.config.projects.findIndex((p) => p.id === dyn.id);
      if (idx >= 0) {
        this.config.projects[idx] = dyn;
        this.monitors[idx] = new ProjectMonitor(dyn);
      } else {
        this.config.projects.push(dyn);
        this.monitors.push(new ProjectMonitor(dyn));
      }
    }
  }

  private async bootstrapProjectPackages(project: MonitoringProjectConfig): Promise<void> {
    for (const pkg of project.packages) {
      if (this.state.packageVersions[pkg.address]) continue;
      const snapshot = await this.client.getPackageVersion(pkg.address);
      if (!snapshot) continue;
      for (const monitor of this.monitors) monitor.seedPackageVersion(snapshot);
      this.state = this.stateStore.upsertPackageVersion(this.state, snapshot);
    }
  }

  private async bootstrapProjectTrackedObjects(project: MonitoringProjectConfig): Promise<void> {
    const projectIndex = this.config.projects.findIndex((p) => p.id === project.id);
    if (projectIndex < 0) return;
    for (const trackedObject of project.trackedObjects) {
      const snapshot = await this.client.getMoveObjectSnapshot(
        project.id,
        project.name,
        trackedObject.label,
        trackedObject.address,
      );
      if (!snapshot) continue;
      this.state = this.stateStore.upsertTrackedObjectSnapshot(this.state, snapshot);
      this.seedMonitorFromTrackedSnapshot(projectIndex, snapshot);
      this.updateProfilesFromSnapshot(project, projectIndex, snapshot);
    }
  }

}

function mergeTimelineStatus(left: AlertStatus, right: AlertStatus): AlertStatus {
  if (left === 'open' || right === 'open') {
    return 'open';
  }
  if (left === 'acknowledged' || right === 'acknowledged') {
    return 'acknowledged';
  }
  return 'resolved';
}

function extractTimelineDigests(details: Record<string, unknown>): string[] {
  const values = new Set<string>();
  const digest = details.digest;
  if (typeof digest === 'string' && digest.length > 0) {
    values.add(digest);
  }

  const flowEvidence = details.flowEvidence;
  const windowDigests = flowEvidence && typeof flowEvidence === 'object'
    ? (flowEvidence as { windowDigests?: unknown }).windowDigests
    : undefined;
  if (Array.isArray(windowDigests)) {
    for (const item of windowDigests) {
      if (typeof item === 'string' && item.length > 0) {
        values.add(item);
      }
    }
  }

  return Array.from(values);
}

function extractTimelineSenders(details: Record<string, unknown>): string[] {
  const sender = details.sender;
  return typeof sender === 'string' && sender.length > 0 ? [sender] : [];
}

function extractTimelineAddresses(details: Record<string, unknown>): string[] {
  const values = new Set<string>();
  const directKeys = ['address', 'packageAddress'];

  for (const key of directKeys) {
    const value = details[key];
    if (typeof value === 'string' && value.length > 0) {
      values.add(value);
    }
  }

  const suspiciousTargets = details.suspiciousTargets;
  if (Array.isArray(suspiciousTargets)) {
    for (const item of suspiciousTargets) {
      if (typeof item === 'string' && item.length > 0) {
        values.add(item);
      }
    }
  }

  const flowEvidence = details.flowEvidence;
  const nodes = flowEvidence && typeof flowEvidence === 'object'
    ? (flowEvidence as { nodes?: unknown }).nodes
    : undefined;
  if (Array.isArray(nodes)) {
    for (const node of nodes) {
      const address = node && typeof node === 'object' ? (node as { address?: unknown }).address : undefined;
      if (typeof address === 'string' && /^0x[0-9a-fA-F]+$/.test(address)) {
        values.add(address);
      }
    }
  }

  return Array.from(values);
}

function extractTimelineFieldChanges(details: Record<string, unknown>): Array<{
  address: string;
  field: string;
  previousValue: string;
  currentValue: string;
}> {
  const address = details.address;
  const field = details.field;
  const previousValue = details.previousValue;
  const currentValue = details.currentValue;

  if (
    typeof address !== 'string' ||
    typeof field !== 'string' ||
    previousValue == null ||
    currentValue == null
  ) {
    return [];
  }

  return [{
    address,
    field,
    previousValue: String(previousValue),
    currentValue: String(currentValue),
  }];
}

function extractTimelineFundFlows(details: Record<string, unknown>): Array<{
  address: string;
  coinType: string;
  amount: string;
}> {
  const flowEvidence = details.flowEvidence;
  const edges = flowEvidence && typeof flowEvidence === 'object'
    ? (flowEvidence as { edges?: unknown }).edges
    : undefined;
  if (Array.isArray(edges)) {
    const extracted = edges
      .filter((edge): edge is { from: string; to: string; coinType: string; amount: string } => (
        Boolean(edge) &&
        typeof edge === 'object' &&
        typeof (edge as { from?: unknown }).from === 'string' &&
        typeof (edge as { to?: unknown }).to === 'string' &&
        typeof (edge as { coinType?: unknown }).coinType === 'string' &&
        typeof (edge as { amount?: unknown }).amount === 'string'
      ))
      .filter((edge) => edge.amount !== '0')
      .map((edge) => ({
        address: `${edge.from}->${edge.to}`,
        coinType: edge.coinType,
        amount: edge.amount,
      }));

    if (extracted.length > 0) {
      return extracted;
    }
  }

  const address = details.address;
  const coinType = details.coinType;
  const amount = details.rawOutflow;

  if (typeof address !== 'string' || typeof coinType !== 'string' || amount == null) {
    return [];
  }

  return [{
    address,
    coinType,
    amount: String(amount),
  }];
}

function extractTimelineRiskScore(details: Record<string, unknown>): number | undefined {
  const riskScore = details.riskScore;
  return typeof riskScore === 'number' && Number.isFinite(riskScore) ? riskScore : undefined;
}

function extractTimelineSuppressionReasons(details: Record<string, unknown>): string[] {
  const reasons = details.suppressionReasons;
  if (!Array.isArray(reasons)) {
    return [];
  }

  return reasons.filter((item): item is string => typeof item === 'string' && item.length > 0);
}

function extractAttackFindings(ruleId: string, details: Record<string, unknown>): Array<{
  attackType: string;
  chainHints?: {
    stage?: string;
  };
}> {
  const findings = details.attackFindings;
  const extracted = Array.isArray(findings)
    ? findings.filter((item): item is {
        attackType: string;
        chainHints?: {
          stage?: string;
        };
      } => typeof item === 'object' && item !== null && typeof (item as { attackType?: unknown }).attackType === 'string')
    : [];

  if (extracted.length > 0) {
    return extracted;
  }

  const inferredStage = inferChainStageFromRule(ruleId);
  const inferredType = inferAttackTypeFromRule(ruleId);
  if (!inferredStage && !inferredType) {
    return [];
  }

  return [
    {
      attackType: inferredType ?? ruleId,
      chainHints: {
        stage: inferredStage,
      },
    },
  ];
}

function inferChainStageFromRule(ruleId: string): string | undefined {
  if (ruleId.startsWith('behavior:unauthorized-sensitive:') || ruleId.startsWith('package-upgrade:')) {
    return 'takeover';
  }
  if (ruleId.startsWith('address-outflow:') || ruleId === 'behavior:repeated-drain' || ruleId.includes('liquidation')) {
    return 'extraction';
  }
  if (
    ruleId === 'behavior:price-manipulation' ||
    ruleId === 'behavior:flashloan-like-attack' ||
    ruleId.startsWith('tracked-object-critical:') ||
    ruleId.startsWith('tracked-object-drop:')
  ) {
    return 'manipulation';
  }
  if (ruleId === 'behavior:suspicious-target-call') {
    return 'probe';
  }
  // attack: 类告警：从 attackType 推断链路阶段
  if (ruleId.startsWith('attack:')) {
    const attackType = ruleId.slice('attack:'.length);
    if (attackType.includes('drain') || attackType.includes('rug-pull') || attackType.includes('laundering') || attackType.includes('extraction')) {
      return 'extraction';
    }
    if (attackType.includes('oracle') || attackType.includes('price') || attackType.includes('manipulation') || attackType.includes('flash-loan')) {
      return 'manipulation';
    }
    if (attackType.includes('takeover') || attackType.includes('governance') || attackType.includes('permission') || attackType.includes('upgrade')) {
      return 'takeover';
    }
    if (attackType.includes('probe') || attackType.includes('scan')) {
      return 'probe';
    }
  }
  return undefined;
}

function inferAttackTypeFromRule(ruleId: string): string | undefined {
  if (ruleId.startsWith('package-upgrade:')) {
    return 'package-upgrade-hijack';
  }
  if (ruleId === 'behavior:price-manipulation') {
    return 'oracle-price-manipulation';
  }
  if (ruleId.startsWith('address-outflow:')) {
    return 'liquidity-drain';
  }
  if (ruleId.startsWith('behavior:unauthorized-sensitive:')) {
    return 'admin-takeover';
  }
  if (ruleId === 'behavior:suspicious-target-call') {
    return 'execution-abuse';
  }
  // attack: 类告警直接使用 attackType
  if (ruleId.startsWith('attack:')) {
    return ruleId.slice('attack:'.length);
  }
  return undefined;
}

function buildOrderedChainPath(stages: Set<string>): string[] {
  const order = ['probe', 'manipulation', 'takeover', 'extraction'];
  return order.filter((stage) => stages.has(stage));
}

function buildAttackerClusterKey(senders: string[], affectedAddresses: string[]): string | undefined {
  if (senders.length === 1) {
    return `sender:${senders[0]}`;
  }
  if (senders.length > 1) {
    return `coordinated:${senders.join('|')}`;
  }
  if (affectedAddresses.length === 1) {
    return `address:${affectedAddresses[0]}`;
  }
  if (affectedAddresses.length > 1) {
    return `surface:${affectedAddresses.slice(0, 3).join('|')}`;
  }
  return undefined;
}

function selectPrimaryDigest(digests: string[]): string | undefined {
  return digests.find((item) => item.length > 0);
}

function computeCorrelationConfidence(incident: IncidentGroup): number {
  let score = 0.55;

  if (incident.senders.size === 1) {
    score += 0.2;
  } else if (incident.senders.size > 1) {
    score += 0.1;
  }

  if (incident.digests.size >= 2) {
    score += 0.1;
  }

  if (incident.chainStages.size >= 2) {
    score += 0.1;
  }

  if (incident.affectedAddresses.size > 0 || incident.fieldChanges.size > 0 || incident.fundFlows.size > 0) {
    score += 0.05;
  }

  return Math.min(0.99, Number(score.toFixed(2)));
}

function inferPlaybookLabels(attackTypes: string[], chainStages: string[]): string[] {
  const labels = new Set<string>();

  for (const attackType of attackTypes) {
    labels.add(attackType);
  }

  const stages = new Set(chainStages);
  if (chainStages.length >= 2) {
    labels.add('multi-tx-attack-chain');
  }
  if (attackTypes.includes('oracle-price-manipulation') && stages.has('extraction')) {
    labels.add('price-manipulation-drain');
  }
  if (attackTypes.includes('governance-proposal-hijack') && stages.has('takeover')) {
    labels.add('governance-takeover');
  }
  if (attackTypes.includes('package-upgrade-hijack') && stages.has('takeover')) {
    labels.add('upgrade-hijack');
  }

  return Array.from(labels).sort();
}

function classifyIncidentCategory(ruleId: string): string {
  if (ruleId.startsWith('behavior:')) {
    return 'behavior';
  }
  if (ruleId.startsWith('tracked-object-critical:') || ruleId.startsWith('tracked-object-drop:')) {
    return 'tracked-object';
  }
  if (ruleId.startsWith('address-outflow:')) {
    return 'fund-flow';
  }
  if (ruleId.startsWith('function-guard:')) {
    return 'access-control';
  }
  if (ruleId.startsWith('package-upgrade:')) {
    return 'governance';
  }
  if (ruleId.startsWith('traffic-spike:') || ruleId.startsWith('failure-spike:')) {
    return 'anomaly';
  }
  if (ruleId.startsWith('attack:')) {
    return 'attack';
  }
  return 'unknown';
}

function findIncidentGroup(
  incidents: IncidentGroup[],
  evidence: {
    projectId: string;
    bucket: number;
    digests: string[];
    senders: string[];
    addresses: string[];
  },
): IncidentGroup | undefined {
  const candidates = incidents.filter(
    (item) => item.projectId === evidence.projectId && Math.abs(item.bucket - evidence.bucket) <= 1,
  );
  if (candidates.length === 0) {
    return undefined;
  }

  const overlapped = candidates.find((item) =>
    intersects(item.digests, evidence.digests) ||
    intersects(item.senders, evidence.senders) ||
    intersects(item.affectedAddresses, evidence.addresses),
  );
  if (overlapped) {
    return overlapped;
  }

  const correlatedAdjacent = candidates.find((item) => {
    if (item.bucket === evidence.bucket) {
      return false;
    }
    return intersects(item.senders, evidence.senders) || intersects(item.affectedAddresses, evidence.addresses);
  });
  if (correlatedAdjacent) {
    return correlatedAdjacent;
  }

  if (evidence.senders.length > 0 && candidates.some((item) => item.senders.size > 0)) {
    return undefined;
  }

  return candidates[0];
}

function intersects(values: Set<string>, candidates: string[]): boolean {
  return candidates.some((item) => values.has(item));
}

function stringifyComparable(value: unknown): string {
  if (value === undefined || value === null) {
    return 'null';
  }
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return JSON.stringify(value);
}

function toBigIntSafely(value: unknown): bigint | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return BigInt(Math.trunc(value));
  }
  if (typeof value === 'string' && /^-?\d+$/.test(value)) {
    return BigInt(value);
  }
  return null;
}

function minComparableValue(left: string, right: string): string {
  const leftNumeric = toBigIntSafely(left);
  const rightNumeric = toBigIntSafely(right);
  if (leftNumeric !== null && rightNumeric !== null) {
    return leftNumeric <= rightNumeric ? left : right;
  }
  return left <= right ? left : right;
}

function maxComparableValue(left: string, right: string): string {
  const leftNumeric = toBigIntSafely(left);
  const rightNumeric = toBigIntSafely(right);
  if (leftNumeric !== null && rightNumeric !== null) {
    return leftNumeric >= rightNumeric ? left : right;
  }
  return left >= right ? left : right;
}

function computeMedianString(values: string[]): string | undefined {
  const numerics = values
    .map((value) => toBigIntSafely(value))
    .filter((value): value is bigint => value !== null)
    .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));

  if (numerics.length === 0) {
    return values.at(-1);
  }

  return numerics[Math.floor(numerics.length / 2)]?.toString();
}

/** Normalize all address fields in a project config using canonicalizeSuiAddress. */
function normalizeProjectAddresses(project: MonitoringProjectConfig): MonitoringProjectConfig {
  return {
    ...project,
    packages: project.packages.map((pkg) => ({
      ...pkg,
      address: canonicalizeSuiAddress(pkg.address),
      allowedUpgradeSenders: (pkg.allowedUpgradeSenders ?? []).map(canonicalizeSuiAddress),
      deprecatedAddresses: (pkg.deprecatedAddresses ?? []).map(canonicalizeSuiAddress),
    })),
    protectedAddresses: project.protectedAddresses.map((addr) => ({
      ...addr,
      address: canonicalizeSuiAddress(addr.address),
      allowedSenders: (addr.allowedSenders ?? []).map(canonicalizeSuiAddress),
    })),
    functionGuards: project.functionGuards.map((guard) => ({
      ...guard,
      package: canonicalizeSuiAddress(guard.package),
      allowedSenders: guard.allowedSenders.map(canonicalizeSuiAddress),
    })),
    trafficSpikes: project.trafficSpikes.map((spike) => ({
      ...spike,
      package: canonicalizeSuiAddress(spike.package),
    })),
    failureSpikes: project.failureSpikes.map((spike) => ({
      ...spike,
      package: canonicalizeSuiAddress(spike.package),
    })),
    trackedObjects: project.trackedObjects.map((obj) => ({
      ...obj,
      address: canonicalizeSuiAddress(obj.address),
    })),
    suspiciousTargets: project.suspiciousTargets.map((target) => ({
      ...target,
      address: canonicalizeSuiAddress(target.address),
    })),
  };
}
