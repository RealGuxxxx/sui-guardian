import type {
  Alert,
  DerivedEvidence,
  FlowHistoryEntry,
  MonitoringProjectConfig,
  ObjectSnapshot,
  PriceReferenceProfile,
  ObservedTransaction,
  PackageVersionSnapshot,
  Severity,
} from './types.js';
import type { SenderHistory } from './detection/sender-tracker.js';
import type { AttackFinding } from './detectors/types.js';
import { getKnownBadActor } from './data/known-bad-actors.js';
import { buildFundFlowGraph } from './detection/fund-flow-graph.js';
import { applyFalsePositiveSuppression } from './detection/false-positive-suppression.js';
import { getRemediationGuide } from './detection/remediation-guide.js';
import { runAttackDetectors } from './detectors/registry.js';
import { runBehaviorRules } from './behavior-rules.js';
import { detectObjectBaselineAnomalies } from './detection/object-baseline.js';
import { detectPriceDeviation } from './detection/price-deviation.js';
import { scoreRisk } from './detection/risk-scorer.js';
import { createAlert, matchesPattern, sameAddress, toBigInt } from './utils.js';

interface WindowEntry {
  digest: string;
  timestampMs: number;
  sender?: string;
}

const MAX_FLOW_HISTORY_ENTRIES = 100;

export class ProjectMonitor {
  private readonly packageVersionCache = new Map<string, PackageVersionSnapshot>();
  private readonly trafficWindows = new Map<string, WindowEntry[]>();
  private readonly failureWindows = new Map<string, WindowEntry[]>();
  private readonly alertCooldowns = new Map<string, number>();
  private readonly trackedSnapshotContents = new Map<string, Record<string, unknown>>();
  private readonly previousTrackedSnapshotContents = new Map<string, Record<string, unknown>>();
  private readonly priceProfiles = new Map<string, PriceReferenceProfile>();
  private flowHistory: FlowHistoryEntry[] = [];

  constructor(private readonly project: MonitoringProjectConfig) {}

  seedPackageVersion(snapshot: PackageVersionSnapshot): void {
    this.packageVersionCache.set(snapshot.packageAddress, snapshot);
  }

  seedTrackedObjectSnapshot(snapshot: ObjectSnapshot): void {
    const existing = this.trackedSnapshotContents.get(snapshot.label);
    if (existing) {
      this.previousTrackedSnapshotContents.set(snapshot.label, existing);
    }

    this.trackedSnapshotContents.set(snapshot.label, snapshot.contents);
  }

  seedPriceReferenceProfile(profile: PriceReferenceProfile): void {
    this.priceProfiles.set(profile.label, profile);
  }

  seedFlowHistory(entries: FlowHistoryEntry[]): void {
    this.flowHistory = entries.slice(-MAX_FLOW_HISTORY_ENTRIES);
  }

  getFlowHistory(): FlowHistoryEntry[] {
    return [...this.flowHistory];
  }

  processTransaction(
    tx: ObservedTransaction,
    recentAlerts: Array<{ ruleId: string; details: Record<string, unknown> }> = [],
    senderHistory: SenderHistory | null = null,
  ): Alert[] {
    if (!this.transactionTouchesProject(tx)) {
      return [];
    }

    const derived = this.buildDerivedSignals(tx, recentAlerts, senderHistory);
    const behaviorAlerts = this.project.behaviorRules.enabled
      ? runBehaviorRules({
          projectId: this.project.id,
          projectName: this.project.name,
          tx,
          protectedAddresses: this.project.protectedAddresses.map((item) => item.address),
          sensitiveCalls: this.project.functionGuards.map((guard) => ({
            label: guard.label,
            package: guard.package,
            module: guard.module,
            function: guard.function,
            allowedSenders: guard.allowedSenders,
            severity: guard.severity,
          })),
          derived,
        })
      : [];

    const baseAlerts = [
      ...this.checkAddressOutflows(tx),
      ...this.checkFunctionGuards(tx),
      ...this.checkTrafficSpikes(tx),
      ...this.checkFailureSpikes(tx),
      ...this.checkDeprecatedPackageCalls(tx),
      ...this.checkKnownBadActor(tx),
      ...behaviorAlerts,
    ];

    return [
      ...baseAlerts,
      ...convertAttackFindingsToAlerts(derived, this.project, tx, baseAlerts),
    ];
  }

  processPackageVersion(snapshot: PackageVersionSnapshot): Alert[] {
    const packageConfig = this.project.packages.find((item) => sameAddress(item.address, snapshot.packageAddress));
    if (!packageConfig) {
      return [];
    }

    const previous = this.packageVersionCache.get(snapshot.packageAddress);
    this.packageVersionCache.set(snapshot.packageAddress, snapshot);

    if (!previous || snapshot.version <= previous.version) {
      return [];
    }

    const authorized = (packageConfig.allowedUpgradeSenders ?? []).some((sender) => sameAddress(sender, snapshot.sender));
    const attackFindings = authorized
      ? []
      : [
          {
            attackType: 'package-upgrade-hijack',
            category: 'governance' as const,
            summary: `监控包 ${packageConfig.label ?? snapshot.packageAddress} 出现未授权升级`,
            evidence: {
              packageAddress: snapshot.packageAddress,
              previousVersion: previous.version,
              nextVersion: snapshot.version,
              sender: snapshot.sender,
            },
            riskHints: {
              scoreDelta: 35,
              severityFloor: 'critical' as const,
            },
            chainHints: {
              stage: 'takeover' as const,
            },
          },
        ];
    return [
      createAlert({
        projectId: this.project.id,
        projectName: this.project.name,
        ruleId: `package-upgrade:${snapshot.packageAddress}`,
        ruleName: 'Package 升级检测',
        severity: authorized ? 'high' : 'critical',
        summary: `监控包 ${packageConfig.label ?? snapshot.packageAddress} 版本从 ${previous.version} 升级到 ${snapshot.version}`,
        details: {
          packageAddress: snapshot.packageAddress,
          previousVersion: previous.version,
          nextVersion: snapshot.version,
          digest: snapshot.digest,
          sender: snapshot.sender,
          authorized,
          attackFindings,
        },
      }),
    ];
  }

  private checkAddressOutflows(tx: ObservedTransaction): Alert[] {
    const alerts: Alert[] = [];

    for (const protectedAddress of this.project.protectedAddresses) {
      const aggregated = new Map<string, bigint>();

      for (const change of tx.balanceChanges) {
        if (!sameAddress(change.owner, protectedAddress.address)) {
          continue;
        }

        const amount = toBigInt(change.amount);
        if (amount >= 0n) {
          continue;
        }

        aggregated.set(change.coinType, (aggregated.get(change.coinType) ?? 0n) + amount);
      }

      for (const [coinType, amount] of aggregated.entries()) {
        const thresholdRaw = protectedAddress.outflowThresholds[coinType];
        if (!thresholdRaw) {
          continue;
        }

        const threshold = toBigInt(thresholdRaw);
        const outflow = amount * -1n;
        if (outflow < threshold) {
          continue;
        }

        const senderAuthorized = (protectedAddress.allowedSenders ?? []).some((sender) => sameAddress(sender, tx.sender));
        alerts.push(
          createAlert({
            projectId: this.project.id,
            projectName: this.project.name,
            ruleId: `address-outflow:${protectedAddress.address}:${coinType}`,
            ruleName: '资金异常流出检测',
            severity: senderAuthorized ? 'medium' : 'high',
            summary: `${protectedAddress.label} 在单笔交易中流出 ${outflow.toString()}（${coinType}）`,
            details: {
              address: protectedAddress.address,
              label: protectedAddress.label,
              coinType,
              rawOutflow: outflow.toString(),
              rawThreshold: threshold.toString(),
              digest: tx.digest,
              checkpoint: tx.checkpoint,
              sender: tx.sender,
              senderAuthorized,
              calls: tx.calls,
            },
          }),
        );
      }
    }

    return alerts;
  }

  private checkFunctionGuards(tx: ObservedTransaction): Alert[] {
    const alerts: Alert[] = [];

    for (const guard of this.project.functionGuards) {
      const matchedCall = tx.calls.find(
        (call) =>
          sameAddress(call.package, guard.package) &&
          matchesPattern(call.module, guard.module) &&
          matchesPattern(call.function, guard.function),
      );

      if (!matchedCall) {
        continue;
      }

      const senderAuthorized = guard.allowedSenders.some((sender) => sameAddress(sender, tx.sender));
      if (senderAuthorized) {
        continue;
      }

      alerts.push(
        createAlert({
          projectId: this.project.id,
          projectName: this.project.name,
          ruleId: `function-guard:${guard.label}`,
          ruleName: '高危函数越权调用检测',
          severity: guard.severity ?? 'critical',
          summary: `检测到非授权地址调用敏感函数 ${matchedCall.module}::${matchedCall.function}`,
          details: {
            guardLabel: guard.label,
            digest: tx.digest,
            checkpoint: tx.checkpoint,
            sender: tx.sender,
            call: matchedCall,
          },
        }),
      );
    }

    return alerts;
  }

  private checkTrafficSpikes(tx: ObservedTransaction): Alert[] {
    const alerts: Alert[] = [];

    for (const spike of this.project.trafficSpikes) {
      if (!this.transactionTouchesPackage(tx, spike.package)) {
        continue;
      }

      const window = this.trafficWindows.get(spike.label) ?? [];
      window.push({
        digest: tx.digest,
        timestampMs: Date.parse(tx.timestamp),
        sender: tx.sender,
      });

      const cutoff = Date.parse(tx.timestamp) - spike.windowSeconds * 1_000;
      const pruned = window.filter((item) => item.timestampMs >= cutoff);
      this.trafficWindows.set(spike.label, pruned);

      const uniqueSenders = new Set(pruned.map((item) => item.sender).filter(Boolean));
      if (pruned.length < spike.txCountThreshold || uniqueSenders.size < spike.uniqueSenderThreshold) {
        continue;
      }

      if (!this.consumeCooldown(`traffic:${spike.label}`, spike.cooldownSeconds ?? spike.windowSeconds, Date.parse(tx.timestamp))) {
        continue;
      }

      alerts.push(
        createAlert({
          projectId: this.project.id,
          projectName: this.project.name,
          ruleId: `traffic-spike:${spike.label}`,
          ruleName: '交易热度突增检测',
          severity: spike.severity ?? 'high',
          summary: `包 ${spike.package} 在 ${spike.windowSeconds}s 内出现 ${pruned.length} 笔交易 / ${uniqueSenders.size} 个 sender`,
          details: {
            label: spike.label,
            package: spike.package,
            windowSeconds: spike.windowSeconds,
            txCount: pruned.length,
            uniqueSenderCount: uniqueSenders.size,
            latestDigest: tx.digest,
            latestCheckpoint: tx.checkpoint,
          },
        }),
      );
    }

    return alerts;
  }

  private checkFailureSpikes(tx: ObservedTransaction): Alert[] {
    if (tx.status !== 'FAILURE') {
      return [];
    }

    const alerts: Alert[] = [];

    for (const spike of this.project.failureSpikes) {
      if (!this.transactionTouchesPackage(tx, spike.package)) {
        continue;
      }

      const window = this.failureWindows.get(spike.label) ?? [];
      window.push({
        digest: tx.digest,
        timestampMs: Date.parse(tx.timestamp),
        sender: tx.sender,
      });

      const cutoff = Date.parse(tx.timestamp) - spike.windowSeconds * 1_000;
      const pruned = window.filter((item) => item.timestampMs >= cutoff);
      this.failureWindows.set(spike.label, pruned);

      if (pruned.length < spike.failedTxThreshold) {
        continue;
      }

      if (!this.consumeCooldown(`failure:${spike.label}`, spike.cooldownSeconds ?? spike.windowSeconds, Date.parse(tx.timestamp))) {
        continue;
      }

      alerts.push(
        createAlert({
          projectId: this.project.id,
          projectName: this.project.name,
          ruleId: `failure-spike:${spike.label}`,
          ruleName: '失败交易突增检测',
          severity: spike.severity ?? 'medium',
          summary: `包 ${spike.package} 在 ${spike.windowSeconds}s 内出现 ${pruned.length} 笔失败交易`,
          details: {
            label: spike.label,
            package: spike.package,
            windowSeconds: spike.windowSeconds,
            failedTxCount: pruned.length,
            latestDigest: tx.digest,
            latestCheckpoint: tx.checkpoint,
            latestError: tx.executionError,
          },
        }),
      );
    }

    return alerts;
  }

  private checkDeprecatedPackageCalls(tx: ObservedTransaction): Alert[] {
    const alerts: Alert[] = [];

    for (const pkgConfig of this.project.packages) {
      const deprecatedAddresses = pkgConfig.deprecatedAddresses ?? [];
      if (deprecatedAddresses.length === 0) {
        continue;
      }

      const deprecatedCalls = tx.calls.filter((call) =>
        deprecatedAddresses.some((address) => sameAddress(call.package, address)),
      );
      if (deprecatedCalls.length === 0) {
        continue;
      }

      alerts.push(
        createAlert({
          projectId: this.project.id,
          projectName: this.project.name,
          ruleId: `deprecated-package-call:${pkgConfig.address}`,
          ruleName: '废弃包版本调用检测',
          severity: 'high',
          summary: `检测到调用已废弃的包版本：${pkgConfig.label ?? pkgConfig.address}`,
          details: {
            currentPackage: pkgConfig.address,
            deprecatedPackagesCalled: deprecatedCalls.map((call) => call.package),
            functions: deprecatedCalls.map((call) => `${call.module}::${call.function}`),
            sender: tx.sender,
            digest: tx.digest,
            checkpoint: tx.checkpoint,
            remediation: getRemediationGuide('deprecated-package-call'),
          },
        }),
      );
    }

    return alerts;
  }

  private checkKnownBadActor(tx: ObservedTransaction): Alert[] {
    if (!tx.sender) {
      return [];
    }

    const actor = getKnownBadActor(tx.sender);
    if (!actor) {
      return [];
    }

    const touchesMonitoredAsset =
      this.project.packages.some((pkg) => this.transactionTouchesPackage(tx, pkg.address)) ||
      this.project.protectedAddresses.some((address) =>
        tx.balanceChanges.some((change) => sameAddress(change.owner, address.address)),
      );
    if (!touchesMonitoredAsset) {
      return [];
    }

    return [
      createAlert({
        projectId: this.project.id,
        projectName: this.project.name,
        ruleId: `known-bad-actor:${tx.sender}`,
        ruleName: '已知攻击地址交互检测',
        severity: 'critical',
        summary: `已知攻击地址 ${actor.label} 正在与监控资产交互`,
        details: {
          sender: tx.sender,
          actor,
          digest: tx.digest,
          checkpoint: tx.checkpoint,
          remediation: getRemediationGuide('known-bad-actor'),
        },
      }),
    ];
  }

  private transactionTouchesPackage(tx: ObservedTransaction, packageAddress: string): boolean {
    return (
      tx.calls.some((call) => sameAddress(call.package, packageAddress)) ||
      tx.objectChanges.some((change) => change.isPackage && sameAddress(change.address, packageAddress))
    );
  }

  private transactionTouchesProject(tx: ObservedTransaction): boolean {
    const packageAddresses = [
      ...this.project.packages.map((pkg) => pkg.address),
      ...this.project.packages.flatMap((pkg) => pkg.deprecatedAddresses ?? []),
      ...this.project.functionGuards.map((guard) => guard.package),
    ];
    const objectAddresses = [
      ...this.project.protectedAddresses.map((address) => address.address),
      ...this.project.suspiciousTargets.map((target) => target.address),
    ];

    return (
      tx.calls.some((call) => packageAddresses.some((address) => sameAddress(call.package, address))) ||
      tx.objectChanges.some((change) => objectAddresses.some((address) => sameAddress(change.address, address))) ||
      tx.objectChanges.some((change) => change.isPackage && packageAddresses.some((address) => sameAddress(change.address, address))) ||
      tx.balanceChanges.some((change) => objectAddresses.some((address) => sameAddress(change.owner, address)))
    );
  }

  private buildDerivedSignals(
    tx: ObservedTransaction,
    recentAlerts: Array<{ ruleId: string; details: Record<string, unknown> }>,
    senderHistory: SenderHistory | null,
  ): DerivedEvidence {
    const repeatedCalls = new Map<string, number>();

    for (const call of tx.calls) {
      const key = `${call.module}::${call.function}`;
      repeatedCalls.set(key, (repeatedCalls.get(key) ?? 0) + 1);
    }

    const suspiciousTargets = tx.objectChanges
      .filter((change) => this.project.suspiciousTargets.some((target) => sameAddress(target.address, change.address)))
      .map((change) => change.address);

    const callNames = tx.calls.map((call) => `${call.module}::${call.function}`.toLowerCase());
    const flashLikeFundingDetected = callNames.some((name) =>
      ['flash', 'loan', 'borrow'].some((keyword) => name.includes(keyword)),
    );
    const valueExtractionDetected = callNames.some((name) =>
      ['withdraw', 'redeem', 'claim', 'liquidate', 'borrow'].some((keyword) => name.includes(keyword)),
    );

    const priceEvidence = detectPriceDeviation({
      tx,
      project: this.project,
      trackedSnapshots: this.getTrackedSnapshotContents(),
      priceProfiles: Object.fromEntries(this.priceProfiles.entries()),
    });

    const baselineEvidence = detectObjectBaselineAnomalies({
      tx,
      project: this.project,
      previousSnapshots: this.getPreviousTrackedSnapshotContents(),
      currentSnapshots: this.getTrackedSnapshotContents(),
    });

    const flowEvidence = buildFundFlowGraph({
      tx,
      protectedAddresses: this.project.protectedAddresses.map((item) => item.address),
      attackerAddresses: tx.sender ? [tx.sender] : [],
    });
    this.recordFlowHistory(tx, flowEvidence.attackPathFound, flashLikeFundingDetected, valueExtractionDetected, flowEvidence.netProtectedOutflow, flowEvidence.netAttackerGain);

    const risk = scoreRisk({
      priceEvidence,
      baselineEvidence,
      flowEvidence,
    });

    const evidenceSummary = [
      ...priceEvidence.map((item) => `price:${item.label}:${item.deviationBps ?? 'na'}`),
      ...baselineEvidence.map((item) => `baseline:${item.objectLabel}.${item.field}:${item.anomalyKind}`),
      flowEvidence.attackPathFound ? 'flow:attack_path' : 'flow:no_attack_path',
    ];

    const suppression = applyFalsePositiveSuppression({
      tx,
      project: this.project,
      risk,
      evidenceSummary,
      senderAuthorized: this.isKnownAuthorizedSender(tx.sender),
    });

    const attackFindings = this.project.attackDetectors?.enabled === false
      ? []
      : runAttackDetectors({
        project: this.project,
        tx,
        derived: {
          flashLikeFundingDetected,
          priceDeviationBps: valueExtractionDetected && tx.balanceChanges.some((change) => change.amount.startsWith('-'))
            ? this.project.behaviorRules.priceDeviationThresholdBps
            : undefined,
          suspiciousTargets,
          sameSensitiveCallRepeats: Object.fromEntries(repeatedCalls.entries()),
          valueExtractionDetected,
          priceEvidence,
          baselineEvidence,
          flowEvidence,
          risk,
          evidenceSummary,
        },
        runtime: {
          recentAlerts,
          senderHistory,
        },
      });

    return {
      flashLikeFundingDetected,
      priceDeviationBps: valueExtractionDetected && tx.balanceChanges.some((change) => change.amount.startsWith('-'))
        ? this.project.behaviorRules.priceDeviationThresholdBps
        : undefined,
      suspiciousTargets,
      sameSensitiveCallRepeats: Object.fromEntries(repeatedCalls.entries()),
      valueExtractionDetected,
      priceEvidence,
      baselineEvidence,
      flowEvidence,
      risk,
      suppression,
      evidenceSummary: [
        ...evidenceSummary,
        ...attackFindings.map((finding) => `attack:${finding.attackType}`),
      ],
      attackFindings,
    };
  }

  private getTrackedSnapshotContents(): Record<string, Record<string, unknown>> {
    return Object.fromEntries(this.trackedSnapshotContents.entries());
  }

  private getPreviousTrackedSnapshotContents(): Record<string, Record<string, unknown>> {
    return Object.fromEntries(this.previousTrackedSnapshotContents.entries());
  }

  private recordFlowHistory(
    tx: ObservedTransaction,
    attackPathFound: boolean,
    flashLikeFundingDetected: boolean,
    valueExtractionDetected: boolean,
    netProtectedOutflow: string,
    netAttackerGain: string,
  ): void {
    if (!this.project.flowTracking.enabled) {
      return;
    }

    this.flowHistory = [
      ...this.flowHistory,
      {
        projectId: this.project.id,
        digest: tx.digest,
        timestamp: tx.timestamp,
        sender: tx.sender,
        flashLikeFundingDetected,
        manipulationDetected: attackPathFound || valueExtractionDetected,
        netProtectedOutflow,
        netAttackerGain,
      },
    ].slice(-MAX_FLOW_HISTORY_ENTRIES);
  }

  private isKnownAuthorizedSender(sender?: string): boolean {
    if (!sender) {
      return false;
    }

    return (
      this.project.protectedAddresses.some((item) => (item.allowedSenders ?? []).some((allowed) => sameAddress(allowed, sender))) ||
      this.project.functionGuards.some((guard) => guard.allowedSenders.some((allowed) => sameAddress(allowed, sender))) ||
      this.project.objectBaselines.some((baseline) =>
        baseline.fields.some((field) => (field.allowedSenders ?? []).some((allowed) => sameAddress(allowed, sender))),
      ) ||
      this.project.suppression.maintenanceWindows.some((window) =>
        window.allowedSenders.some((allowed) => sameAddress(allowed, sender)),
      )
    );
  }

  private consumeCooldown(key: string, cooldownSeconds: number, timestampMs: number): boolean {
    const lastTriggeredAt = this.alertCooldowns.get(key) ?? 0;
    if (timestampMs - lastTriggeredAt < cooldownSeconds * 1_000) {
      return false;
    }

    this.alertCooldowns.set(key, timestampMs);
    return true;
  }

  getProject(): MonitoringProjectConfig {
    return this.project;
  }
}

function convertAttackFindingsToAlerts(
  derived: DerivedEvidence,
  project: MonitoringProjectConfig,
  tx: ObservedTransaction,
  baseAlerts: Alert[],
): Alert[] {
  const existingRuleIds = new Set(baseAlerts.map((alert) => alert.ruleId));
  const attackFindings = derived.attackFindings ?? [];
  const alerts: Alert[] = [];

  for (const finding of attackFindings) {
    const ruleId = `attack:${finding.attackType}`;
    if (existingRuleIds.has(ruleId)) {
      continue;
    }

    const severity = finding.riskHints?.severityFloor ?? derived.risk?.recommendedSeverity ?? 'high';
    if (!isActionableSeverity(severity)) {
      continue;
    }

    alerts.push(
      createAlert({
        projectId: project.id,
        projectName: project.name,
        ruleId,
        ruleName: `攻击检测 / ${finding.attackType}`,
        severity,
        summary: finding.summary,
        details: {
          digest: tx.digest,
          checkpoint: tx.checkpoint,
          sender: tx.sender,
          attackType: finding.attackType,
          category: finding.category,
          evidence: finding.evidence,
          riskScore: derived.risk?.riskScore ?? 0,
          confidence: derived.risk?.confidence ?? 0,
          flowEvidence: derived.flowEvidence,
          chainHints: finding.chainHints,
          attackFindings: [finding],
          remediation: getRemediationGuide(finding.attackType),
        },
      }),
    );
    existingRuleIds.add(ruleId);
  }

  return alerts;
}

function isActionableSeverity(severity: Severity): boolean {
  return severity === 'medium' || severity === 'high' || severity === 'critical';
}
