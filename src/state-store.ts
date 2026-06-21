import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import type {
  Alert,
  AlertStatus,
  FlowHistoryEntry,
  IncidentAlert,
  ObjectBaselineProfile,
  ObjectSnapshot,
  PackageVersionSnapshot,
  PriceReferenceProfile,
  RuntimeState,
  ScanRecord,
} from './types.js';
import { buildAlertFingerprint, nowIso, severityRank } from './utils.js';

const MAX_SCAN_HISTORY = 200;
const MAX_RECENT_TRANSACTION_DIGESTS = 5000;

export class StateStore {
  constructor(
    private readonly stateFile: string,
    private readonly maxAlerts: number,
  ) {}

  async load(): Promise<RuntimeState> {
    try {
      const raw = await readFile(this.stateFile, 'utf8');
      const data = JSON.parse(raw) as Partial<RuntimeState> & {
        recentAlerts?: unknown[];
        scanHistory?: unknown[];
      };

      return {
        lastCheckpoint: Number.isFinite(data.lastCheckpoint) ? Number(data.lastCheckpoint) : 0,
        packageVersions: data.packageVersions ?? {},
        trackedObjectSnapshots: normalizeObjectSnapshots((data as { trackedObjectSnapshots?: unknown }).trackedObjectSnapshots),
        priceReferenceProfiles: normalizePriceReferenceProfiles((data as { priceReferenceProfiles?: unknown }).priceReferenceProfiles),
        objectBaselineProfiles: normalizeObjectBaselineProfiles((data as { objectBaselineProfiles?: unknown }).objectBaselineProfiles),
        flowHistory: normalizeFlowHistory((data as { flowHistory?: unknown }).flowHistory),
        recentTransactionDigests: normalizeTransactionDigests((data as { recentTransactionDigests?: unknown }).recentTransactionDigests),
        recentAlerts: dedupeIncidentAlerts((data.recentAlerts ?? []).map((item) => normalizeIncidentAlert(item))).slice(0, this.maxAlerts),
        scanHistory: (data.scanHistory ?? []).map((item) => normalizeScanRecord(item)).slice(0, MAX_SCAN_HISTORY),
        updatedAt: typeof data.updatedAt === 'string' ? data.updatedAt : nowIso(),
      };
    } catch {
      return createEmptyRuntimeState();
    }
  }

  async save(state: RuntimeState): Promise<void> {
    const dir = path.dirname(this.stateFile);
    await mkdir(dir, { recursive: true });
    await writeFile(this.stateFile, JSON.stringify(state, null, 2), 'utf8');
  }

  pushAlert(state: RuntimeState, alert: Alert): RuntimeState {
    const fingerprint = buildAlertFingerprint(alert);
    const existingIndex = state.recentAlerts.findIndex((item) => item.fingerprint === fingerprint);

    if (existingIndex >= 0) {
      const existing = state.recentAlerts[existingIndex]!;
      const merged: IncidentAlert = {
        ...existing,
        severity: severityRank(alert.severity) > severityRank(existing.severity) ? alert.severity : existing.severity,
        summary: alert.summary,
        details: alert.details,
        updatedAt: alert.createdAt,
        lastSeenAt: alert.createdAt,
        occurrences: existing.occurrences + 1,
        status: existing.status === 'resolved' ? 'open' : existing.status,
      };

      const nextAlerts = [
        merged,
        ...state.recentAlerts.filter((item) => item.id !== existing.id),
      ].slice(0, this.maxAlerts);

      return {
        ...state,
        recentAlerts: nextAlerts,
        updatedAt: nowIso(),
      };
    }

    const incident: IncidentAlert = {
      ...alert,
      fingerprint,
      status: 'open',
      firstSeenAt: alert.createdAt,
      lastSeenAt: alert.createdAt,
      updatedAt: alert.createdAt,
      occurrences: 1,
    };

    return {
      ...state,
      recentAlerts: [incident, ...state.recentAlerts].slice(0, this.maxAlerts),
      updatedAt: nowIso(),
    };
  }

  updateAlertStatus(state: RuntimeState, alertId: string, status: AlertStatus, note?: string): RuntimeState {
    const updatedAt = nowIso();
    const nextAlerts = state.recentAlerts.map((item) => {
      if (item.id !== alertId) {
        return item;
      }
      const acknowledgedAt = status === 'acknowledged' && !item.acknowledgedAt ? updatedAt : item.acknowledgedAt;
      const resolvedAt = status === 'resolved' && !item.resolvedAt ? updatedAt : item.resolvedAt;
      const ackResponseSeconds =
        acknowledgedAt && item.ackResponseSeconds === undefined
          ? Math.max(0, Math.round((Date.parse(acknowledgedAt) - Date.parse(item.firstSeenAt)) / 1000))
          : item.ackResponseSeconds;
      return {
        ...item,
        status,
        note: note !== undefined ? note : item.note,
        acknowledgedAt,
        resolvedAt,
        ackResponseSeconds,
        updatedAt,
      };
    });

    return {
      ...state,
      recentAlerts: nextAlerts,
      updatedAt,
    };
  }

  appendScanRecord(state: RuntimeState, record: ScanRecord): RuntimeState {
    return {
      ...state,
      scanHistory: [record, ...state.scanHistory].slice(0, MAX_SCAN_HISTORY),
      updatedAt: nowIso(),
    };
  }

  pushProcessedDigest(state: RuntimeState, digest: string): RuntimeState {
    const nextDigests = [digest, ...state.recentTransactionDigests.filter((item) => item !== digest)].slice(
      0,
      MAX_RECENT_TRANSACTION_DIGESTS,
    );

    return {
      ...state,
      recentTransactionDigests: nextDigests,
      updatedAt: nowIso(),
    };
  }

  upsertPackageVersion(state: RuntimeState, snapshot: PackageVersionSnapshot): RuntimeState {
    return {
      ...state,
      packageVersions: {
        ...state.packageVersions,
        [snapshot.packageAddress]: snapshot,
      },
      updatedAt: nowIso(),
    };
  }

  upsertTrackedObjectSnapshot(state: RuntimeState, snapshot: ObjectSnapshot): RuntimeState {
    return {
      ...state,
      trackedObjectSnapshots: {
        ...state.trackedObjectSnapshots,
        [snapshot.address]: snapshot,
      },
      updatedAt: nowIso(),
    };
  }

  upsertPriceReferenceProfile(state: RuntimeState, profile: PriceReferenceProfile): RuntimeState {
    return {
      ...state,
      priceReferenceProfiles: {
        ...state.priceReferenceProfiles,
        [`${profile.projectId}:${profile.label}`]: profile,
      },
      updatedAt: nowIso(),
    };
  }

  upsertObjectBaselineProfile(state: RuntimeState, profile: ObjectBaselineProfile): RuntimeState {
    return {
      ...state,
      objectBaselineProfiles: {
        ...state.objectBaselineProfiles,
        [`${profile.projectId}:${profile.objectLabel}`]: profile,
      },
      updatedAt: nowIso(),
    };
  }

  replaceProjectFlowHistory(state: RuntimeState, projectId: string, entries: FlowHistoryEntry[]): RuntimeState {
    return {
      ...state,
      flowHistory: {
        ...(state.flowHistory ?? {}),
        [projectId]: entries,
      },
      updatedAt: nowIso(),
    };
  }

  setLastCheckpoint(state: RuntimeState, checkpoint: number): RuntimeState {
    return {
      ...state,
      lastCheckpoint: checkpoint,
      updatedAt: nowIso(),
    };
  }
}

function createEmptyRuntimeState(): RuntimeState {
  return {
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
}

function dedupeIncidentAlerts(alerts: IncidentAlert[]): IncidentAlert[] {
  const merged = new Map<string, IncidentAlert>();

  for (const alert of alerts) {
    const existing = merged.get(alert.fingerprint);
    if (!existing) {
      merged.set(alert.fingerprint, alert);
      continue;
    }

    const latest = compareIsoDates(alert.lastSeenAt, existing.lastSeenAt) >= 0 ? alert : existing;
    const earliest = latest === alert ? existing : alert;

    merged.set(alert.fingerprint, {
      ...latest,
      id: existing.id,
      severity: severityRank(alert.severity) > severityRank(existing.severity) ? alert.severity : existing.severity,
      firstSeenAt: compareIsoDates(alert.firstSeenAt, existing.firstSeenAt) <= 0 ? alert.firstSeenAt : existing.firstSeenAt,
      lastSeenAt: compareIsoDates(alert.lastSeenAt, existing.lastSeenAt) >= 0 ? alert.lastSeenAt : existing.lastSeenAt,
      updatedAt: compareIsoDates(alert.updatedAt, existing.updatedAt) >= 0 ? alert.updatedAt : existing.updatedAt,
      occurrences: alert.occurrences + existing.occurrences,
      status: mergeAlertStatus(alert.status, existing.status),
      note: latest.note ?? earliest.note,
    });
  }

  return Array.from(merged.values()).sort((left, right) => compareIsoDates(right.lastSeenAt, left.lastSeenAt));
}

function normalizeIncidentAlert(candidate: unknown): IncidentAlert {
  const fallbackTime = nowIso();

  if (!candidate || typeof candidate !== 'object') {
    return {
      id: `legacy-${Math.random().toString(16).slice(2)}`,
      createdAt: fallbackTime,
      projectId: 'unknown',
      projectName: 'Unknown Project',
      ruleId: 'legacy',
      ruleName: 'Legacy Alert',
      severity: 'medium',
      summary: 'Legacy alert payload imported without structured fields',
      details: {},
      fingerprint: buildAlertFingerprint({ projectId: 'unknown', ruleId: 'legacy' }),
      status: 'open',
      firstSeenAt: fallbackTime,
      lastSeenAt: fallbackTime,
      updatedAt: fallbackTime,
      occurrences: 1,
    };
  }

  const raw = candidate as Partial<IncidentAlert> & Partial<Alert>;
  const createdAt = typeof raw.createdAt === 'string' ? raw.createdAt : fallbackTime;
  const projectId = typeof raw.projectId === 'string' ? raw.projectId : 'unknown';
  const ruleId = typeof raw.ruleId === 'string' ? raw.ruleId : 'legacy';

  return {
    id: typeof raw.id === 'string' ? raw.id : `legacy-${Math.random().toString(16).slice(2)}`,
    createdAt,
    projectId,
    projectName: typeof raw.projectName === 'string' ? raw.projectName : 'Unknown Project',
    ruleId,
    ruleName: typeof raw.ruleName === 'string' ? raw.ruleName : 'Legacy Alert',
    severity: isSeverity(raw.severity) ? raw.severity : 'medium',
    summary: typeof raw.summary === 'string' ? raw.summary : 'Legacy alert without summary',
    details: raw.details && typeof raw.details === 'object' ? raw.details : {},
    fingerprint:
      typeof raw.fingerprint === 'string' && raw.fingerprint.length > 0
        ? raw.fingerprint
        : buildAlertFingerprint({ projectId, ruleId }),
    status: isAlertStatus(raw.status) ? raw.status : 'open',
    firstSeenAt: typeof raw.firstSeenAt === 'string' ? raw.firstSeenAt : createdAt,
    lastSeenAt: typeof raw.lastSeenAt === 'string' ? raw.lastSeenAt : createdAt,
    updatedAt: typeof raw.updatedAt === 'string' ? raw.updatedAt : createdAt,
    occurrences: Number.isFinite(raw.occurrences) ? Number(raw.occurrences) : 1,
    note: typeof raw.note === 'string' ? raw.note : undefined,
    acknowledgedAt: typeof raw.acknowledgedAt === 'string' ? raw.acknowledgedAt : undefined,
    resolvedAt: typeof raw.resolvedAt === 'string' ? raw.resolvedAt : undefined,
    ackResponseSeconds: Number.isFinite(raw.ackResponseSeconds) ? Number(raw.ackResponseSeconds) : undefined,
  };
}

function normalizeScanRecord(candidate: unknown): ScanRecord {
  const now = nowIso();
  const raw = candidate && typeof candidate === 'object' ? (candidate as Partial<ScanRecord>) : {};
  return {
    id: typeof raw.id === 'string' ? raw.id : `scan-${Math.random().toString(16).slice(2)}`,
    startedAt: typeof raw.startedAt === 'string' ? raw.startedAt : now,
    finishedAt: typeof raw.finishedAt === 'string' ? raw.finishedAt : now,
    latestCheckpoint: Number.isFinite(raw.latestCheckpoint) ? Number(raw.latestCheckpoint) : 0,
    checkpointsProcessed: Number.isFinite(raw.checkpointsProcessed) ? Number(raw.checkpointsProcessed) : 0,
    transactionsProcessed: Number.isFinite(raw.transactionsProcessed) ? Number(raw.transactionsProcessed) : 0,
    alertsTriggered: Number.isFinite(raw.alertsTriggered) ? Number(raw.alertsTriggered) : 0,
    durationMs: Number.isFinite(raw.durationMs) ? Number(raw.durationMs) : 0,
    success: Boolean(raw.success),
    error: typeof raw.error === 'string' ? raw.error : undefined,
  };
}

function normalizeObjectSnapshots(candidate: unknown): Record<string, ObjectSnapshot> {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    return {};
  }

  const snapshots: Record<string, ObjectSnapshot> = {};
  for (const [address, value] of Object.entries(candidate as Record<string, unknown>)) {
    if (!value || typeof value !== 'object') {
      continue;
    }
    const raw = value as Partial<ObjectSnapshot>;
    snapshots[address] = {
      label: typeof raw.label === 'string' ? raw.label : address,
      address: typeof raw.address === 'string' ? raw.address : address,
      projectId: typeof raw.projectId === 'string' ? raw.projectId : 'unknown',
      projectName: typeof raw.projectName === 'string' ? raw.projectName : 'Unknown Project',
      version: Number.isFinite(raw.version) ? Number(raw.version) : undefined,
      digest: typeof raw.digest === 'string' ? raw.digest : undefined,
      type: typeof raw.type === 'string' ? raw.type : undefined,
      contents: raw.contents && typeof raw.contents === 'object' ? raw.contents as Record<string, unknown> : {},
      updatedAt: typeof raw.updatedAt === 'string' ? raw.updatedAt : nowIso(),
    };
  }
  return snapshots;
}

function normalizeTransactionDigests(candidate: unknown): string[] {
  if (!Array.isArray(candidate)) {
    return [];
  }

  return candidate.filter((item): item is string => typeof item === 'string').slice(0, MAX_RECENT_TRANSACTION_DIGESTS);
}

function normalizePriceReferenceProfiles(candidate: unknown): Record<string, PriceReferenceProfile> {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    return {};
  }

  const profiles: Record<string, PriceReferenceProfile> = {};
  for (const [key, value] of Object.entries(candidate as Record<string, unknown>)) {
    if (!value || typeof value !== 'object') {
      continue;
    }
    const raw = value as Partial<PriceReferenceProfile>;
    profiles[key] = {
      projectId: typeof raw.projectId === 'string' ? raw.projectId : 'unknown',
      label: typeof raw.label === 'string' ? raw.label : key,
      recentObservedPrices: Array.isArray(raw.recentObservedPrices)
        ? raw.recentObservedPrices.filter((item): item is string => typeof item === 'string')
        : [],
      medianPrice: typeof raw.medianPrice === 'string' ? raw.medianPrice : undefined,
      updatedAt: typeof raw.updatedAt === 'string' ? raw.updatedAt : nowIso(),
    };
  }
  return profiles;
}

function normalizeObjectBaselineProfiles(candidate: unknown): Record<string, ObjectBaselineProfile> {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    return {};
  }

  const profiles: Record<string, ObjectBaselineProfile> = {};
  for (const [key, value] of Object.entries(candidate as Record<string, unknown>)) {
    if (!value || typeof value !== 'object') {
      continue;
    }
    const raw = value as Partial<ObjectBaselineProfile>;
    const fields = raw.fields && typeof raw.fields === 'object' ? raw.fields : {};
    profiles[key] = {
      projectId: typeof raw.projectId === 'string' ? raw.projectId : 'unknown',
      objectLabel: typeof raw.objectLabel === 'string' ? raw.objectLabel : key,
      fields: Object.fromEntries(
        Object.entries(fields).map(([field, fieldValue]) => {
          const rawField = fieldValue && typeof fieldValue === 'object' ? fieldValue as Record<string, unknown> : {};
          return [field, {
            lastValue: typeof rawField.lastValue === 'string' ? rawField.lastValue : undefined,
            minValue: typeof rawField.minValue === 'string' ? rawField.minValue : undefined,
            maxValue: typeof rawField.maxValue === 'string' ? rawField.maxValue : undefined,
            lastSender: typeof rawField.lastSender === 'string' ? rawField.lastSender : undefined,
            lastUpdatedAt: typeof rawField.lastUpdatedAt === 'string' ? rawField.lastUpdatedAt : undefined,
          }];
        }),
      ),
    };
  }
  return profiles;
}

function normalizeFlowHistory(candidate: unknown): Record<string, FlowHistoryEntry[]> {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    return {};
  }

  const history: Record<string, FlowHistoryEntry[]> = {};
  for (const [projectId, value] of Object.entries(candidate as Record<string, unknown>)) {
    if (!Array.isArray(value)) {
      continue;
    }
    history[projectId] = value
      .map((item) => normalizeFlowHistoryEntry(item, projectId))
      .filter((item): item is FlowHistoryEntry => item !== null);
  }
  return history;
}

function normalizeFlowHistoryEntry(candidate: unknown, fallbackProjectId: string): FlowHistoryEntry | null {
  if (!candidate || typeof candidate !== 'object') {
    return null;
  }

  const raw = candidate as Partial<FlowHistoryEntry>;
  if (typeof raw.digest !== 'string' || typeof raw.timestamp !== 'string') {
    return null;
  }

  return {
    projectId: typeof raw.projectId === 'string' ? raw.projectId : fallbackProjectId,
    digest: raw.digest,
    timestamp: raw.timestamp,
    sender: typeof raw.sender === 'string' ? raw.sender : undefined,
    flashLikeFundingDetected: Boolean(raw.flashLikeFundingDetected),
    manipulationDetected: Boolean(raw.manipulationDetected),
    netProtectedOutflow: typeof raw.netProtectedOutflow === 'string' ? raw.netProtectedOutflow : '0',
    netAttackerGain: typeof raw.netAttackerGain === 'string' ? raw.netAttackerGain : '0',
  };
}

function compareIsoDates(left: string, right: string): number {
  const leftTime = Date.parse(left);
  const rightTime = Date.parse(right);
  return leftTime - rightTime;
}

function mergeAlertStatus(left: AlertStatus, right: AlertStatus): AlertStatus {
  if (left === 'open' || right === 'open') {
    return 'open';
  }
  if (left === 'acknowledged' || right === 'acknowledged') {
    return 'acknowledged';
  }
  return 'resolved';
}

function isSeverity(value: unknown): value is IncidentAlert['severity'] {
  return value === 'info' || value === 'low' || value === 'medium' || value === 'high' || value === 'critical';
}

function isAlertStatus(value: unknown): value is AlertStatus {
  return value === 'open' || value === 'acknowledged' || value === 'resolved';
}
