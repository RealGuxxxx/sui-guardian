import { createHash, randomUUID } from 'node:crypto';

import type { Alert, Severity } from './types.js';

export function canonicalizeSuiAddress(address: string): string {
  const normalized = address.trim().toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]+$/.test(normalized) || normalized.length > 64 || normalized.length === 0) {
    throw new Error(`Invalid Sui address: ${address}`);
  }
  return `0x${normalized.padStart(64, '0')}`;
}

export function sameAddress(left?: string, right?: string): boolean {
  if (!left || !right) {
    return false;
  }
  return canonicalizeSuiAddress(left) === canonicalizeSuiAddress(right);
}

export function matchesPattern(value: string, pattern: string): boolean {
  if (pattern === '*') {
    return true;
  }
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`, 'i').test(value);
}

export function toBigInt(value: string): bigint {
  return BigInt(value);
}

export function getValueAtPath(source: unknown, path: string): unknown {
  if (!path) {
    return source;
  }

  const segments = path.split('.').filter(Boolean);
  let current = source;

  for (const segment of segments) {
    if (Array.isArray(current) && /^\d+$/.test(segment)) {
      current = current[Number(segment)];
      continue;
    }

    if (!current || typeof current !== 'object') {
      return undefined;
    }

    current = (current as Record<string, unknown>)[segment];
  }

  return current;
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function createAlert(input: Omit<Alert, 'id' | 'createdAt'>): Alert {
  return {
    id: randomUUID(),
    createdAt: nowIso(),
    ...input,
  };
}

export function buildAlertFingerprint(
  alert: Pick<Alert, 'projectId' | 'ruleId'> & { details?: Record<string, unknown> },
): string {
  // 对于 attack: 类告警，加入 sender 使不同攻击者的同类攻击各自独立 incident
  if (alert.ruleId.startsWith('attack:') && typeof alert.details?.sender === 'string' && alert.details.sender.length > 0) {
    return createHash('sha256').update(`${alert.projectId}:${alert.ruleId}:${alert.details.sender}`).digest('hex').slice(0, 24);
  }
  return createHash('sha256').update(`${alert.projectId}:${alert.ruleId}`).digest('hex').slice(0, 24);
}

export function priceDeviationExceedsThreshold(
  item: { deviationBps?: number; thresholdBps?: number; thresholdExceeded?: boolean },
  fallbackThreshold = 1500,
): boolean {
  if (item.thresholdExceeded !== undefined) {
    return item.thresholdExceeded;
  }

  return (item.deviationBps ?? 0) >= (item.thresholdBps ?? fallbackThreshold);
}

export function severityRank(severity: Severity): number {
  return {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
  }[severity];
}

export function summarizeAlert(alert: Alert): string {
  return `[${alert.severity.toUpperCase()}] ${alert.projectName} / ${alert.ruleName}: ${alert.summary}`;
}

export function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}
