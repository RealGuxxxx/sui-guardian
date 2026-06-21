import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';

import YAML from 'yaml';

import type { MonitoringProjectConfig } from './types.js';

export type GeneratedProjectRules = Partial<Omit<MonitoringProjectConfig, 'id' | 'name'>> & {
  id?: string;
  name?: string;
};

async function isFile(filePath: string): Promise<boolean> {
  return stat(filePath).then((value) => value.isFile()).catch(() => false);
}

export async function loadGeneratedProjectRules(generatedDir: string): Promise<Record<string, GeneratedProjectRules>> {
  const results: Record<string, GeneratedProjectRules> = {};
  const entries = await readdir(generatedDir, { withFileTypes: true }).catch(() => []);
  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }
    const projectId = entry.name;
    const filePath = path.join(generatedDir, projectId, 'current.yml');
    if (!(await isFile(filePath))) {
      continue;
    }
    const raw = await readFile(filePath, 'utf8');
    const parsed = YAML.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object') {
      continue;
    }
    results[projectId] = parsed as GeneratedProjectRules;
  }
  return results;
}

type RuleKeyFn<T> = (item: T) => string;

function mergeByKey<T>(base: T[], generated: T[], keyFn: RuleKeyFn<T>): T[] {
  const map = new Map<string, T>();
  for (const item of base) {
    map.set(keyFn(item), item);
  }
  for (const item of generated) {
    const key = keyFn(item);
    const existing = map.get(key);
    if (!existing) {
      map.set(key, item);
      continue;
    }
    const merged = { ...(existing as object), ...(item as object) } as T;
    for (const field of ['allowedSenders', 'allowedUpgradeSenders', 'deprecatedAddresses'] as const) {
      const current = (existing as Record<string, unknown>)[field];
      const next = (item as Record<string, unknown>)[field];
      if (Array.isArray(current) || Array.isArray(next)) {
        (merged as Record<string, string[]>)[field] = Array.from(
          new Set([
            ...(Array.isArray(current) ? current as string[] : []),
            ...(Array.isArray(next) ? next as string[] : []),
          ]),
        );
      }
    }
    map.set(key, merged);
  }
  return Array.from(map.values());
}

export function mergeProjectRules(base: MonitoringProjectConfig, generated: GeneratedProjectRules | undefined): MonitoringProjectConfig {
  if (!generated) {
    return base;
  }

  const merged: MonitoringProjectConfig = {
    ...base,
    packages: mergeByKey(base.packages, generated.packages ?? [], (item) => item.address),
    protectedAddresses: mergeByKey(base.protectedAddresses, generated.protectedAddresses ?? [], (item) => item.label),
    functionGuards: mergeByKey(base.functionGuards, generated.functionGuards ?? [], (item) => item.label),
    trafficSpikes: mergeByKey(base.trafficSpikes, generated.trafficSpikes ?? [], (item) => item.label),
    failureSpikes: mergeByKey(base.failureSpikes, generated.failureSpikes ?? [], (item) => item.label),
    trackedObjects: mergeByKey(base.trackedObjects, generated.trackedObjects ?? [], (item) => item.label),
    suspiciousTargets: mergeByKey(base.suspiciousTargets, generated.suspiciousTargets ?? [], (item) => item.label),
    priceModels: mergeByKey(base.priceModels, generated.priceModels ?? [], (item) => item.label),
    objectBaselines: mergeByKey(base.objectBaselines, generated.objectBaselines ?? [], (item) => item.label),
    behaviorRules: { ...base.behaviorRules, ...(generated.behaviorRules ?? {}) },
    flowTracking: { ...base.flowTracking, ...(generated.flowTracking ?? {}) },
    suppression: { ...base.suppression, ...(generated.suppression ?? {}) },
    id: base.id,
    name: base.name,
  };

  return merged;
}
