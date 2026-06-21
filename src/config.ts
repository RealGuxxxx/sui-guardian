import { readFile } from 'node:fs/promises';

import YAML from 'yaml';
import { z } from 'zod';

import type {
  AppConfig,
  BehaviorRuleConfig,
  FailureSpikeConfig,
  FlowTrackingConfig,
  FunctionGuardConfig,
  MaintenanceWindowConfig,
  MonitoringProjectConfig,
  ObjectBaselineConfig,
  ObjectBaselineFieldConfig,
  PackageWatchConfig,
  PriceModelConfig,
  ProtectedAddressConfig,
  SuspiciousTargetConfig,
  SuppressionConfig,
  TrackedObjectConfig,
  TrafficSpikeConfig,
} from './types.js';
import { loadGeneratedProjectRules, mergeProjectRules } from './generated-rules.js';
import { canonicalizeSuiAddress } from './utils.js';

const packageSchema = z.object({
  label: z.string().optional(),
  address: z.string().min(1),
  allowedUpgradeSenders: z.array(z.string().min(1)).optional().default([]),
  deprecatedAddresses: z.array(z.string().min(1)).optional().default([]),
});

const protectedAddressSchema = z.object({
  label: z.string().min(1),
  address: z.string().min(1),
  outflowThresholds: z.record(z.string(), z.string()),
  allowedSenders: z.array(z.string().min(1)).optional().default([]),
});

const functionGuardSchema = z.object({
  label: z.string().min(1),
  package: z.string().min(1),
  module: z.string().min(1),
  function: z.string().min(1),
  allowedSenders: z.array(z.string().min(1)).default([]),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional(),
});

const trafficSpikeSchema = z.object({
  label: z.string().min(1),
  package: z.string().min(1),
  windowSeconds: z.number().int().positive(),
  txCountThreshold: z.number().int().positive(),
  uniqueSenderThreshold: z.number().int().positive(),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional(),
  cooldownSeconds: z.number().int().positive().optional(),
});

const failureSpikeSchema = z.object({
  label: z.string().min(1),
  package: z.string().min(1),
  windowSeconds: z.number().int().positive(),
  failedTxThreshold: z.number().int().positive(),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional(),
  cooldownSeconds: z.number().int().positive().optional(),
});

const trackedObjectSchema = z.object({
  label: z.string().min(1),
  address: z.string().min(1),
  watchFields: z.array(z.string().min(1)).optional().default([]),
  criticalFields: z.array(z.string().min(1)).optional().default([]),
  numericDecreaseThresholds: z.record(z.string(), z.string()).optional().default({}),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional(),
});

const suspiciousTargetSchema = z.object({
  label: z.string().min(1),
  address: z.string().min(1),
});

const behaviorRuleSchema = z.object({
  enabled: z.boolean().default(true),
  minRepeatedCalls: z.number().int().positive().default(2),
  minProtectedOutflow: z.string().min(1).default('1'),
  priceDeviationThresholdBps: z.number().int().positive().default(1500),
});

const attackDetectorSchema = z.object({
  enabled: z.boolean().default(true),
}).default({
  enabled: true,
});

const priceModelSchema = z.object({
  label: z.string().min(1),
  trackedObjectLabel: z.string().min(1),
  observedFieldPath: z.string().min(1),
  referenceMode: z.enum(['tracked_field', 'rolling_median', 'fixed_range']).default('rolling_median'),
  referenceObjectLabel: z.string().min(1).optional(),
  referenceFieldPath: z.string().min(1).optional(),
  fixedLowerBound: z.string().min(1).optional(),
  fixedUpperBound: z.string().min(1).optional(),
  deviationThresholdBps: z.number().int().positive().default(1500),
});

const objectBaselineFieldSchema = z.object({
  path: z.string().min(1),
  kind: z.enum(['permission', 'price', 'inventory', 'state']),
  allowedSenders: z.array(z.string().min(1)).default([]),
  maxDeltaBps: z.number().int().nonnegative().optional(),
  maxAbsoluteDecrease: z.string().min(1).optional(),
});

const objectBaselineSchema = z.object({
  label: z.string().min(1),
  trackedObjectLabel: z.string().min(1),
  fields: z.array(objectBaselineFieldSchema).default([]),
});

const flowTrackingSchema = z.object({
  enabled: z.boolean().default(true),
  minProtectedOutflow: z.string().min(1).default('1'),
  attackerGainThreshold: z.string().min(1).default('1'),
  shortWindowTxCount: z.number().int().positive().default(2),
});

const maintenanceWindowSchema = z.object({
  label: z.string().min(1),
  allowedSenders: z.array(z.string().min(1)).default([]),
  startHourUtc: z.number().int().min(0).max(23),
  endHourUtc: z.number().int().min(0).max(23),
});

const suppressionSchema = z.object({
  enabled: z.boolean().default(true),
  duplicateWindowSeconds: z.number().int().positive().default(600),
  weakSignalScoreThreshold: z.number().int().nonnegative().default(35),
  maintenanceWindows: z.array(maintenanceWindowSchema).default([]),
});

const aiRulesSchema = z.object({
  enabled: z.boolean().default(false),
  generatedDir: z.string().min(1).default('.data/generated'),
  reloadIntervalMs: z.number().int().positive().default(60_000),
  shadow: z.object({
    enabled: z.boolean().default(true),
    notify: z.boolean().default(false),
    minMinutes: z.number().int().positive().default(60),
  }).default({
    enabled: true,
    notify: false,
    minMinutes: 60,
  }),
  canary: z.object({
    enabled: z.boolean().default(true),
    stage: z.enum(['shadow', 'traffic_failure', 'objects_prices', 'full']).default('shadow'),
    promotionMinMinutes: z.number().int().positive().default(60),
  }).default({
    enabled: true,
    stage: 'shadow',
    promotionMinMinutes: 60,
  }),
  generator: z.object({
    enabled: z.boolean().default(false),
    sourceRoot: z.string().default(''),
    deploymentsDir: z.string().min(1).default('.data/deployments'),
    modelBaseUrl: z.string().url().default('https://api.openai.com'),
    modelName: z.string().min(1).default('gpt-5.4'),
    regenerateIntervalHours: z.number().int().positive().default(168),
  }).default({
    enabled: false,
    sourceRoot: '',
    deploymentsDir: '.data/deployments',
    modelBaseUrl: 'https://api.openai.com',
    modelName: 'gpt-5.4',
    regenerateIntervalHours: 168,
  }),
}).default({
  enabled: false,
  generatedDir: '.data/generated',
  reloadIntervalMs: 60_000,
  shadow: {
    enabled: true,
    notify: false,
    minMinutes: 60,
  },
  canary: {
    enabled: true,
    stage: 'shadow',
    promotionMinMinutes: 60,
  },
  generator: {
    enabled: false,
    sourceRoot: '',
    deploymentsDir: '.data/deployments',
    modelBaseUrl: 'https://api.openai.com',
    modelName: 'gpt-5.4',
    regenerateIntervalHours: 168,
  },
});

const schema = z.object({
  network: z.object({
    name: z.string().min(1),
    graphqlEndpoint: z.string().url(),
    pollIntervalMs: z.number().int().positive(),
    bootstrapLookbackCheckpoints: z.number().int().nonnegative(),
    checkpointOverlap: z.number().int().nonnegative().default(3),
    maxCheckpointsPerTick: z.number().int().positive(),
    maxTransactionsPerPage: z.number().int().positive().max(200),
  }),
  storage: z.object({
    stateFile: z.string().min(1),
    maxAlerts: z.number().int().positive(),
  }),
  server: z.object({
    host: z.string().min(1),
    port: z.number().int().positive(),
  }),
  alerts: z.object({
    console: z.boolean().default(true),
    webhookUrl: z.string().optional().default(''),
  }),
  aiRules: aiRulesSchema.optional(),
  projects: z.array(
    z.object({
      id: z.string().min(1),
      name: z.string().min(1),
      packages: z.array(packageSchema).default([]),
      protectedAddresses: z.array(protectedAddressSchema).default([]),
      functionGuards: z.array(functionGuardSchema).default([]),
      trafficSpikes: z.array(trafficSpikeSchema).default([]),
      failureSpikes: z.array(failureSpikeSchema).default([]),
      trackedObjects: z.array(trackedObjectSchema).default([]),
      suspiciousTargets: z.array(suspiciousTargetSchema).default([]),
      behaviorRules: behaviorRuleSchema.default({
        enabled: true,
        minRepeatedCalls: 2,
        minProtectedOutflow: '1',
        priceDeviationThresholdBps: 1500,
      }),
      attackDetectors: attackDetectorSchema.optional(),
      priceModels: z.array(priceModelSchema).default([]),
      objectBaselines: z.array(objectBaselineSchema).default([]),
      flowTracking: flowTrackingSchema.default({
        enabled: true,
        minProtectedOutflow: '1',
        attackerGainThreshold: '1',
        shortWindowTxCount: 2,
      }),
      suppression: suppressionSchema.default({
        enabled: true,
        duplicateWindowSeconds: 600,
        weakSignalScoreThreshold: 35,
        maintenanceWindows: [],
      }),
    }),
  ).default([]),
});

function normalizePackage(config: z.infer<typeof packageSchema>): PackageWatchConfig {
  return {
    label: config.label,
    address: canonicalizeSuiAddress(config.address),
    allowedUpgradeSenders: config.allowedUpgradeSenders?.map(canonicalizeSuiAddress) ?? [],
    deprecatedAddresses: config.deprecatedAddresses?.map(canonicalizeSuiAddress) ?? [],
  };
}

function normalizeProtectedAddress(config: z.infer<typeof protectedAddressSchema>): ProtectedAddressConfig {
  return {
    label: config.label,
    address: canonicalizeSuiAddress(config.address),
    outflowThresholds: config.outflowThresholds,
    allowedSenders: config.allowedSenders?.map(canonicalizeSuiAddress) ?? [],
  };
}

function normalizeFunctionGuard(config: z.infer<typeof functionGuardSchema>): FunctionGuardConfig {
  return {
    label: config.label,
    package: canonicalizeSuiAddress(config.package),
    module: config.module,
    function: config.function,
    allowedSenders: config.allowedSenders.map(canonicalizeSuiAddress),
    severity: config.severity,
  };
}

function normalizeTrafficSpike(config: z.infer<typeof trafficSpikeSchema>): TrafficSpikeConfig {
  return {
    label: config.label,
    package: canonicalizeSuiAddress(config.package),
    windowSeconds: config.windowSeconds,
    txCountThreshold: config.txCountThreshold,
    uniqueSenderThreshold: config.uniqueSenderThreshold,
    severity: config.severity,
    cooldownSeconds: config.cooldownSeconds,
  };
}

function normalizeFailureSpike(config: z.infer<typeof failureSpikeSchema>): FailureSpikeConfig {
  return {
    label: config.label,
    package: canonicalizeSuiAddress(config.package),
    windowSeconds: config.windowSeconds,
    failedTxThreshold: config.failedTxThreshold,
    severity: config.severity,
    cooldownSeconds: config.cooldownSeconds,
  };
}

function normalizeTrackedObject(config: z.infer<typeof trackedObjectSchema>): TrackedObjectConfig {
  return {
    label: config.label,
    address: canonicalizeSuiAddress(config.address),
    watchFields: config.watchFields,
    criticalFields: config.criticalFields,
    numericDecreaseThresholds: config.numericDecreaseThresholds,
    severity: config.severity,
  };
}

function normalizeSuspiciousTarget(config: z.infer<typeof suspiciousTargetSchema>): SuspiciousTargetConfig {
  return {
    label: config.label,
    address: canonicalizeSuiAddress(config.address),
  };
}

function normalizeBehaviorRule(config: z.infer<typeof behaviorRuleSchema>): BehaviorRuleConfig {
  return {
    enabled: config.enabled,
    minRepeatedCalls: config.minRepeatedCalls,
    minProtectedOutflow: config.minProtectedOutflow,
    priceDeviationThresholdBps: config.priceDeviationThresholdBps,
  };
}

function normalizePriceModel(config: z.infer<typeof priceModelSchema>): PriceModelConfig {
  return {
    label: config.label,
    trackedObjectLabel: config.trackedObjectLabel,
    observedFieldPath: config.observedFieldPath,
    referenceMode: config.referenceMode,
    referenceObjectLabel: config.referenceObjectLabel,
    referenceFieldPath: config.referenceFieldPath,
    fixedLowerBound: config.fixedLowerBound,
    fixedUpperBound: config.fixedUpperBound,
    deviationThresholdBps: config.deviationThresholdBps,
  };
}

function normalizeObjectBaselineField(config: z.infer<typeof objectBaselineFieldSchema>): ObjectBaselineFieldConfig {
  return {
    path: config.path,
    kind: config.kind,
    allowedSenders: config.allowedSenders.map(canonicalizeSuiAddress),
    maxDeltaBps: config.maxDeltaBps,
    maxAbsoluteDecrease: config.maxAbsoluteDecrease,
  };
}

function normalizeObjectBaseline(config: z.infer<typeof objectBaselineSchema>): ObjectBaselineConfig {
  return {
    label: config.label,
    trackedObjectLabel: config.trackedObjectLabel,
    fields: config.fields.map(normalizeObjectBaselineField),
  };
}

function normalizeFlowTracking(config: z.infer<typeof flowTrackingSchema>): FlowTrackingConfig {
  return {
    enabled: config.enabled,
    minProtectedOutflow: config.minProtectedOutflow,
    attackerGainThreshold: config.attackerGainThreshold,
    shortWindowTxCount: config.shortWindowTxCount,
  };
}

function normalizeMaintenanceWindow(config: z.infer<typeof maintenanceWindowSchema>): MaintenanceWindowConfig {
  return {
    label: config.label,
    allowedSenders: config.allowedSenders.map(canonicalizeSuiAddress),
    startHourUtc: config.startHourUtc,
    endHourUtc: config.endHourUtc,
  };
}

function normalizeSuppression(config: z.infer<typeof suppressionSchema>): SuppressionConfig {
  return {
    enabled: config.enabled,
    duplicateWindowSeconds: config.duplicateWindowSeconds,
    weakSignalScoreThreshold: config.weakSignalScoreThreshold,
    maintenanceWindows: config.maintenanceWindows.map(normalizeMaintenanceWindow),
  };
}

function normalizeProject(project: z.infer<typeof schema>['projects'][number]): MonitoringProjectConfig {
  return {
    id: project.id,
    name: project.name,
    packages: project.packages.map(normalizePackage),
    protectedAddresses: project.protectedAddresses.map(normalizeProtectedAddress),
    functionGuards: project.functionGuards.map(normalizeFunctionGuard),
    trafficSpikes: project.trafficSpikes.map(normalizeTrafficSpike),
    failureSpikes: project.failureSpikes.map(normalizeFailureSpike),
    trackedObjects: project.trackedObjects.map(normalizeTrackedObject),
    suspiciousTargets: project.suspiciousTargets.map(normalizeSuspiciousTarget),
    behaviorRules: normalizeBehaviorRule(project.behaviorRules),
    attackDetectors: project.attackDetectors,
    priceModels: project.priceModels.map(normalizePriceModel),
    objectBaselines: project.objectBaselines.map(normalizeObjectBaseline),
    flowTracking: normalizeFlowTracking(project.flowTracking),
    suppression: normalizeSuppression(project.suppression),
  };
}

export async function loadConfig(path: string): Promise<AppConfig> {
  const raw = await readFile(path, 'utf8');
  const parsed = schema.parse(YAML.parse(raw));

  return {
    network: parsed.network,
    storage: parsed.storage,
    server: parsed.server,
    alerts: {
      console: parsed.alerts.console,
      webhookUrl: parsed.alerts.webhookUrl || undefined,
    },
    aiRules: parsed.aiRules,
    projects: parsed.projects.map(normalizeProject),
  };
}

export async function loadMergedConfig(path: string): Promise<AppConfig> {
  const config = await loadConfig(path);
  const aiRules = config.aiRules;
  if (!aiRules?.enabled) {
    return config;
  }

  const generated = await loadGeneratedProjectRules(aiRules.generatedDir);
  return {
    ...config,
    projects: config.projects.map((project) => mergeProjectRules(project, generated[project.id])),
  };
}
