import { z } from 'zod';

const severitySchema = z.enum(['info', 'low', 'medium', 'high', 'critical']);

export const generatedRulesSchema = z.object({
  version: z.string().min(1),
  projectId: z.string().min(1),
  rules: z.object({
    packages: z.array(z.object({
      label: z.string().optional(),
      address: z.string().min(1),
      allowedUpgradeSenders: z.array(z.string().min(1)).optional().default([]),
      deprecatedAddresses: z.array(z.string().min(1)).optional().default([]),
    })).optional().default([]),
    protectedAddresses: z.array(z.object({
      label: z.string().min(1),
      address: z.string().min(1),
      outflowThresholds: z.record(z.string(), z.string()),
      allowedSenders: z.array(z.string().min(1)).optional().default([]),
    })).optional().default([]),
    functionGuards: z.array(z.object({
      label: z.string().min(1),
      package: z.string().min(1),
      module: z.string().min(1),
      function: z.string().min(1),
      allowedSenders: z.array(z.string().min(1)).optional().default([]),
      severity: severitySchema.optional(),
    })).optional().default([]),
    trafficSpikes: z.array(z.object({
      label: z.string().min(1),
      package: z.string().min(1),
      windowSeconds: z.number().int().positive(),
      txCountThreshold: z.number().int().positive(),
      uniqueSenderThreshold: z.number().int().positive(),
      severity: severitySchema.optional(),
      cooldownSeconds: z.number().int().positive().optional(),
    })).optional().default([]),
    failureSpikes: z.array(z.object({
      label: z.string().min(1),
      package: z.string().min(1),
      windowSeconds: z.number().int().positive(),
      failedTxThreshold: z.number().int().positive(),
      severity: severitySchema.optional(),
      cooldownSeconds: z.number().int().positive().optional(),
    })).optional().default([]),
    trackedObjects: z.array(z.object({
      label: z.string().min(1),
      address: z.string().min(1),
      watchFields: z.array(z.string().min(1)).optional().default([]),
      criticalFields: z.array(z.string().min(1)).optional().default([]),
      numericDecreaseThresholds: z.record(z.string(), z.string()).optional().default({}),
      severity: severitySchema.optional(),
    })).optional().default([]),
    suspiciousTargets: z.array(z.object({
      label: z.string().min(1),
      address: z.string().min(1),
    })).optional().default([]),
    behaviorRules: z.object({
      enabled: z.boolean().default(true),
      minRepeatedCalls: z.number().int().positive().default(2),
      minProtectedOutflow: z.string().min(1).default('1'),
      priceDeviationThresholdBps: z.number().int().positive().default(1500),
    }).default({
      enabled: true,
      minRepeatedCalls: 2,
      minProtectedOutflow: '1',
      priceDeviationThresholdBps: 1500,
    }),
    priceModels: z.array(z.object({
      label: z.string().min(1),
      trackedObjectLabel: z.string().min(1),
      observedFieldPath: z.string().min(1),
      referenceMode: z.enum(['tracked_field', 'rolling_median', 'fixed_range']).default('rolling_median'),
      referenceObjectLabel: z.string().min(1).optional(),
      referenceFieldPath: z.string().min(1).optional(),
      fixedLowerBound: z.string().min(1).optional(),
      fixedUpperBound: z.string().min(1).optional(),
      deviationThresholdBps: z.number().int().positive().default(1500),
    })).optional().default([]),
    objectBaselines: z.array(z.object({
      label: z.string().min(1),
      trackedObjectLabel: z.string().min(1),
      fields: z.array(z.object({
        path: z.string().min(1),
        kind: z.enum(['permission', 'price', 'inventory', 'state']),
        allowedSenders: z.array(z.string().min(1)).optional().default([]),
        maxDeltaBps: z.number().int().nonnegative().optional(),
        maxAbsoluteDecrease: z.string().min(1).optional(),
      })).optional().default([]),
    })).optional().default([]),
    flowTracking: z.object({
      enabled: z.boolean().default(true),
      minProtectedOutflow: z.string().min(1).default('1'),
      attackerGainThreshold: z.string().min(1).default('1'),
      shortWindowTxCount: z.number().int().positive().default(2),
    }).default({
      enabled: true,
      minProtectedOutflow: '1',
      attackerGainThreshold: '1',
      shortWindowTxCount: 2,
    }),
    suppression: z.object({
      enabled: z.boolean().default(true),
      duplicateWindowSeconds: z.number().int().positive().default(600),
      weakSignalScoreThreshold: z.number().int().nonnegative().default(35),
      maintenanceWindows: z.array(z.object({
        label: z.string().min(1),
        allowedSenders: z.array(z.string().min(1)).optional().default([]),
        startHourUtc: z.number().int().min(0).max(23),
        endHourUtc: z.number().int().min(0).max(23),
      })).optional().default([]),
    }).default({
      enabled: true,
      duplicateWindowSeconds: 600,
      weakSignalScoreThreshold: 35,
      maintenanceWindows: [],
    }),
  }),
  explanations: z.array(z.object({
    ruleId: z.string().min(1),
    summary: z.string().min(1),
    staticEvidence: z.array(z.string().min(1)).optional().default([]),
    dynamicEvidence: z.array(z.string().min(1)).optional().default([]),
    confidence: z.number().min(0).max(1),
    recommendedSeverity: severitySchema,
  })).optional().default([]),
});

export type GeneratedRulesPayload = z.infer<typeof generatedRulesSchema>;

