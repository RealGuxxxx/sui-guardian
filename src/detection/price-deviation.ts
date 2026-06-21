import type {
  MonitoringProjectConfig,
  ObservedTransaction,
  PriceDeviationEvidence,
  PriceReferenceProfile,
} from '../types.js';

interface PriceDeviationContext {
  tx: ObservedTransaction;
  project: MonitoringProjectConfig;
  trackedSnapshots: Record<string, Record<string, unknown>>;
  priceProfiles: Record<string, PriceReferenceProfile>;
}

export function detectPriceDeviation(ctx: PriceDeviationContext): PriceDeviationEvidence[] {
  return ctx.project.priceModels.map((model) => {
    const snapshot = ctx.trackedSnapshots[model.trackedObjectLabel] ?? {};
    const observedRaw = snapshot[model.observedFieldPath];
    if (observedRaw === undefined) {
      return {
        label: model.label,
        referenceKind: model.referenceMode,
        extractionCoupled: false,
        incomplete: true,
      };
    }

    const observed = Number(observedRaw);
    const profile = ctx.priceProfiles[model.label];
    let reference = observed;

    if (model.referenceMode === 'rolling_median') {
      reference = Number(profile?.medianPrice ?? observedRaw);
    } else if (model.referenceMode === 'fixed_range') {
      reference = Number(model.fixedLowerBound ?? observedRaw);
    } else if (model.referenceMode === 'tracked_field' && model.referenceObjectLabel && model.referenceFieldPath) {
      const referenceSnapshot = ctx.trackedSnapshots[model.referenceObjectLabel] ?? {};
      reference = Number(referenceSnapshot[model.referenceFieldPath] ?? observedRaw);
    }

    const deviationBps = reference === 0 ? 0 : Math.round((Math.abs(observed - reference) / reference) * 10_000);

    return {
      label: model.label,
      observedPrice: String(observedRaw),
      referencePrice: String(reference),
      deviationBps,
      referenceKind: model.referenceMode,
      extractionCoupled: ctx.tx.balanceChanges.some((item) => item.amount.startsWith('-')),
    };
  });
}
