import type {
  MonitoringProjectConfig,
  ObjectBaselineEvidence,
  ObservedTransaction,
} from '../types.js';
import { sameAddress } from '../utils.js';

interface ObjectBaselineContext {
  tx: ObservedTransaction;
  project: MonitoringProjectConfig;
  previousSnapshots: Record<string, Record<string, unknown>>;
  currentSnapshots: Record<string, Record<string, unknown>>;
}

export function detectObjectBaselineAnomalies(ctx: ObjectBaselineContext): ObjectBaselineEvidence[] {
  return ctx.project.objectBaselines.flatMap((baseline) =>
    baseline.fields.flatMap((field) => {
      const previous = ctx.previousSnapshots[baseline.trackedObjectLabel] ?? {};
      const current = ctx.currentSnapshots[baseline.trackedObjectLabel] ?? {};
      const previousValue = previous[field.path];
      const currentValue = current[field.path];

      if (previousValue === currentValue) {
        return [];
      }

      const senderAuthorized = (field.allowedSenders ?? []).some((sender) => sameAddress(sender, ctx.tx.sender));
      const anomalyKind =
        field.kind === 'permission'
          ? 'permission_change'
          : field.kind === 'price'
            ? 'price_shift'
            : field.kind === 'inventory'
              ? 'inventory_drop'
              : 'state_flip';

      return [{
        objectLabel: baseline.trackedObjectLabel,
        field: field.path,
        previousValue: previousValue === undefined ? undefined : String(previousValue),
        currentValue: currentValue === undefined ? undefined : String(currentValue),
        expectedRange: field.maxDeltaBps !== undefined ? `delta_bps<=${field.maxDeltaBps}` : undefined,
        anomalyKind,
        senderAuthorized,
      }];
    }),
  );
}
