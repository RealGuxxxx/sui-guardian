import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectMaintenanceWindowBypassAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const windows = ctx.project.suppression.maintenanceWindows ?? [];
  if (windows.length === 0 || !ctx.tx.sender) {
    return [];
  }

  const hour = new Date(ctx.tx.timestamp).getUTCHours();
  const senderWindows = windows.filter((window) => window.allowedSenders.includes(ctx.tx.sender!));
  if (senderWindows.length === 0) {
    return [];
  }

  const inAllowedWindow = senderWindows.some((window) => hour >= window.startHourUtc && hour < window.endHourUtc);
  const hasPrivilegedSignal = (ctx.derived.baselineEvidence ?? []).some((item) => item.anomalyKind === 'permission_change');

  if (inAllowedWindow || !hasPrivilegedSignal) {
    return [];
  }

  return [
    {
      attackType: 'maintenance-window-bypass',
      category: 'governance',
      summary: '检测到高权限操作发生在允许维护窗口之外',
      evidence: {
        sender: ctx.tx.sender,
        timestamp: ctx.tx.timestamp,
        maintenanceWindows: senderWindows.map((window) => window.label),
      },
      riskHints: {
        scoreDelta: 20,
        severityFloor: 'medium',
      },
      chainHints: {
        stage: 'takeover',
      },
    },
  ];
}
