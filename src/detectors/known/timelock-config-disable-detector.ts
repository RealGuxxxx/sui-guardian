import type { AttackDetectorContext, AttackFinding } from '../types.js';

export function detectTimelockConfigDisableAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const hasConfigMutation = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('config') || name.includes('executor') || name.includes('set_');
  });
  const timelockShift = (ctx.derived.baselineEvidence ?? []).find(
    (item) => item.field.toLowerCase().includes('timelock') && !item.senderAuthorized,
  );

  if (!hasConfigMutation || !timelockShift) {
    return [];
  }

  return [
    {
      attackType: 'timelock-config-disable',
      category: 'governance',
      summary: '检测到 timelock 类配置被未授权关闭后紧接关键配置变更',
      evidence: {
        objectLabel: timelockShift.objectLabel,
        field: timelockShift.field,
        anomalyKind: timelockShift.anomalyKind,
        calls: ctx.tx.calls,
      },
      riskHints: {
        scoreDelta: 30,
        severityFloor: 'high',
      },
      chainHints: {
        stage: 'takeover',
      },
    },
  ];
}
