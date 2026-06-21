import type { AttackDetectorContext, AttackFinding } from '../types.js';

const UPDATER_FIELD_KEYWORDS = ['updater_quorum', 'signer_quorum', 'update_quorum', 'oracle_quorum'];

export function detectOracleUpdaterQuorumCollapseAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const updaterShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && UPDATER_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrLiquidationCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('liquidat');
  });
  const flow = ctx.derived.flowEvidence;

  if (!updaterShift || !hasBorrowOrLiquidationCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-updater-quorum-collapse',
      category: 'price-manipulation',
      summary: '检测到 oracle 更新者共识阈值被压缩后紧随借贷或清算提取',
      evidence: {
        objectLabel: updaterShift.objectLabel,
        field: updaterShift.field,
        anomalyKind: updaterShift.anomalyKind,
        pathRoles: flow.pathRoles,
        netProtectedOutflow: flow.netProtectedOutflow,
        netAttackerGain: flow.netAttackerGain,
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
