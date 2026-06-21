import type { AttackDetectorContext, AttackFinding } from '../types.js';

const SIGNER_FIELD_KEYWORDS = ['signer_set', 'reporter_set', 'updater_set', 'oracle_signers'];

export function detectOracleSignerSetRotationAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const signerShift = (ctx.derived.baselineEvidence ?? []).find((item) => {
    const fieldName = `${item.objectLabel}.${item.field}`.toLowerCase();
    return !item.senderAuthorized && SIGNER_FIELD_KEYWORDS.some((keyword) => fieldName.includes(keyword));
  });
  const hasBorrowOrLiquidationCall = ctx.tx.calls.some((call) => {
    const name = `${call.module}::${call.function}`.toLowerCase();
    return name.includes('borrow') || name.includes('loan') || name.includes('liquidat');
  });
  const flow = ctx.derived.flowEvidence;

  if (!signerShift || !hasBorrowOrLiquidationCall || !ctx.derived.valueExtractionDetected) {
    return [];
  }

  if (!flow?.attackPathFound || !flow.pathRoles.includes('protected_outflow') || !flow.pathRoles.includes('attacker_receipt')) {
    return [];
  }

  return [
    {
      attackType: 'oracle-signer-set-rotation',
      category: 'permission',
      summary: '检测到 oracle signer/reporter 集合被未授权轮换后紧随借贷或清算提取',
      evidence: {
        objectLabel: signerShift.objectLabel,
        field: signerShift.field,
        anomalyKind: signerShift.anomalyKind,
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
