import type { Alert, DerivedEvidence, ObservedTransaction, Severity } from './types.js';
import { createAlert, matchesPattern, sameAddress } from './utils.js';

export interface SensitiveCallPattern {
  label: string;
  package: string;
  module: string;
  function: string;
  allowedSenders?: string[];
  severity?: Severity;
}

export interface RuleContext {
  projectId: string;
  projectName: string;
  tx: ObservedTransaction;
  protectedAddresses: string[];
  sensitiveCalls: SensitiveCallPattern[];
  derived?: DerivedEvidence;
}

export function runBehaviorRules(ctx: RuleContext): Alert[] {
  return [
    ...detectUnauthorizedSensitiveCall(ctx),
    ...detectRepeatedDrainPattern(ctx),
    ...detectFlashLoanLikeAttack(ctx),
    ...detectPriceManipulation(ctx),
    ...detectSuspiciousTargetCalls(ctx),
  ];
}

function detectUnauthorizedSensitiveCall(ctx: RuleContext): Alert[] {
  const matches = ctx.sensitiveCalls.filter((pattern) =>
    ctx.tx.calls.some(
      (call) =>
        sameAddress(call.package, pattern.package) &&
        matchesPattern(call.module, pattern.module) &&
        matchesPattern(call.function, pattern.function),
    ),
  );

  return matches
    .filter((pattern) => !(pattern.allowedSenders ?? []).some((sender) => sameAddress(sender, ctx.tx.sender)))
    .map((pattern) =>
      createAlert({
        projectId: ctx.projectId,
        projectName: ctx.projectName,
        ruleId: `behavior:unauthorized-sensitive:${pattern.label}`,
        ruleName: '行为规则 / 非授权敏感函数调用',
        severity: pattern.severity ?? 'critical',
        summary: `非授权地址调用敏感函数 ${pattern.module}::${pattern.function}`,
        details: {
          digest: ctx.tx.digest,
          checkpoint: ctx.tx.checkpoint,
          sender: ctx.tx.sender,
          label: pattern.label,
          riskScore: ctx.derived?.risk?.riskScore ?? 0,
          confidence: ctx.derived?.risk?.confidence ?? 0,
          evidenceSummary: ctx.derived?.evidenceSummary ?? [],
          attackFindings: ctx.derived?.attackFindings ?? [],
        },
      }),
    );
}

function detectRepeatedDrainPattern(ctx: RuleContext): Alert[] {
  const repeated = Object.entries(ctx.derived?.sameSensitiveCallRepeats ?? {}).find(([, count]) => count >= 2);
  if (!repeated) {
    return [];
  }

  const protectedOutflow = ctx.tx.balanceChanges.reduce((total, change) => {
    if (!change.owner || !ctx.protectedAddresses.some((item) => sameAddress(item, change.owner))) {
      return total;
    }

    const amount = BigInt(change.amount);
    return amount < 0n ? total + amount * -1n : total;
  }, 0n);

  if (protectedOutflow < 1n) {
    return [];
  }

  return [
    createAlert({
      projectId: ctx.projectId,
      projectName: ctx.projectName,
      ruleId: `behavior:repeated-drain:${repeated[0]}`,
      ruleName: '行为规则 / 重复高危消耗模式',
      severity: 'critical',
      summary: `同一交易内重复高危调用 ${repeated[0]}，并出现关键资产流出`,
      details: {
        digest: ctx.tx.digest,
        checkpoint: ctx.tx.checkpoint,
        sender: ctx.tx.sender,
        repeatedCall: repeated[0],
        repeatCount: repeated[1],
        protectedOutflow: protectedOutflow.toString(),
        riskScore: ctx.derived?.risk?.riskScore ?? 0,
        confidence: ctx.derived?.risk?.confidence ?? 0,
        evidenceSummary: ctx.derived?.evidenceSummary ?? [],
        attackFindings: ctx.derived?.attackFindings ?? [],
      },
    }),
  ];
}

function detectFlashLoanLikeAttack(ctx: RuleContext): Alert[] {
  const callNames = ctx.tx.calls.map((call) => `${call.module}::${call.function}`.toLowerCase());
  const hasManipulation = callNames.some((name) =>
    ['swap', 'mint', 'deposit', 'vote'].some((keyword) => name.includes(keyword)),
  );
  const hasExtraction = callNames.some((name) =>
    ['withdraw', 'redeem', 'claim', 'liquidate', 'borrow'].some((keyword) => name.includes(keyword)),
  );

  if (!ctx.derived?.flashLikeFundingDetected || !hasManipulation || !hasExtraction) {
    return [];
  }

  return [
    createAlert({
      projectId: ctx.projectId,
      projectName: ctx.projectName,
      ruleId: 'behavior:flashloan-like-attack',
      ruleName: '行为规则 / 闪电贷式攻击闭环',
      severity: 'critical',
      summary: '检测到临时大额注资后紧接状态操纵与价值提取的闭环行为',
      details: {
        digest: ctx.tx.digest,
        checkpoint: ctx.tx.checkpoint,
        sender: ctx.tx.sender,
        calls: ctx.tx.calls,
        riskScore: ctx.derived?.risk?.riskScore ?? 0,
        confidence: ctx.derived?.risk?.confidence ?? 0,
        evidenceSummary: ctx.derived?.evidenceSummary ?? [],
        attackFindings: ctx.derived?.attackFindings ?? [],
      },
    }),
  ];
}

function detectPriceManipulation(ctx: RuleContext): Alert[] {
  const matched = (ctx.derived?.priceEvidence ?? []).find(
    (item) => (item.deviationBps ?? 0) >= 1500 && item.extractionCoupled,
  );
  const fallbackDeviation = ctx.derived?.priceDeviationBps ?? 0;
  const deviation = matched?.deviationBps ?? fallbackDeviation;

  if (deviation < 1500 || !ctx.derived?.valueExtractionDetected) {
    return [];
  }

  return [
    createAlert({
      projectId: ctx.projectId,
      projectName: ctx.projectName,
      ruleId: 'behavior:price-manipulation',
      ruleName: '行为规则 / 价格操纵后价值提取',
      severity: ctx.derived?.suppression?.finalSeverity ?? ctx.derived?.risk?.recommendedSeverity ?? 'critical',
      summary: `价格偏离 ${deviation} bps，且同交易发生价值提取动作`,
      details: {
        digest: ctx.tx.digest,
        checkpoint: ctx.tx.checkpoint,
        sender: ctx.tx.sender,
        priceDeviationBps: deviation,
        riskScore: ctx.derived?.risk?.riskScore ?? 0,
        confidence: ctx.derived?.risk?.confidence ?? 0,
        evidenceSummary: ctx.derived?.evidenceSummary ?? [],
        attackFindings: ctx.derived?.attackFindings ?? [],
      },
    }),
  ];
}

function detectSuspiciousTargetCalls(ctx: RuleContext): Alert[] {
  const suspiciousTargets = ctx.derived?.suspiciousTargets ?? [];
  if (suspiciousTargets.length === 0) {
    return [];
  }

  return [
    createAlert({
      projectId: ctx.projectId,
      projectName: ctx.projectName,
      ruleId: 'behavior:suspicious-target-call',
      ruleName: '行为规则 / 可疑外部目标调用',
      severity: 'high',
      summary: `命中非白名单外部目标 ${suspiciousTargets.join(', ')}`,
      details: {
        digest: ctx.tx.digest,
        checkpoint: ctx.tx.checkpoint,
        sender: ctx.tx.sender,
        suspiciousTargets,
        riskScore: ctx.derived?.risk?.riskScore ?? 0,
        confidence: ctx.derived?.risk?.confidence ?? 0,
        evidenceSummary: ctx.derived?.evidenceSummary ?? [],
        attackFindings: ctx.derived?.attackFindings ?? [],
      },
    }),
  ];
}
