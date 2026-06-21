import type { AttackDetectorContext, AttackFinding } from '../types.js';

/**
 * UpgradeCap 滥用检测器
 *
 * 基于 Pawtato Finance 攻击（2026年1月）模式：
 * 合约的 create_new_admin_cap 函数接受任意 UpgradeCap 作为参数
 * 而不验证它来自哪个包，攻击者部署廉价合约获取其 UpgradeCap，
 * 传入受害合约来铸造 AdminCap，进而执行特权操作。
 *
 * 检测信号：
 * 1. 调用了非标准升级生命周期函数（非 authorize_upgrade / commit_upgrade）
 *    但函数名包含 admin/cap/grant/create/mint 等关键词
 * 2. 同一 PTB 在非升级上下文中使用了 UpgradeCap 相关对象
 * 3. UpgradeCap 涉及的包发生了未预期的对象所有权变更
 */

// 正当的升级生命周期函数名（不告警这些）
const LEGITIMATE_UPGRADE_FNS = new Set([
  'authorize_upgrade',
  'commit_upgrade',
  'make_immutable',
  'only_dep_upgrades',
  'only_additive_upgrades',
  'restrict',
]);

// 触发告警的高风险函数名关键词（非升级上下文但接受 Cap 类参数）
const SUSPICIOUS_FN_PATTERNS = [
  'create_admin',
  'create_new_admin',
  'new_admin_cap',
  'grant_admin',
  'mint_cap',
  'create_cap',
  'set_admin',
  'set_owner',
  'transfer_admin',
  'claim_admin',
  'create_role',
  'grant_role',
  'admin_from_upgrade',
];

export function detectUpgradeCapMisuseAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const suspiciousCalls = ctx.tx.calls.filter((call) => {
    const fnLower = call.function.toLowerCase();

    // 跳过标准升级函数
    if (LEGITIMATE_UPGRADE_FNS.has(fnLower)) {
      return false;
    }

    // 检查是否匹配可疑函数名模式
    return SUSPICIOUS_FN_PATTERNS.some((pattern) => fnLower.includes(pattern.toLowerCase()));
  });

  if (suspiciousCalls.length === 0) {
    return [];
  }

  // 检查同一 PTB 是否还有升级相关的对象变更（表明真的有 UpgradeCap 被使用）
  const hasUpgradeObjectChange = ctx.tx.objectChanges.some(
    (change) => change.isPackage && change.outputVersion !== undefined,
  );

  // 检查是否有新建的非包对象（可能是 AdminCap 被铸造）
  const hasNewNonPackageObject = ctx.tx.objectChanges.some(
    (change) => !change.isPackage && change.idCreated,
  );

  // 必须有至少一个佐证信号：升级对象变更或新建对象
  // 没有这些信号说明交易未产生实际效果，不触发告警（避免误报）
  if (!hasUpgradeObjectChange && !hasNewNonPackageObject) {
    return [];
  }

  return [
    {
      attackType: 'upgrade-cap-misuse',
      category: 'permission',
      summary:
        '检测到 UpgradeCap 可能被用于非标准特权函数（Pawtato 攻击模式）：攻击者可能利用任意合约的 UpgradeCap 伪造 AdminCap',
      evidence: {
        sender: ctx.tx.sender,
        suspiciousCalls: suspiciousCalls.map((c) => ({
          package: c.package,
          module: c.module,
          function: c.function,
        })),
        hasUpgradeObjectChange,
        hasNewNonPackageObject,
        allCalls: ctx.tx.calls.map((c) => `${c.module}::${c.function}`),
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
