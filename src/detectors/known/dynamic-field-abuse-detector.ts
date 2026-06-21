import type { AttackDetectorContext, AttackFinding } from '../types.js';

/**
 * Sui Dynamic Field Abuse Detector
 *
 * Sui's `dynamic_field` and `dynamic_object_field` modules allow attaching
 * arbitrary typed fields to objects at runtime — a powerful feature that
 * attackers can exploit to bypass access control or extract assets.
 *
 * Attack patterns:
 *
 * 1. **Unauthorized State Mutation** — Calling `dynamic_field::borrow_mut` on
 *    a shared object (e.g., a vault or config) to modify reserved state
 *    without going through the intended API.
 *    Signal: borrow_mut calls on shared objects in the same PTB as a
 *    value extraction event.
 *
 * 2. **Dynamic Field Drain** — Using `dynamic_field::remove` or
 *    `dynamic_object_field::remove` to extract assets that are stored
 *    inside an object using dynamic storage (common in Kiosk-like designs).
 *    Signal: multiple remove calls + outflow balance changes.
 *
 * 3. **Mass Field Manipulation** — Batch add/remove of dynamic fields in a
 *    single PTB (5+) to manipulate accounting state or drain a collection.
 *    Signal: 5+ dynamic field operations (add/remove/borrow_mut) in one PTB.
 *
 * 4. **Field Key Collision Exploit** — Adding a dynamic field with a key
 *    that shadows/overwrites an existing field used for access gating.
 *    Signal: `add` call immediately preceded/followed by a `borrow_mut`
 *    or privileged function in the same PTB.
 */

const DYNAMIC_FIELD_MODULES = [
  'dynamic_field',
  'dynamic_object_field',
  'df',  // common alias
  'dof', // common alias
];

const BORROW_MUT_PATTERNS = ['borrow_mut', 'borrow_global_mut'];
const REMOVE_PATTERNS = ['remove', 'extract', 'take'];
const ADD_PATTERNS = ['add', 'add_child_object'];
const PRIVILEGED_PATTERNS = [
  'withdraw', 'transfer', 'drain', 'take', 'migrate',
  'admin', 'upgrade', 'set_', 'update_',
];

const MASS_OPS_THRESHOLD = 5;
const REMOVE_THRESHOLD = 2;

function isDfModule(mod: string): boolean {
  const modLower = mod.toLowerCase();
  return DYNAMIC_FIELD_MODULES.some((p) => modLower === p || modLower.endsWith(`::${p}`) || modLower.includes(`_${p}`));
}

function isDfBorrowMut(mod: string, fn: string): boolean {
  return isDfModule(mod) && BORROW_MUT_PATTERNS.some((p) => fn.toLowerCase().includes(p));
}

function isDfRemove(mod: string, fn: string): boolean {
  return isDfModule(mod) && REMOVE_PATTERNS.some((p) => fn.toLowerCase() === p || fn.toLowerCase().startsWith(p));
}

function isDfAdd(mod: string, fn: string): boolean {
  return isDfModule(mod) && ADD_PATTERNS.some((p) => fn.toLowerCase() === p || fn.toLowerCase().startsWith(p));
}

function isPrivilegedNonDf(mod: string, fn: string): boolean {
  if (isDfModule(mod)) return false;
  const fnLower = fn.toLowerCase();
  return PRIVILEGED_PATTERNS.some((p) => fnLower.includes(p));
}

export function detectDynamicFieldAbuseAttacks(ctx: AttackDetectorContext): AttackFinding[] {
  const { tx, derived } = ctx;

  const dfBorrowMutCalls = tx.calls.filter((c) => isDfBorrowMut(c.module, c.function));
  const dfRemoveCalls = tx.calls.filter((c) => isDfRemove(c.module, c.function));
  const dfAddCalls = tx.calls.filter((c) => isDfAdd(c.module, c.function));
  const totalDfOps = dfBorrowMutCalls.length + dfRemoveCalls.length + dfAddCalls.length;

  if (totalDfOps === 0) return [];

  // Pattern 1: borrow_mut + value extraction (outflow detected)
  const isUnauthorizedMutation =
    dfBorrowMutCalls.length >= 1 && derived.valueExtractionDetected;

  // Pattern 2: multiple removes + outflow balance changes
  const hasOutflow = tx.balanceChanges.some((c) => {
    try { return BigInt(c.amount ?? '0') < 0n; } catch { return false; }
  });
  const isDynamicDrain = dfRemoveCalls.length >= REMOVE_THRESHOLD && hasOutflow;

  // Pattern 3: mass field manipulation (add/remove/borrow_mut >= 5)
  const isMassManipulation = totalDfOps >= MASS_OPS_THRESHOLD;

  // Pattern 4: field add immediately combined with privileged calls
  const hasPrivilegedCalls = tx.calls.some((c) => isPrivilegedNonDf(c.module, c.function));
  const isKeyCollision = dfAddCalls.length >= 1 && dfBorrowMutCalls.length >= 1 && hasPrivilegedCalls;

  if (!isUnauthorizedMutation && !isDynamicDrain && !isMassManipulation && !isKeyCollision) {
    return [];
  }

  const patterns: string[] = [];
  if (isUnauthorizedMutation) patterns.push('unauthorized-borrow_mut-with-extraction');
  if (isDynamicDrain) patterns.push(`dynamic-drain (${dfRemoveCalls.length} removes + outflow)`);
  if (isMassManipulation) patterns.push(`mass-field-ops (${totalDfOps} ops)`);
  if (isKeyCollision) patterns.push('field-key-collision-with-privileged-call');

  const highestRisk = isUnauthorizedMutation || isDynamicDrain;
  const scoreDelta = isUnauthorizedMutation ? 40 : isDynamicDrain ? 35 : isMassManipulation ? 30 : 25;

  return [
    {
      attackType: 'dynamic-field-abuse',
      category: 'execution-abuse',
      summary: `检测到动态字段滥用攻击：${patterns.join('、')}，${dfBorrowMutCalls.length} 次 borrow_mut + ${dfRemoveCalls.length} 次 remove 在同一 PTB`,
      evidence: {
        sender: tx.sender,
        dfBorrowMutCount: dfBorrowMutCalls.length,
        dfRemoveCount: dfRemoveCalls.length,
        dfAddCount: dfAddCalls.length,
        totalDfOps,
        isUnauthorizedMutation,
        isDynamicDrain,
        isMassManipulation,
        isKeyCollision,
        hasOutflow,
        valueExtractionDetected: derived.valueExtractionDetected,
        affectedModules: [
          ...new Set([
            ...dfBorrowMutCalls.map((c) => c.module),
            ...dfRemoveCalls.map((c) => c.module),
          ]),
        ],
        patterns,
      },
      riskHints: {
        scoreDelta,
        severityFloor: highestRisk ? 'high' : 'medium',
      },
      chainHints: {
        stage: isUnauthorizedMutation || isDynamicDrain ? 'extraction' : 'manipulation',
      },
    },
  ];
}
