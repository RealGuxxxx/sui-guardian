import YAML from 'yaml';

import { SuiGraphqlClient } from '../graphql-client.js';
import { nowIso } from '../utils.js';
import { collectWindowStats } from './chain-stats.js';
import { buildMoveFactsFromCode } from './move-facts.js';
import type { MovePackageFacts } from './move-facts.js';
import { callOpenAiJson } from './openai.js';
import { generatedRulesSchema } from './rule-schema.js';
import type { GeneratedRulesPayload } from './rule-schema.js';

export interface AnalyzeCodeParams {
  code: Array<{ filename: string; content: string }>;
  packageAddress?: string;
  graphqlEndpoint?: string;
  projectId?: string;
  projectName?: string;
  openai: { apiKey: string; baseUrl: string; model: string };
}

export interface AnalyzeCodeResult {
  rules: GeneratedRulesPayload['rules'];
  configYaml: string;
  explanations: GeneratedRulesPayload['explanations'];
}

export async function analyzeCode(params: AnalyzeCodeParams): Promise<AnalyzeCodeResult> {
  const projectId = params.projectId ?? 'generated';
  const projectName = params.projectName ?? 'Analyzed Project';

  const moveFacts = buildMoveFactsFromCode(projectName, params.code);

  let chainStats: unknown = undefined;
  if (params.graphqlEndpoint) {
    try {
      const client = new SuiGraphqlClient(params.graphqlEndpoint);
      const latestCheckpoint = await client.getLatestCheckpoint();
      chainStats = await collectWindowStats({
        client: client as Parameters<typeof collectWindowStats>[0]['client'],
        latestCheckpoint,
        windowDays: 7,
        maxSampledCheckpoints: 300,
        pageSize: 50,
      });
    } catch {
      // Chain stats are optional — silently skip if unavailable
    }
  }

  const packages = params.packageAddress
    ? [{ label: projectName, address: params.packageAddress }]
    : [];

  const system = buildSecurityAnalysisSystemPrompt();
  const user = buildAnalysisUserPayload({
    projectId,
    projectName,
    packages,
    code: params.code,
    moveFacts,
    chainStats,
  });

  const json = await callOpenAiJson({ client: params.openai, system, user });
  const payload = generatedRulesSchema.parse(json);

  const configYaml = YAML.stringify(payload.rules);

  return {
    rules: payload.rules,
    configYaml,
    explanations: payload.explanations,
  };
}

function buildSecurityAnalysisSystemPrompt(): string {
  return `You are an elite smart contract security analyst specializing in Sui Move contracts and DeFi protocol security.

## Your Mission
Analyze the provided Move source code and generate PRECISE, ACTIONABLE monitoring rules that will detect real attacks in production.

## Sui-Specific Security Knowledge

### Sui Object Model
- Every asset is an object with an owner (address, shared, immutable, or object-owned)
- SHARED objects can be accessed by anyone — focus access-control monitoring here
- AdminCap / OwnerCap / TreasuryCap structs (with \`key\` ability, no \`store\`) are soulbound capabilities
- If a Cap has \`store\`, it can be transferred — this is a HIGH RISK pattern to flag
- \`transfer::public_share_object()\` makes an object accessible to ALL — monitor calls that share previously-owned objects

### Capability Pattern Risks
- Functions taking \`&mut AdminCap\` or \`&AdminCap\` are privileged — guard them
- One-time witness (OTW) structs (same name as module, ALLCAPS) should only be created once during \`init()\`
- If UpgradeCap / UpgradePolicy is transferable, a stolen cap = protocol takeover
- Watch for \`capability_access()\` calls from unexpected senders

### Flash Loan / Hot Potato Patterns
- Sui flash loans use "hot potato" objects — structs with no \`copy\` or \`drop\` abilities that MUST be returned
- Pattern: \`borrow()\` returns (Asset, Receipt) → Receipt has no drop → must call \`repay(receipt)\` in same PTB
- Attack: manipulate price oracle BETWEEN borrow and repay in the same programmable transaction block (PTB)
- Monitor: large outflow from pool followed immediately by repay in the same transaction

### Oracle / Price Feed Risks
- Move oracle fields are often stored as u64 in shared objects
- Common attack: flash-loan → swap to move price → borrow using manipulated price → repay
- Red flags in code: functions that update a price field WITHOUT requiring multiple signers or time delay
- Watch for: price updates from a single sender, no TWAP, no deviation check on the oracle writer side

### Package Upgrade Risks
- \`sui::package::authorize_upgrade()\` + \`sui::package::commit_upgrade()\` sequence = upgrade happening
- If UpgradeCap is NOT frozen (not called \`make_immutable()\`), upgrades are possible
- CRITICAL: Package upgrade in same checkpoint as large fund movement = likely rug pull
- Monitor: any upgrade event, check if followed within 10 checkpoints by significant outflow

### Dynamic Field Attacks
- \`dynamic_field::add/remove/borrow_mut\` on shared objects without proper access control
- Attacker can manipulate internal accounting stored in dynamic fields
- Watch: unexpected removal of dynamic fields from treasury/pool objects

### Governance Attacks
- Multi-sig proposals that get fast-tracked (time delay bypassed)
- Quorum collapse: governance parameter changed so 1 person can pass proposals
- Vote concentration: one address acquires majority voting power then passes malicious proposal

### Real Sui Mainnet Exploits (Reference for Rule Generation)

**Cetus Protocol ($223M, May 2025) — CLMM Integer Overflow:**
- Bug: checked_shlw in integer-mate library — overflow guard used wrong mask (0xffffffffffffffff << 192 instead of 1 << 192) and > instead of >=
- Move bit-shifts (<<) do NOT abort on overflow — they silently truncate (unlike +, * which abort)
- Attack: flash_swap → add_liquidity with tiny tick range + crafted liquidity ≈ 2^113 → overflow makes 1 token mint enormous liquidity → remove_liquidity drains real funds → repay
- Scale: 200+ pools hit in a single PTB batch, $62M bridged via Wormhole before validators froze $162M
- **Detection rule**: flash borrow + add_liquidity + remove_liquidity in same PTB is the highest-confidence signal

**Scallop Lending ($142K, April 2026) — Deprecated Contract + Uninitialized State:**
- Attacker called old V2 rewards contract (still callable — Sui immutability means all versions stay live)
- last_index field uninitialized on new accounts (defaults to 0 in Move structs)
- New account claims rewards as if staking since pool inception: owed = (current_index - 0) * balance
- **Detection rule**: calls to non-current (older version) package IDs of known protocols

**Pawtato Finance (January 2026) — Unvalidated UpgradeCap Capability Gate:**
- create_new_admin_cap(upgrade_cap: UpgradeCap) accepted ANY UpgradeCap without validating which package
- Attacker deployed cheap contract, got its UpgradeCap for cents, passed it to victim's create_new_admin_cap
- Bytecode indicator: function accepts UpgradeCap param but never reads it (no MoveLoc/CopyLoc/ImmBorRef)
- **Detection rule**: create_admin / grant_admin / new_admin_cap functions that take a Cap parameter

**Cetus Spoof Token Setup (May 2025) — Worthless Token Pool Injection:**
- Before main exploit, attacker published worthless BULLA/MOJO tokens then immediately added them as pool counterparts
- New package published + add_liquidity in same PTB = pre-attack setup
- **Detection rule**: new package publish + pool create/inject in same PTB

**Typus Finance ($3.4M, October 2025) — Custom Oracle Missing Authorization:**
- Protocol used a custom on-chain oracle without standard Pyth/Switchboard staleness checks
- The oracle update function lacked BOTH: (1) multi-signer authorization and (2) \`assert!\` rate-of-change bounds
- Attacker manipulated the oracle price directly, bypassing price feeds
- Bytecode indicator: oracle write function with no \`assert!\` calls and no multi-sig check
- **Detection rule**: oracle update functions callable by single senders; price fields updated with no deviation bound

**Nemo Protocol ($2.4M, September 2025) — PT/YT Oracle Imbalance Pricing:**
- Nemo is a yield tokenization protocol issuing Principal Tokens (PT) and Yield Tokens (YT)
- The PT/YT pricing oracle used a spot AMM price rather than a time-weighted or anchored price
- Attacker used a flash loan to imbalance the PT/YT pool, manipulating the oracle, then borrowed at false prices
- High-risk pattern: yield-bearing token protocols that price PT/YT using live pool reserves
- **Detection rule**: flash loan activity + PT/YT oracle pricing function in same TX window

**Aftermath Finance Perpetuals ($1.14M, April 2026) — Negative Fee Parameter Abuse:**
- Permissionless integrator registration (costs cents in gas), then fee is set via \`set_taker_fee()\`
- Attacker set taker fee to -100,000 bps (negative u64 overflow) — protocol treated the "fee" as collateral credit
- The accounting logic: \`collateral += fee_owed\` where fee_owed was negative → inflated virtual collateral
- Withdrew real USDC against the inflated "collateral" — 11 transactions over 36 minutes, $1.14M total
- High-risk pattern: fee parameters stored as i64 or interpreted as signed, no bounds validation
- **Detection rule**: \`set_taker_fee\` / \`set_integrator_fee\` with extreme values, followed by withdrawal/borrow

**Volo Protocol ($3.5M, April 2026) — Admin Key Compromise + Multi-Vault Rapid Drain:**
- Compromised admin private key gave attacker full access to ALL vault withdrawal functions
- Script ran automatically: WBTC vault → XAUm vault → USDC vault in sequential transactions within minutes
- Classic admin-key compromise pattern: same sender, multiple privileged calls, multiple assets drained rapidly
- High-risk pattern: single admin key controls multiple treasury vaults with no time-lock or multi-sig
- **Detection rule**: same sender hits 3+ protected vault addresses with emergency_withdraw/drain in minutes

### Common Sui DeFi Attack Vectors
1. **CLMM Integer Overflow + Flash Loan**: flash borrow → add_liquidity (tiny tick range, crafted liquidity) → u256 bit-shift overflow → remove_liquidity drains real funds → repay
2. **Oracle Manipulation + Flash Loan**: Borrow → drain liquidity → manipulate price → borrow over-collateralized → repay
3. **Upgrade + Drain**: Upgrade package to add backdoor → immediately drain treasury
4. **Capability Theft / Admin Key Compromise**: Admin key compromise → unauthorized upgrade/withdrawal → rapid multi-vault drain script
5. **Unvalidated Cap Gate**: Accept any UpgradeCap/AdminCap without verifying it belongs to the right package
6. **Deprecated Contract Exploit**: Call older (pre-upgrade) package version with uninitialized state
7. **Reentrancy via PTB**: Chain of calls in single PTB that re-enters a pool before accounting is updated
8. **Slippage Abuse**: Set minAmountOut=0 on swap functions that allow it
9. **Liquidity Drain**: Remove all liquidity before users can react (rug pull)
10. **Bridge Burst Drain**: Post-exploit, rapidly bridge funds cross-chain at $1M/30s via Wormhole/CCTP
11. **Negative Fee Parameter Abuse**: Set integrator fee to extreme negative value to create fake collateral credit (Aftermath Finance pattern)
12. **Custom Oracle Manipulation**: Unguarded oracle update function → direct price manipulation without flash loan (Typus Finance pattern)
13. **PT/YT AMM Imbalance**: Flash loan → imbalance yield-token pool → oracle reads manipulated spot price → overborrow (Nemo Finance pattern)

## Rule Generation Guidelines

### functionGuards — Guard These Function Patterns:
- Any function with \`Cap\` in parameters (admin ops)
- Functions named: withdraw, emergency_withdraw, drain, pause, unpause, upgrade, migrate, set_owner, set_admin, set_fee
- Functions that call transfer::transfer on large-value objects
- Functions that modify shared-object fields without time locks

### trackedObjects — Track These Object Types:
- Treasury, Vault, Pool, Reserve, Bag (contain user funds)
- Global state objects with balance/supply fields
- Oracle price feed objects (price, last_update_time fields)

### objectBaselines — Monitor These Field Changes:
- Balance/reserve fields: kind=inventory (alert on unexpected decrease)
- Admin/owner address fields: kind=permission (alert on change)
- Price/rate fields: kind=price (alert on large deviation)
- Pause/emergency/enabled bool fields: kind=state (alert on flip)

### protectedAddresses — Protect These Addresses:
- Treasury addresses (match Treasury/Vault/Pool struct holders)
- Protocol fee recipients
- Multi-sig admin addresses if identifiable

### behaviorRules:
- Set priceDeviationThresholdBps to 500 (5%) for DeFi protocols, 1000 (10%) for lower-risk
- Set minRepeatedCalls to 3 for most protocols (reduce false positives)

### trafficSpikes / failureSpikes:
- Add traffic spike detection: windowSeconds=300, txCountThreshold=50
- Add failure spike: windowSeconds=60, failedTxThreshold=10

### CLMM / DEX Protocol Specific Guards:
- If the contract has CLMM functions (add_liquidity, open_position, mint_position), guard them with a functionGuard
- If there are flash loan functions (borrow, flash_swap, take_flash_loan), create a functionGuard for them
- For flash loan receipt structs: if they have any abilities (especially drop), flag this in explanations as critical
- If a math library is used for fixed-point arithmetic, mention the Cetus integer-overflow pattern in explanations

### Capability Validation Guards:
- Any function that takes an UpgradeCap, AdminCap, or OwnerCap parameter should be in functionGuards
- If the function body does NOT validate which package/object the cap comes from, set severity to "critical"
- Check if Cap structs have store ability — if yes, they can be transferred by any module (HIGH RISK)

### Deprecated Contract Risk:
- If the contract shows version-related patterns (v1, v2, old, legacy in module names), note the deprecated contract risk
- Contracts with reward/staking functions and last_index/last_epoch fields should be flagged for uninitialized state risk

### Fee Parameter Abuse Risk (Aftermath Finance Pattern):
- Any function named set_taker_fee, set_maker_fee, set_integrator_fee, set_fee_bps, configure_fee, update_fee_rate
- If fee parameters are u64 but semantically represent signed values (rebates, negative fees), flag as CRITICAL
- Look for arithmetic like \`collateral += fee\` or \`balance = balance + fee_amount\` — if fee can be negative (overflow), this is exploitable
- Recommend: add functionGuard for all fee-setting functions + objectBaseline on fee-related fields

### Admin Key / Multi-Vault Risk (Volo Protocol Pattern):
- If the code controls multiple distinct vaults/treasuries/reserves accessible via a single AdminCap:
  → Create protectedAddresses for each vault
  → Create functionGuards for all withdrawal functions (emergency_withdraw, drain, migrate, transfer_all)
  → Recommend multi-sig or timelock for withdrawal functions in explanations
- Pattern of concern: admin function that iterates over or accepts an array of vault addresses in one call

### Custom Oracle Authorization Risk (Typus Finance Pattern):
- Oracle update functions that lack \`assert!\` bounds checks are HIGH RISK
- Single-sender oracle updates (no multi-sig requirement) should be flagged
- Look for: functions writing to price/rate/index fields with no deviation validation
- Recommend: objectBaseline on oracle price fields with kind=price + low deviation threshold (200 bps)

### PT/YT Yield Token AMM Risk (Nemo Finance Pattern):
- Protocols issuing Principal Tokens (PT) or Yield Tokens (YT) with AMM-based pricing are vulnerable
- If the code prices PT/YT using live pool reserves (spot price), add trafficSpike detection
- Flash loan + PT/YT pool operations in same PTB = high-confidence attack signal
- Recommend: functionGuard on any oracle_price_update or get_price function that reads pool reserves directly

## Critical Rules
1. Do NOT invent addresses. Only use addresses explicitly provided in the \`project.packages\` input.
2. If no package address is provided, set packages to [].
3. For functionGuards: package/module/function must match EXACTLY what you see in the source code.
4. Return ONLY a valid JSON object. No YAML, no markdown, no explanation text outside JSON.
5. Generate at least one explanation per non-trivial rule you create, explaining WHY it matters.
6. Be specific — generic rules are useless. A rule for "withdraw" should name the exact module and function.`;
}

function buildAnalysisUserPayload(params: {
  projectId: string;
  projectName: string;
  packages: Array<{ label: string; address: string }>;
  code: Array<{ filename: string; content: string }>;
  moveFacts: MovePackageFacts;
  chainStats?: unknown;
}): string {
  // Build a security-focused summary from moveFacts for the AI
  const securitySummary = summarizeSecurityRelevantFacts(params.moveFacts);

  return JSON.stringify({
    task: 'sui_security_rule_generation',
    project: {
      projectId: params.projectId,
      projectName: params.projectName,
      network: 'mainnet',
      packages: params.packages,
    },
    // Full source code for deep analysis
    moveCode: params.code.map(({ filename, content }) => ({ filename, source: content })),
    // Structured facts extracted from source (pre-computed for the AI)
    moveFacts: params.moveFacts,
    // Security-relevant highlights (help the AI focus)
    securityHighlights: securitySummary,
    ...(params.chainStats ? { chainStats: params.chainStats } : {}),
    requiredOutputShape: {
      version: nowIso(),
      projectId: params.projectId,
      rules: {
        packages: [
          {
            '_comment': 'IMPORTANT: Only use addresses from project.packages input. If no address was provided, leave packages as []. Never invent addresses.',
            label: 'Protocol V3 (current)',
            address: '<USE THE ADDRESS FROM project.packages — do NOT invent one>',
            allowedUpgradeSenders: ['<official deployer address if identifiable>'],
            deprecatedAddresses: [
              '<older version package addresses if visible in code (e.g., version constants, migration functions)>',
              'These trigger high-severity alerts when called (Scallop deprecated-contract attack pattern)',
            ],
          },
        ],
        protectedAddresses: [],
        functionGuards: [],
        trafficSpikes: [],
        failureSpikes: [],
        trackedObjects: [],
        suspiciousTargets: [],
        behaviorRules: { enabled: true, minRepeatedCalls: 3, minProtectedOutflow: '1000000', priceDeviationThresholdBps: 500 },
        priceModels: [],
        objectBaselines: [],
        flowTracking: { enabled: true, minProtectedOutflow: '1000000', attackerGainThreshold: '100000', shortWindowTxCount: 3 },
        suppression: { enabled: true, duplicateWindowSeconds: 600, weakSignalScoreThreshold: 30, maintenanceWindows: [] },
      },
      explanations: [
        {
          ruleId: 'example-rule-id',
          summary: 'Explain why this rule is important for security',
          staticEvidence: ['List code patterns that justify this rule'],
          dynamicEvidence: ['List on-chain signals that would confirm an attack'],
          confidence: 0.85,
          recommendedSeverity: 'high',
        },
      ],
    },
  });
}

/** Build a concise security-relevant summary from parsed Move facts. */
function summarizeSecurityRelevantFacts(facts: MovePackageFacts): Record<string, unknown> {
  const capabilityTypes: string[] = [];
  const treasuryTypes: string[] = [];
  const eventTypes: string[] = [];
  const unguardedPublicEntryFns: Array<{ module: string; function: string }> = [];
  const adminFunctions: Array<{ module: string; function: string; params: string[] }> = [];
  const flashLoanFunctions: Array<{ module: string; function: string }> = [];
  const clmmFunctions: Array<{ module: string; function: string }> = [];
  const capGateFunctions: Array<{ module: string; function: string; params: string[] }> = [];
  const hotPotatoStructs: string[] = [];
  const brokenHotPotatoStructs: string[] = [];
  const feeSettingFunctions: Array<{ module: string; function: string }> = [];
  const oracleUpdateFunctions: Array<{ module: string; function: string }> = [];
  const yieldTokenFunctions: Array<{ module: string; function: string }> = [];
  const riskFlags: string[] = [];
  let hasOneTimeWitness = false;
  let multiVaultCount = 0;

  const versionedModules: string[] = [];

  for (const mod of facts.modules) {
    if (mod.hasOneTimeWitness) hasOneTimeWitness = true;

    // Versioned module name → deprecated contract risk (Scallop pattern)
    if (mod.isVersioned) {
      versionedModules.push(mod.name);
    }

    for (const struct of mod.structs) {
      if (struct.isCapability) capabilityTypes.push(`${mod.name}::${struct.name}`);
      if (struct.isTreasury) {
        treasuryTypes.push(`${mod.name}::${struct.name}`);
        multiVaultCount++;
      }
      if (struct.isEvent) eventTypes.push(`${mod.name}::${struct.name}`);

      // Hot-potato: struct with no abilities — used in flash loan receipts (correct, secure)
      if (struct.isHotPotato) {
        hotPotatoStructs.push(`${mod.name}::${struct.name}`);
      }

      // Broken hot-potato: receipt-like struct that HAS the drop ability — can be discarded without repaying (CRITICAL)
      if (struct.isBrokenHotPotato) {
        brokenHotPotatoStructs.push(`${mod.name}::${struct.name}`);
      }

      // Uninitialized reward index (Scallop attack pattern)
      const rewardIndexFields = struct.fields.filter((f) =>
        /last_index|last_epoch|last_claim|reward_index|accrued_index/.test(f.name.toLowerCase()),
      );
      if (rewardIndexFields.length > 0) {
        riskFlags.push(
          `CRITICAL: Struct ${mod.name}::${struct.name} has reward index field(s) (${rewardIndexFields.map((f) => f.name).join(', ')}) — verify initialized on account creation (Scallop hack: defaulted to 0)`,
        );
      }
    }

    for (const fn of mod.functions) {
      if (fn.noAccessControl && fn.entry) {
        unguardedPublicEntryFns.push({ module: mod.name, function: fn.name });
      }

      const fnLower = fn.name.toLowerCase();
      const hasAdminName = /withdraw|drain|pause|upgrade|migrate|set_|admin|emergency|owner/.test(fnLower);
      if (fn.visibility !== 'private' && (hasAdminName || fn.paramTypes?.some((t) => /Cap$|Admin|Owner|Auth/.test(t)))) {
        adminFunctions.push({ module: mod.name, function: fn.name, params: fn.paramTypes ?? [] });
      }

      // Flash loan pattern detection (Cetus attack vector)
      if (/flash|borrow.*loan|hot.*potato|take.*loan|flash.*swap/.test(fnLower)) {
        flashLoanFunctions.push({ module: mod.name, function: fn.name });
      }

      // CLMM pattern detection (Cetus attack target)
      if (/add_liquidity|remove_liquidity|open_position|close_position|mint_position|burn_position|tick|sqrt_price/.test(fnLower)) {
        clmmFunctions.push({ module: mod.name, function: fn.name });
      }

      // UpgradeCap/AdminCap gate functions — Pawtato attack pattern
      if (
        fn.paramTypes?.some((t) => /UpgradeCap|AdminCap|OwnerCap/.test(t)) &&
        !/authorize_upgrade|commit_upgrade|make_immutable|restrict/.test(fnLower)
      ) {
        capGateFunctions.push({ module: mod.name, function: fn.name, params: fn.paramTypes ?? [] });
      }

      // Fee-setting functions — Aftermath Finance attack pattern
      if (/set_taker_fee|set_maker_fee|set_fee_rate|update_fee_rate|set_rebate|set_builder_fee|set_integrator_fee|update_fee|set_protocol_fee|configure_fee|set_fee_bps|update_taker_fee|register_and_set_fee/.test(fnLower)) {
        feeSettingFunctions.push({ module: mod.name, function: fn.name });
      }

      // Oracle update functions without authorization — Typus Finance attack pattern
      if (/update_price|set_price|write_price|oracle_update|update_oracle|feed_price|push_price|update_rate|set_rate/.test(fnLower)) {
        oracleUpdateFunctions.push({ module: mod.name, function: fn.name });
      }

      // Yield token / PT-YT functions — Nemo Finance attack pattern
      if (/mint_pt|burn_pt|mint_yt|burn_yt|yield_token|principal_token|get_pt_price|get_yt_price|pt_rate|yt_rate/.test(fnLower)) {
        yieldTokenFunctions.push({ module: mod.name, function: fn.name });
      }
    }

    // Detect public(package) entry functions misused as access control
    const publicPackageEntryFns = mod.functions.filter(
      (fn) => fn.visibility === 'public_friend' && fn.entry,
    );
    if (publicPackageEntryFns.length > 0) {
      riskFlags.push(
        `WARNING: ${publicPackageEntryFns.length} public(package) entry function(s) in ${mod.name} — public(package) does NOT restrict PTB callers (anyone can call these from a PTB)`,
      );
    }
  }

  // Aggregate risk flags from collected data
  if (unguardedPublicEntryFns.length > 0) {
    riskFlags.push(`${unguardedPublicEntryFns.length} public entry function(s) have no assert!/abort access control`);
  }
  if (treasuryTypes.length > 0) {
    riskFlags.push(`Found ${treasuryTypes.length} treasury/vault struct(s): ${treasuryTypes.join(', ')}`);
  }
  if (capabilityTypes.length > 0) {
    riskFlags.push(`Found ${capabilityTypes.length} capability type(s): ${capabilityTypes.join(', ')}`);
  }
  if (flashLoanFunctions.length > 0) {
    riskFlags.push(`CRITICAL: Flash loan functions detected (${flashLoanFunctions.map((f) => f.function).join(', ')}) — monitor for Cetus-style CLMM overflow attack`);
  }
  if (clmmFunctions.length > 0) {
    riskFlags.push(`CLMM liquidity functions detected — check for integer overflow in fixed-point math and bit-shift operations`);
  }
  if (capGateFunctions.length > 0) {
    riskFlags.push(`HIGH RISK: ${capGateFunctions.length} function(s) accept UpgradeCap/AdminCap but are not standard upgrade lifecycle functions (Pawtato attack pattern)`);
  }
  if (hotPotatoStructs.length > 0) {
    riskFlags.push(`Hot-potato struct(s) detected (${hotPotatoStructs.join(', ')}) — these MUST have zero abilities to be secure flash loan receipts`);
  }
  if (brokenHotPotatoStructs.length > 0) {
    riskFlags.push(`CRITICAL: Broken hot-potato struct(s) detected (${brokenHotPotatoStructs.join(', ')}) — receipt-like struct has the 'drop' ability, meaning it can be discarded without repaying the flash loan`);
  }

  // Aftermath Finance pattern: fee-setting functions
  if (feeSettingFunctions.length > 0) {
    riskFlags.push(
      `HIGH RISK: Fee-setting function(s) detected (${feeSettingFunctions.map((f) => f.function).join(', ')}) — guard against negative/extreme fee parameter abuse (Aftermath Finance $1.14M attack: set taker fee to -100,000 bps as u64 overflow)`,
    );
  }

  // Typus Finance pattern: oracle update functions
  if (oracleUpdateFunctions.length > 0) {
    riskFlags.push(
      `HIGH RISK: Oracle update function(s) detected (${oracleUpdateFunctions.map((f) => f.function).join(', ')}) — verify each has authorization checks AND price deviation bounds; single-sender oracle updates are exploitable (Typus Finance $3.4M: no assert!, no multi-sig)`,
    );
  }

  // Nemo Finance pattern: yield token functions
  if (yieldTokenFunctions.length > 0) {
    riskFlags.push(
      `MEDIUM RISK: Yield token (PT/YT) function(s) detected (${yieldTokenFunctions.map((f) => f.function).join(', ')}) — verify PT/YT pricing uses TWAP not spot price; flash loan imbalance can manipulate AMM-based oracle (Nemo Finance $2.4M)`,
    );
  }

  // Versioned modules → deprecated contract risk
  if (versionedModules.length > 0) {
    riskFlags.push(
      `MEDIUM RISK: Versioned module name(s) detected (${versionedModules.join(', ')}) — if older package versions are still deployed on-chain, attackers can call them with uninitialized state (Scallop $142K pattern: uninitialized last_index on deprecated contract)`,
    );
  }

  // Volo Protocol pattern: multiple treasury/vault structs under one admin
  if (multiVaultCount >= 3) {
    riskFlags.push(
      `HIGH RISK: ${multiVaultCount} distinct treasury/vault struct(s) detected — if controlled by a single AdminCap, a compromised key drains ALL vaults; recommend multi-sig or per-vault timelocks (Volo Protocol $3.5M: single key compromise drained WBTC + XAUm + USDC vaults)`,
    );
  }

  return {
    capabilityTypes,
    treasuryTypes,
    eventTypes,
    hasOneTimeWitness,
    unguardedPublicEntryFunctions: unguardedPublicEntryFns,
    adminOrPrivilegedFunctions: adminFunctions,
    flashLoanFunctions,
    clmmFunctions,
    capGateFunctions,
    hotPotatoStructs,
    brokenHotPotatoStructs,
    feeSettingFunctions,
    oracleUpdateFunctions,
    yieldTokenFunctions,
    multiVaultCount,
    versionedModules,
    riskFlags,
  };
}
