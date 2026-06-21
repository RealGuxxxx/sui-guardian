import { mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { buildMoveFactsForPackage, buildMoveFactsFromCode } from '../src/ai/move-facts.js';

const SAMPLE_SOURCE = `
module 0xdemo::vault {
  // One-time witness
  struct VAULT has copy, drop {}

  // Capability types
  struct AdminCap has key { id: UID }
  struct UpgradeCap has key, store { id: UID }

  // Treasury / vault
  struct Treasury has key, store {
    id: UID,
    balance: u64,
    fee_rate: u64,
  }

  // Event type
  struct WithdrawEvent has copy, drop {
    amount: u64,
    recipient: address,
  }

  // Hot-potato: zero abilities (valid flash loan receipt)
  struct FlashReceipt {
    amount: u64,
    pool_id: ID,
  }

  // Broken hot-potato: has drop ability (critical security flaw)
  struct LoanReceipt has drop {
    amount: u64,
  }

  // Private function with no access control concern
  fun internal_check(): bool { true }

  // Public function with AdminCap param
  public fun set_fee(cap: &AdminCap, rate: u64) {
    assert!(rate < 10000, 0);
  }

  // Public entry function WITHOUT access control — should be flagged
  public entry fun deposit(amount: u64) {}

  // Public(friend) function
  public(friend) fun borrow_flash(): Treasury { abort 0 }

  const MAX_FEE: u64 = 500;
}
`;

describe('buildMoveFactsForPackage', () => {
  it('extracts public entry functions', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'sui-guardian-move-'));
    await writeFile(path.join(dir, 'Move.toml'), `[package]\nname = "Demo"\nversion = "0.0.1"\n`, 'utf8');
    await writeFile(path.join(dir, 'demo.move'), `module demo::m { public entry fun withdraw() {} }`, 'utf8');

    const facts = await buildMoveFactsForPackage('demo', dir);
    expect(facts.label).toBe('demo');
    expect(facts.modules.some((m) => m.functions.some((f) => f.entry && f.name === 'withdraw'))).toBe(true);
  });
});

describe('buildMoveFactsFromCode — enhanced parser', () => {
  it('extracts module address', () => {
    const facts = buildMoveFactsFromCode('test', [{ filename: 'vault.move', content: SAMPLE_SOURCE }]);
    const mod = facts.modules[0]!;
    expect(mod.address).toContain('0xdemo::vault');
  });

  it('detects one-time witness struct', () => {
    const facts = buildMoveFactsFromCode('test', [{ filename: 'vault.move', content: SAMPLE_SOURCE }]);
    expect(facts.modules[0]!.hasOneTimeWitness).toBe(true);
  });

  it('identifies capability structs', () => {
    const facts = buildMoveFactsFromCode('test', [{ filename: 'vault.move', content: SAMPLE_SOURCE }]);
    const structs = facts.modules[0]!.structs;
    const capNames = structs.filter((s) => s.isCapability).map((s) => s.name);
    expect(capNames).toContain('AdminCap');
    expect(capNames).toContain('UpgradeCap');
  });

  it('identifies treasury / fund structs', () => {
    const facts = buildMoveFactsFromCode('test', [{ filename: 'vault.move', content: SAMPLE_SOURCE }]);
    const structs = facts.modules[0]!.structs;
    expect(structs.find((s) => s.name === 'Treasury')?.isTreasury).toBe(true);
  });

  it('identifies event structs', () => {
    const facts = buildMoveFactsFromCode('test', [{ filename: 'vault.move', content: SAMPLE_SOURCE }]);
    const structs = facts.modules[0]!.structs;
    expect(structs.find((s) => s.name === 'WithdrawEvent')?.isEvent).toBe(true);
  });

  it('extracts all function visibilities', () => {
    const facts = buildMoveFactsFromCode('test', [{ filename: 'vault.move', content: SAMPLE_SOURCE }]);
    const fns = facts.modules[0]!.functions;
    expect(fns.find((f) => f.name === 'set_fee')?.visibility).toBe('public');
    expect(fns.find((f) => f.name === 'deposit')?.entry).toBe(true);
    expect(fns.find((f) => f.name === 'borrow_flash')?.visibility).toBe('public_friend');
  });

  it('flags public entry functions without access control', () => {
    const facts = buildMoveFactsFromCode('test', [{ filename: 'vault.move', content: SAMPLE_SOURCE }]);
    const fns = facts.modules[0]!.functions;
    const deposit = fns.find((f) => f.name === 'deposit');
    expect(deposit?.noAccessControl).toBe(true);
  });

  it('does not flag functions with capability params', () => {
    const facts = buildMoveFactsFromCode('test', [{ filename: 'vault.move', content: SAMPLE_SOURCE }]);
    const fns = facts.modules[0]!.functions;
    const setFee = fns.find((f) => f.name === 'set_fee');
    // set_fee has AdminCap param — should not be flagged as no access control
    expect(setFee?.noAccessControl).toBeFalsy();
  });

  it('extracts constants', () => {
    const facts = buildMoveFactsFromCode('test', [{ filename: 'vault.move', content: SAMPLE_SOURCE }]);
    const consts = facts.modules[0]!.constants;
    expect(consts.find((c) => c.name === 'MAX_FEE')).toBeDefined();
  });

  it('extracts struct fields', () => {
    const facts = buildMoveFactsFromCode('test', [{ filename: 'vault.move', content: SAMPLE_SOURCE }]);
    const treasury = facts.modules[0]!.structs.find((s) => s.name === 'Treasury');
    expect(treasury?.fields.some((f) => f.name === 'balance')).toBe(true);
  });

  it('identifies hot-potato structs (zero abilities)', () => {
    const facts = buildMoveFactsFromCode('test', [{ filename: 'vault.move', content: SAMPLE_SOURCE }]);
    const structs = facts.modules[0]!.structs;
    const flashReceipt = structs.find((s) => s.name === 'FlashReceipt');
    expect(flashReceipt?.isHotPotato).toBe(true);
    expect(flashReceipt?.isBrokenHotPotato).toBe(false);
  });

  it('identifies broken hot-potato structs (receipt struct with drop ability)', () => {
    const facts = buildMoveFactsFromCode('test', [{ filename: 'vault.move', content: SAMPLE_SOURCE }]);
    const structs = facts.modules[0]!.structs;
    const loanReceipt = structs.find((s) => s.name === 'LoanReceipt');
    expect(loanReceipt?.isBrokenHotPotato).toBe(true);
  });
});
