import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';

export type FunctionVisibility = 'public' | 'public_friend' | 'private';

export interface MoveFunctionFact {
  module: string;
  name: string;
  visibility: FunctionVisibility;
  entry: boolean;
  /** True if function has no access control (no assert!/abort/require pattern) */
  noAccessControl?: boolean;
  /** Parameter type names (helps identify capability parameters) */
  paramTypes?: string[];
}

export interface MoveStructFact {
  module: string;
  name: string;
  abilities: string[];           // key, store, copy, drop
  isCapability: boolean;         // name ends in Cap, or has key but not store
  isTreasury: boolean;           // name contains Treasury, Vault, Pool, Bag, Balance
  isEvent: boolean;              // has copy + drop but no key/store (event pattern)
  isHotPotato: boolean;          // zero abilities — must be consumed in same PTB (flash loan receipt)
  isBrokenHotPotato: boolean;    // has drop ability but name suggests receipt/hot potato (critical: can be discarded)
  fields: Array<{ name: string; type: string }>;
}

export interface MoveModuleFact {
  name: string;
  address?: string;              // module address::name
  functions: MoveFunctionFact[];
  structs: MoveStructFact[];
  hasOneTimeWitness: boolean;    // module has OTW struct (same name as module, all caps)
  /** True if module name contains v1/v2/old/legacy — indicates deprecated contract risk */
  isVersioned: boolean;
  constants: Array<{ name: string; type: string; value?: string }>;
}

export interface MovePackageFacts {
  label: string;
  moveTomlPath: string;
  modules: MoveModuleFact[];
}

async function listMoveFiles(root: string): Promise<string[]> {
  const entries = await readdir(root, { withFileTypes: true });
  const results: string[] = [];
  for (const entry of entries) {
    const next = path.join(root, entry.name);
    if (entry.isDirectory()) {
      results.push(...await listMoveFiles(next));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith('.move')) {
      results.push(next);
    }
  }
  return results;
}

function inferModuleName(filePath: string): string {
  const base = path.basename(filePath);
  return base.endsWith('.move') ? base.slice(0, -5) : base;
}

/** Strip line comments and block comments to simplify subsequent parsing */
function stripComments(source: string): string {
  // Block comments
  let s = source.replace(/\/\*[\s\S]*?\*\//g, ' ');
  // Line comments
  s = s.replace(/\/\/[^\n]*/g, '');
  return s;
}

function extractModuleAddress(source: string): string | undefined {
  const m = source.match(/\bmodule\s+([a-zA-Z0-9_:]+)\s*\{/);
  return m ? m[1] : undefined;
}

function extractStructFacts(source: string, moduleName: string): MoveStructFact[] {
  const results: MoveStructFact[] = [];
  // Match struct declarations with ability lists
  const structRegex = /\bstruct\s+([A-Za-z0-9_]+)\s*(?:has\s+([a-z,\s]+))?\s*\{([^}]*)\}/g;
  let m: RegExpExecArray | null;

  while ((m = structRegex.exec(source)) !== null) {
    const name = m[1] ?? '';
    const abilitiesRaw = (m[2] ?? '').trim();
    const fieldsRaw = m[3] ?? '';

    const abilities = abilitiesRaw
      .split(',')
      .map((a) => a.trim())
      .filter((a) => a.length > 0);

    const hasKey = abilities.includes('key');
    const hasStore = abilities.includes('store');
    const hasCopy = abilities.includes('copy');
    const hasDrop = abilities.includes('drop');

    // Capability: ends in Cap, or has key but no store (soulbound), or name contains Auth/Owner/Admin/Manager
    const isCapability =
      /Cap$/.test(name) ||
      /Admin|Owner|Authority|Manager|Operator|Governor|Upgrader/.test(name) ||
      (hasKey && !hasStore);

    // Treasury / vault / pool: holds funds
    const isTreasury = /Treasury|Vault|Pool|Reserve|Balance|Bag|Escrow|Locker|Safe|Fund/.test(name);

    // Event: copy + drop, no key
    const isEvent = hasCopy && hasDrop && !hasKey;

    // Hot-potato: zero abilities (must be returned in same PTB — flash loan receipt pattern)
    const isHotPotato = abilities.length === 0;

    // Broken hot-potato: has drop but name suggests it's a receipt (critical security flaw)
    const looksLikeReceipt = /Receipt|Ticket|Loan|Flash|Borrow|Debt|Obligation/.test(name);
    const isBrokenHotPotato = hasDrop && looksLikeReceipt && !isEvent;

    // Parse fields
    const fields: Array<{ name: string; type: string }> = [];
    const fieldRegex = /([a-zA-Z0-9_]+)\s*:\s*([^,\n]+)/g;
    let fm: RegExpExecArray | null;
    while ((fm = fieldRegex.exec(fieldsRaw)) !== null) {
      const fieldName = fm[1]?.trim() ?? '';
      const fieldType = fm[2]?.trim().replace(/,$/, '') ?? '';
      if (fieldName && fieldName !== 'has' && fieldType) {
        fields.push({ name: fieldName, type: fieldType });
      }
    }

    if (name) {
      results.push({ module: moduleName, name, abilities, isCapability, isTreasury, isEvent, isHotPotato, isBrokenHotPotato, fields });
    }
  }

  return results;
}

/** Extract the brace-delimited body of a function starting from `offset` (after the signature). */
function extractFunctionBody(source: string, offset: number): string {
  let i = offset;
  // Skip to the opening brace (could be a return type annotation before it)
  while (i < source.length && source[i] !== '{' && source[i] !== ';') i++;
  if (i >= source.length || source[i] === ';') return '';
  let depth = 0;
  const start = i;
  while (i < source.length) {
    if (source[i] === '{') depth++;
    else if (source[i] === '}') {
      depth--;
      if (depth === 0) return source.slice(start, i + 1);
    }
    i++;
  }
  return source.slice(start);
}

function extractFunctionFacts(source: string, moduleName: string): MoveFunctionFact[] {
  const results: MoveFunctionFact[] = [];

  // Match all function signatures: optional visibility + optional entry + fun name(params)
  // Covers: fun, public fun, public entry fun, public(friend) fun, public(package) fun, entry fun
  const funcRegex = /\b(public\s*(?:\(\s*(?:friend|package)\s*\)\s*)?|entry\s+)?(entry\s+)?fun\s+([a-zA-Z0-9_]+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)/g;
  let m: RegExpExecArray | null;

  while ((m = funcRegex.exec(source)) !== null) {
    const vis1 = (m[1] ?? '').trim();
    const isEntry2 = Boolean(m[2]);
    const name = m[3] ?? '';
    const paramsRaw = m[4] ?? '';

    if (!name) continue;

    // Determine visibility
    let visibility: FunctionVisibility = 'private';
    let entry = isEntry2;

    if (vis1.startsWith('public')) {
      if (vis1.includes('friend') || vis1.includes('package')) {
        // public(friend) and public(package) are equivalent — package-internal only
        visibility = 'public_friend';
      } else {
        visibility = 'public';
      }
    }
    if (vis1.includes('entry') || vis1 === 'entry') {
      entry = true;
    }

    // Extract parameter types (useful for identifying capability parameters)
    const paramTypes: string[] = [];
    const paramParts = paramsRaw.split(',');
    for (const part of paramParts) {
      const colonIdx = part.indexOf(':');
      if (colonIdx >= 0) {
        const typeStr = part.slice(colonIdx + 1).trim().replace(/&mut\s+|&\s*/g, '').trim();
        if (typeStr) paramTypes.push(typeStr);
      }
    }

    // Extract this function's body to check for access-control patterns
    const body = extractFunctionBody(source, m.index + m[0].length);
    const noAccessControl =
      visibility !== 'private' &&
      !body.includes('assert!') &&
      !body.includes('abort') &&
      !paramTypes.some((t) => /Cap$|AdminCap|OwnerCap|Auth|Witness/.test(t));

    results.push({ module: moduleName, name, visibility, entry, noAccessControl, paramTypes });
  }

  return results.filter((f) => f.name.length > 0);
}

function extractConstants(source: string): Array<{ name: string; type: string; value?: string }> {
  const results: Array<{ name: string; type: string; value?: string }> = [];
  const constRegex = /\bconst\s+([A-Z_][A-Z0-9_]*)\s*:\s*([a-zA-Z0-9_:]+)\s*=\s*([^;]+);/g;
  let m: RegExpExecArray | null;
  while ((m = constRegex.exec(source)) !== null) {
    results.push({ name: m[1] ?? '', type: m[2] ?? '', value: m[3]?.trim() });
  }
  return results;
}

function parseModuleFacts(source: string, filename: string): MoveModuleFact {
  const stripped = stripComments(source);
  const moduleName = inferModuleName(filename);
  const address = extractModuleAddress(stripped);

  const structs = extractStructFacts(stripped, moduleName);
  const functions = extractFunctionFacts(stripped, moduleName);
  const constants = extractConstants(stripped);

  // One-time witness: a struct with same name as module in ALL_CAPS that has copy+drop
  const moduleNameUpper = moduleName.toUpperCase();
  const hasOneTimeWitness = structs.some(
    (s) => s.name === moduleNameUpper && s.abilities.includes('copy') && s.abilities.includes('drop'),
  );

  // Versioned module: name contains v1/v2/old/legacy — indicates deprecated contract risk (Scallop pattern)
  const isVersioned = /[_-]?v\d+$|[_-]?v\d+[_-]|_old$|_legacy$|_deprecated$/.test(moduleName.toLowerCase());

  return { name: moduleName, address, functions, structs, constants, hasOneTimeWitness, isVersioned };
}

export async function buildMoveFactsForPackage(label: string, packageDir: string): Promise<MovePackageFacts> {
  const moveTomlPath = path.join(packageDir, 'Move.toml');
  const files = await listMoveFiles(packageDir);
  const modules: MoveModuleFact[] = [];
  for (const file of files) {
    const src = await readFile(file, 'utf8');
    modules.push(parseModuleFacts(src, file));
  }
  return { label, moveTomlPath, modules };
}

export function buildMoveFactsFromCode(
  label: string,
  files: Array<{ filename: string; content: string }>,
): MovePackageFacts {
  const modules = files.map(({ filename, content }) => parseModuleFacts(content, filename));
  return { label, moveTomlPath: '', modules };
}
