import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { generateProjectRules } from '../src/ai/rule-generator.js';

describe('generateProjectRules', () => {
  it('writes current.yml and meta json using injected providers', async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'sui-guardian-ai-gen-'));
    const sourceRoot = path.join(tempDir, 'source');
    const deploymentsPath = path.join(tempDir, 'deployments.json');
    const generatedDir = path.join(tempDir, 'generated');
    const pkgDir = path.join(sourceRoot, 'demo');

    await mkdir(pkgDir, { recursive: true });
    await writeFile(path.join(pkgDir, 'Move.toml'), `[package]\nname = "Demo"\nversion = "0.0.1"\n`, 'utf8');
    await writeFile(path.join(pkgDir, 'demo.move'), `module demo::m { public entry fun withdraw() {} }`, 'utf8');
    await writeFile(
      deploymentsPath,
      JSON.stringify({ projectId: 'demo', network: 'testnet', packages: [{ label: 'demo', packageId: '0x1' }] }),
      'utf8',
    );

    const result = await generateProjectRules({
      projectId: 'demo',
      projectName: 'Demo',
      generatedDir,
      deploymentsPath,
      sourceRoot,
      graphqlEndpoint: 'https://graphql.testnet.sui.io/graphql',
      openai: { apiKey: 'k', baseUrl: 'https://example.com', model: 'm' },
      providers: {
        callOpenAiJson: async () => ({
          version: 'v1',
          projectId: 'demo',
          rules: {
            functionGuards: [
              {
                label: 'withdraw',
                package: '0x1',
                module: 'vault',
                function: 'withdraw',
                allowedSenders: ['0xabc'],
                severity: 'critical',
              },
            ],
          },
        }),
        collectWindowStats: async ({ windowDays }: { windowDays: number }) => ({
          windowDays,
          sampledCheckpoints: 1,
          sampledTransactions: 1,
          callCounts: {},
        }),
        getLatestCheckpoint: async () => 100,
      },
    });

    expect(result.rulesPath).toContain(path.join(generatedDir, 'demo', 'current.yml'));
    const yaml = await readFile(result.rulesPath, 'utf8');
    expect(yaml).toContain('functionGuards');
    const meta = await readFile(result.metaPath, 'utf8');
    expect(meta).toContain('"version": "v1"');
  });

  it('injects deployment packages when model omits packages', async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), 'sui-guardian-ai-gen-'));
    const sourceRoot = path.join(tempDir, 'source');
    const deploymentsPath = path.join(tempDir, 'deployments.json');
    const generatedDir = path.join(tempDir, 'generated');
    const pkgDir = path.join(sourceRoot, 'demo');

    await mkdir(pkgDir, { recursive: true });
    await writeFile(path.join(pkgDir, 'Move.toml'), `[package]\nname = "Demo"\nversion = "0.0.1"\n`, 'utf8');
    await writeFile(path.join(pkgDir, 'demo.move'), `module demo::m { public entry fun withdraw() {} }`, 'utf8');
    await writeFile(
      deploymentsPath,
      JSON.stringify({ projectId: 'demo', network: 'testnet', packages: [{ label: 'demo', packageId: '0x1' }] }),
      'utf8',
    );

    const result = await generateProjectRules({
      projectId: 'demo',
      projectName: 'Demo',
      generatedDir,
      deploymentsPath,
      sourceRoot,
      graphqlEndpoint: 'https://graphql.testnet.sui.io/graphql',
      openai: { apiKey: 'k', baseUrl: 'https://example.com', model: 'm' },
      providers: {
        callOpenAiJson: async () => ({
          version: 'v1',
          projectId: 'demo',
          rules: {},
        }),
        collectWindowStats: async ({ windowDays }: { windowDays: number }) => ({
          windowDays,
          sampledCheckpoints: 1,
          sampledTransactions: 1,
          callCounts: {},
        }),
        getLatestCheckpoint: async () => 100,
      },
    });

    const yaml = await readFile(result.rulesPath, 'utf8');
    expect(yaml).toContain('packages');
    expect(yaml).toContain('address');
  });
});
