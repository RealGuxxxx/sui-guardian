import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';

import YAML from 'yaml';

import { SuiGraphqlClient } from '../graphql-client.js';
import { canonicalizeSuiAddress, nowIso } from '../utils.js';
import { collectWindowStats as collectWindowStatsDefault } from './chain-stats.js';
import { buildMoveFactsForPackage as buildMoveFactsForPackageDefault } from './move-facts.js';
import { callOpenAiJson as callOpenAiJsonDefault } from './openai.js';
import { generatedRulesSchema } from './rule-schema.js';

export interface GenerateRulesParams {
  projectId: string;
  projectName: string;
  generatedDir: string;
  deploymentsPath: string;
  sourceRoot: string;
  graphqlEndpoint: string;
  openai: {
    apiKey: string;
    baseUrl: string;
    model: string;
  };
  providers?: {
    callOpenAiJson?: typeof callOpenAiJsonDefault;
    buildMoveFactsForPackage?: typeof buildMoveFactsForPackageDefault;
    collectWindowStats?: typeof collectWindowStatsDefault;
    getLatestCheckpoint?: (client: SuiGraphqlClient) => Promise<number>;
  };
}

async function atomicWrite(filePath: string, contents: string): Promise<void> {
  const dir = path.dirname(filePath);
  await mkdir(dir, { recursive: true });
  const tmp = `${filePath}.${Date.now()}.tmp`;
  await writeFile(tmp, contents, 'utf8');
  await rename(tmp, filePath);
}

export async function generateProjectRules(params: GenerateRulesParams): Promise<{ version: string; rulesPath: string; metaPath: string }> {
  const deploymentsRaw = await readFile(params.deploymentsPath, 'utf8');
  const deployments = JSON.parse(deploymentsRaw) as {
    projectId?: string;
    network?: string;
    packages?: Array<{ label: string; packageId: string }>;
  };
  const packages = (deployments.packages ?? []).map((pkg) => ({
    label: pkg.label,
    address: canonicalizeSuiAddress(pkg.packageId),
  }));

  const client = new SuiGraphqlClient(params.graphqlEndpoint);
  const callOpenAiJson = params.providers?.callOpenAiJson ?? callOpenAiJsonDefault;
  const buildMoveFactsForPackage = params.providers?.buildMoveFactsForPackage ?? buildMoveFactsForPackageDefault;
  const collectWindowStats = params.providers?.collectWindowStats ?? collectWindowStatsDefault;
  const getLatestCheckpoint = params.providers?.getLatestCheckpoint ?? ((value) => value.getLatestCheckpoint());

  const latestCheckpoint = await getLatestCheckpoint(client);
  const stats7 = await collectWindowStats({ client, latestCheckpoint, windowDays: 7, maxSampledCheckpoints: 500, pageSize: 50 } as any);
  const stats30 = await collectWindowStats({ client, latestCheckpoint, windowDays: 30, maxSampledCheckpoints: 1000, pageSize: 50 } as any);
  const stats90 = await collectWindowStats({ client, latestCheckpoint, windowDays: 90, maxSampledCheckpoints: 1500, pageSize: 50 } as any);

  const moveFacts = await Promise.all(
    (deployments.packages ?? []).map((pkg) => buildMoveFactsForPackage(pkg.label, path.join(params.sourceRoot, pkg.label))),
  );

  const system = [
    'You must return a single JSON object.',
    'Do not output YAML.',
    'Do not invent addresses. Use only addresses present in the deployments payload.',
  ].join('\n');

  const user = JSON.stringify({
    project: {
      projectId: params.projectId,
      projectName: params.projectName,
      network: 'testnet',
      packages,
    },
    deployments,
    moveFacts,
    stats: { stats7, stats30, stats90 },
    policy: { alertPreference: 'neutral_first_week_then_tune' },
    requiredOutputShape: {
      version: nowIso(),
      projectId: params.projectId,
      rules: {},
      explanations: [],
    },
  });

  const json = await callOpenAiJson({
    client: { apiKey: params.openai.apiKey, baseUrl: params.openai.baseUrl, model: params.openai.model },
    system,
    user,
  });

  const payload = generatedRulesSchema.parse(json);
  const version = payload.version;

  const ensuredPackages = payload.rules.packages.length > 0
    ? payload.rules.packages
    : packages.map((pkg) => ({
        label: pkg.label,
        address: pkg.address,
        allowedUpgradeSenders: [],
      }));
  const ensuredRules = {
    ...payload.rules,
    packages: ensuredPackages,
  };

  const projectDir = path.join(params.generatedDir, params.projectId);
  const rulesPath = path.join(projectDir, 'current.yml');
  const metaPath = path.join(projectDir, 'meta', 'current.json');
  const versionedRulesPath = path.join(projectDir, 'versions', `${encodeURIComponent(version)}.yml`);
  const versionedMetaPath = path.join(projectDir, 'meta', 'versions', `${encodeURIComponent(version)}.json`);

  const rulesYaml = YAML.stringify(ensuredRules);
  const metaJson = JSON.stringify({
    version,
    projectId: payload.projectId,
    generatedAt: nowIso(),
    explanations: payload.explanations ?? [],
    checkpoints: {
      latest: latestCheckpoint,
      windows: [
        { days: 7, sampledCheckpoints: (stats7 as any).sampledCheckpoints, sampledTransactions: (stats7 as any).sampledTransactions },
        { days: 30, sampledCheckpoints: (stats30 as any).sampledCheckpoints, sampledTransactions: (stats30 as any).sampledTransactions },
        { days: 90, sampledCheckpoints: (stats90 as any).sampledCheckpoints, sampledTransactions: (stats90 as any).sampledTransactions },
      ],
    },
  }, null, 2);

  await atomicWrite(rulesPath, rulesYaml);
  await atomicWrite(metaPath, metaJson);
  await atomicWrite(versionedRulesPath, rulesYaml);
  await atomicWrite(versionedMetaPath, metaJson);

  return { version, rulesPath, metaPath };
}
