import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { generateProjectRules } from './rule-generator.js';

function getArgValue(argv: string[], flag: string): string | undefined {
  const index = argv.indexOf(flag);
  if (index === -1) {
    return undefined;
  }
  return argv[index + 1];
}

export async function runGenerateCli(params: { argv: string[]; env: Record<string, string | undefined> }): Promise<void> {
  const projectId = getArgValue(params.argv, '--projectId') ?? '';
  const projectName = getArgValue(params.argv, '--projectName') ?? projectId;
  const sourceRoot = getArgValue(params.argv, '--sourceRoot') ?? '';
  const deploymentsPath = getArgValue(params.argv, '--deploymentsPath') ?? '';
  const generatedDir = getArgValue(params.argv, '--generatedDir') ?? '.data/generated';
  const graphqlEndpoint = getArgValue(params.argv, '--graphqlEndpoint') ?? 'https://graphql.testnet.sui.io/graphql';

  const apiKey = params.env.OPENAI_API_KEY ?? '';
  const baseUrl = params.env.OPENAI_BASE_URL ?? 'https://api.openai.com';
  const model = params.env.OPENAI_MODEL ?? 'gpt-5.4';

  if (!projectId || !sourceRoot || !deploymentsPath) {
    throw new Error('Missing required args: --projectId --sourceRoot --deploymentsPath');
  }
  if (!apiKey) {
    throw new Error('Missing OPENAI_API_KEY');
  }

  const resolvedDeployments = path.resolve(process.cwd(), deploymentsPath);
  const resolvedSource = path.resolve(process.cwd(), sourceRoot);

  const result = await generateProjectRules({
    projectId,
    projectName,
    generatedDir,
    deploymentsPath: resolvedDeployments,
    sourceRoot: resolvedSource,
    graphqlEndpoint,
    openai: { apiKey, baseUrl, model },
  });

  console.log(JSON.stringify(result, null, 2));
}

async function main(): Promise<void> {
  await runGenerateCli({ argv: process.argv, env: process.env });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  void main();
}
