import 'dotenv/config';

import path from 'node:path';

import { loadConfig } from './config.js';
import { MonitorService } from './monitor-service.js';
import { startServer } from './server.js';
import { errorMessage } from './utils.js';

function getArgValue(flag: string): string | undefined {
  const index = process.argv.indexOf(flag);
  if (index === -1) {
    return undefined;
  }

  return process.argv[index + 1];
}

async function main(): Promise<void> {
  const configPath = path.resolve(
    process.cwd(),
    getArgValue('--config') ?? process.env.CONFIG_PATH ?? 'config/default.yml',
  );
  const once = process.argv.includes('--once');

  const config = await loadConfig(configPath);
  config.server.host = process.env.HOST ?? config.server.host;
  config.server.port = Number(process.env.PORT ?? config.server.port);
  config.alerts.webhookUrl = process.env.ALERT_WEBHOOK_URL ?? config.alerts.webhookUrl;

  const service = new MonitorService(config);
  await service.initialize();

  if (once) {
    const summary = await service.scanOnce();
    console.log(JSON.stringify(summary, null, 2));
    return;
  }

  try {
    const initial = await service.scanOnce();
    console.log('Initial scan summary:', JSON.stringify(initial));
  } catch (error) {
    console.error(`[MONITOR] Initial scan failed; HTTP server will still start: ${errorMessage(error)}`);
  }

  service.start();
  await startServer(service, config.server.host, config.server.port, config.network.graphqlEndpoint);

  const shutdown = async () => {
    service.stop();
    process.exit(0);
  };

  process.on('SIGINT', () => {
    void shutdown();
  });
  process.on('SIGTERM', () => {
    void shutdown();
  });
}

void main().catch((error) => {
  console.error(error);
  process.exit(1);
});
