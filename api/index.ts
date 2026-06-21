import 'dotenv/config';
import { createServer } from '../src/server.js';
import { MonitorService } from '../src/monitor-service.js';
import { loadConfig } from '../src/config.js';
import path from 'node:path';
import type { FastifyInstance } from 'fastify';

let cachedService: MonitorService | null = null;
let cachedApp: FastifyInstance | null = null;

async function getApp(): Promise<FastifyInstance> {
  if (cachedApp) {
    return cachedApp;
  }

  const configPath = path.resolve(process.cwd(), 'config/default.yml');
  const config = await loadConfig(configPath);
  
  // Set up stateless monitor service just to hold the configuration and default state store
  cachedService = new MonitorService(config);
  await cachedService.initialize();

  const app = createServer(cachedService, config.network.graphqlEndpoint);

  // If BACKEND_API_URL is configured, we proxy all API requests to the remote self-hosted server
  const backendApiUrl = process.env.BACKEND_API_URL;
  if (backendApiUrl) {
    const targetUrl = backendApiUrl.replace(/\/$/, '');
    console.log(`[Proxy] Proxying API requests to backend: ${targetUrl}`);
    
    // Fastify hook to intercept all API requests and forward them
    app.addHook('onRequest', async (request, reply) => {
      const url = request.url;
      const isApi = url.startsWith('/api/') || url === '/health' || url === '/state' || url === '/alerts' || url === '/config';
      
      if (isApi) {
        try {
          const target = `${targetUrl}${url}`;
          const headers: Record<string, string> = {};
          for (const [key, val] of Object.entries(request.headers)) {
            if (typeof val === 'string' && key.toLowerCase() !== 'host') {
              headers[key] = val;
            }
          }

          // Forward request body if present
          let bodyInit: string | undefined = undefined;
          if (request.method !== 'GET' && request.method !== 'HEAD' && request.body) {
            bodyInit = typeof request.body === 'string' ? request.body : JSON.stringify(request.body);
          }

          const response = await fetch(target, {
            method: request.method,
            headers,
            body: bodyInit,
          });

          reply.code(response.status);
          for (const [key, val] of response.headers.entries()) {
            // Avoid duplicate headers or host header issues
            if (key.toLowerCase() !== 'transfer-encoding') {
              reply.header(key, val);
            }
          }
          const text = await response.text();
          await reply.send(text);
        } catch (error) {
          console.error(`[Proxy Error] Failed to proxy request to ${targetUrl}:`, error);
          reply.code(502);
          await reply.send({ error: 'Failed to communicate with remote backend daemon', details: String(error) });
        }
      }
    });
  }

  await app.ready();
  cachedApp = app;
  return app;
}

export default async function handler(req: any, res: any) {
  const app = await getApp();
  app.server.emit('request', req, res);
}
