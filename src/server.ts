import Fastify from 'fastify';
import fs from 'node:fs';
import path from 'node:path';

import type { AlertStatus, MonitoringProjectConfig, Severity } from './types.js';
import type { GeneratedRulesPayload } from './ai/rule-schema.js';
import { analyzeCode } from './ai/code-analyzer.js';
import { renderDashboard } from './dashboard.js';
import { renderLandingPage } from './landing.js';
import { MonitorService } from './monitor-service.js';
import { errorMessage } from './utils.js';

// 不需要鉴权的公开路径（监控探活和 dashboard UI）
const PUBLIC_PATHS = new Set(['/', '/dashboard', '/logo.png', '/api/health', '/health']);

export async function startServer(service: MonitorService, host: string, port: number, graphqlEndpoint?: string): Promise<void> {
  const app = Fastify({ logger: false });
  const apiKey = process.env['API_KEY'] ?? '';

  if (!apiKey) {
    console.warn('[WARNING] API_KEY 未配置，所有 API 端点均可无鉴权访问。生产环境请设置 API_KEY 环境变量。');
  }

  // Bearer Token 鉴权 hook
  app.addHook('onRequest', async (request, reply) => {
    if (!apiKey) {
      return;
    }
    if (PUBLIC_PATHS.has(request.url.split('?')[0] ?? '')) {
      return;
    }
    const auth = request.headers['authorization'] ?? '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    if (token !== apiKey) {
      reply.code(401);
      await reply.send({ error: 'Unauthorized' });
    }
  });

  const healthHandler = async () => service.getHealth();

  const stateHandler = async () => service.getState();
  const configHandler = async () => service.getConfigSummary();
  const metricsHandler = async () => service.getMetrics();
  const scanHandler = async () => service.scanOnce();

  app.get('/logo.png', async (_request, reply) => {
    const logoFile = fs.readFileSync(path.resolve(process.cwd(), 'src/logo.png'));
    reply.type('image/png');
    return logoFile;
  });

  app.get('/', async (_request, reply) => {
    reply.type('text/html; charset=utf-8');
    return renderLandingPage();
  });
  app.get('/dashboard', async (_request, reply) => {
    reply.type('text/html; charset=utf-8');
    return renderDashboard();
  });

  app.get('/api/health', healthHandler);
  app.get('/health', healthHandler);

  app.get('/api/state', stateHandler);
  app.get('/state', stateHandler);

  app.get('/api/config', configHandler);
  app.get('/config', configHandler);

  app.get('/api/metrics', metricsHandler);

  app.get('/api/readiness', async () => service.getSubmissionReadiness());

  app.get('/api/behavior-timeline', async (request) => {
    const query = request.query as { limit?: string };
    const limit = query.limit ? Number.parseInt(query.limit, 10) : 10;
    return service.getBehaviorTimeline(Number.isFinite(limit) ? limit : 10);
  });

  app.get('/api/incidents', async (request) => {
    const query = request.query as { limit?: string };
    const limit = query.limit ? Number.parseInt(query.limit, 10) : 10;
    return service.getIncidentTimeline(Number.isFinite(limit) ? limit : 10).map((incident) => ({
      ...incident,
      riskScore: incident.riskScore ?? null,
      suppressionReasons: incident.suppressionReasons ?? [],
    }));
  });

  app.get('/api/assets', async (request) => {
    const query = request.query as { projectId?: string };
    return service.getAssets(query.projectId);
  });

  app.get('/api/alerts', async (request) => {
    const query = request.query as {
      status?: AlertStatus;
      projectId?: string;
      severity?: Severity;
      limit?: string;
    };

    const limit = query.limit ? Number.parseInt(query.limit, 10) : undefined;
    return service.getAlerts({
      status: query.status,
      projectId: query.projectId,
      severity: query.severity,
      limit: Number.isFinite(limit) ? limit : undefined,
    });
  });
  app.get('/alerts', async (request) => {
    const query = request.query as {
      status?: AlertStatus;
      projectId?: string;
      severity?: Severity;
      limit?: string;
    };

    const limit = query.limit ? Number.parseInt(query.limit, 10) : undefined;
    return service.getAlerts({
      status: query.status,
      projectId: query.projectId,
      severity: query.severity,
      limit: Number.isFinite(limit) ? limit : undefined,
    });
  });

  app.get('/api/scans', async (request) => {
    const query = request.query as { limit?: string };
    const limit = query.limit ? Number.parseInt(query.limit, 10) : 20;
    return service.getScanHistory(Number.isFinite(limit) ? limit : 20);
  });

  app.post('/api/scan', scanHandler);
  app.post('/scan', scanHandler);

  // ── Dynamic project management ──────────────────────────────────────────

  app.get('/api/projects', async () => service.listProjects());

  app.post('/api/projects', async (request, reply) => {
    const body = (request.body ?? {}) as {
      id?: unknown;
      name?: unknown;
      rules?: unknown;
    };

    if (typeof body.id !== 'string' || !body.id.trim()) {
      reply.code(400);
      return { error: 'id (string) is required' };
    }
    if (typeof body.name !== 'string' || !body.name.trim()) {
      reply.code(400);
      return { error: 'name (string) is required' };
    }
    if (!body.rules || typeof body.rules !== 'object') {
      reply.code(400);
      return { error: 'rules (object) is required' };
    }

    try {
      const project = rulesPayloadToProject(body.id.trim(), body.name.trim(), body.rules as GeneratedRulesPayload['rules']);
      await service.upsertProject(project);
      return { ok: true, project: { id: project.id, name: project.name } };
    } catch (error) {
      reply.code(422);
      return { error: `Failed to apply project config: ${errorMessage(error)}` };
    }
  });

  app.delete('/api/projects/:id', async (request, reply) => {
    const params = request.params as { id: string };
    const removed = await service.removeProject(params.id);
    if (!removed) {
      reply.code(404);
      return { error: 'Project not found or is a base project that cannot be removed' };
    }
    return { ok: true };
  });

  app.post('/api/analyze', async (request, reply) => {
    const body = (request.body ?? {}) as {
      code?: unknown;
      packageAddress?: unknown;
      projectName?: unknown;
      apiKey?: unknown;
    };

    // Validate code field
    if (!Array.isArray(body.code) || body.code.length === 0) {
      reply.code(400);
      return { error: 'code must be a non-empty array of { filename, content } objects' };
    }
    for (const item of body.code) {
      if (!item || typeof item !== 'object' || typeof (item as { filename?: unknown }).filename !== 'string' || typeof (item as { content?: unknown }).content !== 'string') {
        reply.code(400);
        return { error: 'each code item must have filename (string) and content (string)' };
      }
    }

    // Resolve AI API key: request body takes precedence over env
    const aiKey = (typeof body.apiKey === 'string' && body.apiKey.trim().length > 0)
      ? body.apiKey.trim()
      : (process.env['AI_API_KEY'] ?? '');
    if (!aiKey) {
      reply.code(400);
      return { error: 'AI API key not configured. Set AI_API_KEY env var or pass apiKey in request body.' };
    }

    try {
      const result = await analyzeCode({
        code: (body.code as Array<{ filename: string; content: string }>),
        packageAddress: typeof body.packageAddress === 'string' ? body.packageAddress : undefined,
        graphqlEndpoint,
        projectName: typeof body.projectName === 'string' ? body.projectName : undefined,
        openai: {
          apiKey: aiKey,
          baseUrl: process.env['ANTHROPIC_BASE_URL'] ?? 'https://api.anthropic.com',
          model: process.env['AI_MODEL'] ?? 'claude-opus-4-6',
        },
      });
      return result;
    } catch (error) {
      const msg = errorMessage(error);
      if (msg.includes('ZodError') || msg.includes('parse')) {
        reply.code(422);
        return { error: `AI response did not match expected schema: ${msg}` };
      }
      reply.code(502);
      return { error: `AI analysis failed: ${msg}` };
    }
  });

  app.patch('/api/alerts/:id/status', async (request, reply) => {
    const params = request.params as { id: string };
    const body = (request.body ?? {}) as { status?: AlertStatus; note?: string };

    if (!body.status || !isAlertStatus(body.status)) {
      reply.code(400);
      return { error: 'invalid status' };
    }

    const updated = await service.updateAlertStatus(params.id, body.status, body.note);
    if (!updated) {
      reply.code(404);
      return { error: 'alert not found' };
    }

    return updated;
  });

  await app.listen({ host, port });
  console.log(`HTTP server listening on http://${host}:${port}`);
}

function isAlertStatus(value: string): value is AlertStatus {
  return value === 'open' || value === 'acknowledged' || value === 'resolved';
}

/** Convert AI-generated rules payload to a MonitoringProjectConfig ready for the monitor service. */
function rulesPayloadToProject(id: string, name: string, rules: GeneratedRulesPayload['rules']): MonitoringProjectConfig {
  return {
    id,
    name,
    packages: (rules.packages ?? []).map((pkg) => ({
      label: pkg.label,
      address: pkg.address,
      allowedUpgradeSenders: pkg.allowedUpgradeSenders ?? [],
      deprecatedAddresses: pkg.deprecatedAddresses ?? [],
    })),
    protectedAddresses: (rules.protectedAddresses ?? []).map((addr) => ({
      label: addr.label,
      address: addr.address,
      outflowThresholds: addr.outflowThresholds,
      allowedSenders: addr.allowedSenders ?? [],
    })),
    functionGuards: (rules.functionGuards ?? []).map((guard) => ({
      label: guard.label,
      package: guard.package,
      module: guard.module,
      function: guard.function,
      allowedSenders: guard.allowedSenders ?? [],
      severity: guard.severity,
    })),
    trafficSpikes: (rules.trafficSpikes ?? []).map((spike) => ({
      label: spike.label,
      package: spike.package,
      windowSeconds: spike.windowSeconds,
      txCountThreshold: spike.txCountThreshold,
      uniqueSenderThreshold: spike.uniqueSenderThreshold,
      severity: spike.severity,
      cooldownSeconds: spike.cooldownSeconds,
    })),
    failureSpikes: (rules.failureSpikes ?? []).map((spike) => ({
      label: spike.label,
      package: spike.package,
      windowSeconds: spike.windowSeconds,
      failedTxThreshold: spike.failedTxThreshold,
      severity: spike.severity,
      cooldownSeconds: spike.cooldownSeconds,
    })),
    trackedObjects: (rules.trackedObjects ?? []).map((obj) => ({
      label: obj.label,
      address: obj.address,
      watchFields: obj.watchFields ?? [],
      criticalFields: obj.criticalFields ?? [],
      numericDecreaseThresholds: obj.numericDecreaseThresholds ?? {},
      severity: obj.severity,
    })),
    suspiciousTargets: (rules.suspiciousTargets ?? []).map((target) => ({
      label: target.label,
      address: target.address,
    })),
    behaviorRules: {
      enabled: rules.behaviorRules.enabled,
      minRepeatedCalls: rules.behaviorRules.minRepeatedCalls,
      minProtectedOutflow: rules.behaviorRules.minProtectedOutflow,
      priceDeviationThresholdBps: rules.behaviorRules.priceDeviationThresholdBps,
    },
    priceModels: (rules.priceModels ?? []).map((model) => ({
      label: model.label,
      trackedObjectLabel: model.trackedObjectLabel,
      observedFieldPath: model.observedFieldPath,
      referenceMode: model.referenceMode,
      referenceObjectLabel: model.referenceObjectLabel,
      referenceFieldPath: model.referenceFieldPath,
      fixedLowerBound: model.fixedLowerBound,
      fixedUpperBound: model.fixedUpperBound,
      deviationThresholdBps: model.deviationThresholdBps,
    })),
    objectBaselines: (rules.objectBaselines ?? []).map((baseline) => ({
      label: baseline.label,
      trackedObjectLabel: baseline.trackedObjectLabel,
      fields: (baseline.fields ?? []).map((field) => ({
        path: field.path,
        kind: field.kind,
        allowedSenders: field.allowedSenders ?? [],
        maxDeltaBps: field.maxDeltaBps,
        maxAbsoluteDecrease: field.maxAbsoluteDecrease,
      })),
    })),
    flowTracking: {
      enabled: rules.flowTracking.enabled,
      minProtectedOutflow: rules.flowTracking.minProtectedOutflow,
      attackerGainThreshold: rules.flowTracking.attackerGainThreshold,
      shortWindowTxCount: rules.flowTracking.shortWindowTxCount,
    },
    suppression: {
      enabled: rules.suppression.enabled,
      duplicateWindowSeconds: rules.suppression.duplicateWindowSeconds,
      weakSignalScoreThreshold: rules.suppression.weakSignalScoreThreshold,
      maintenanceWindows: (rules.suppression.maintenanceWindows ?? []).map((w) => ({
        label: w.label,
        allowedSenders: w.allowedSenders ?? [],
        startHourUtc: w.startHourUtc,
        endHourUtc: w.endHourUtc,
      })),
    },
  };
}
