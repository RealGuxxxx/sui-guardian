/**
 * Tests for platform-specific webhook payload formatting in AlertDispatcher.
 * Covers Slack Block Kit, Discord Embeds, generic JSON, retry logic, and idempotency.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { AlertDispatcher } from '../src/alert-dispatcher.js';
import type { Alert } from '../src/types.js';

const baseAlert: Alert = {
  id: 'alert-abcdef123456',
  createdAt: '2026-05-05T10:00:00.000Z',
  projectId: 'test-project',
  projectName: 'Test Protocol',
  ruleId: 'flash-loan-sequence',
  ruleName: '闪电贷序列攻击',
  severity: 'critical',
  summary: '检测到闪电贷资金循环提取行为',
  details: {
    sender: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    riskScore: 87,
    estimatedUsd: 1_500_000,
    chainHints: { stage: 'extraction' },
    remediation: {
      threat: 'Flash loan drain detected.',
      immediateActions: ['暂停合约', '通知团队', '联系安全审计方'],
    },
  },
};

afterEach(() => {
  vi.restoreAllMocks();
});

// ── Helper: capture fetch body ─────────────────────────────────────────────

function mockFetchSuccess() {
  let capturedBody: object | null = null;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
    capturedBody = JSON.parse(init?.body as string ?? '{}') as object;
    return { ok: true, status: 200, statusText: 'OK' } as Response;
  });
  return { getBody: () => capturedBody };
}

// ── Console mode ───────────────────────────────────────────────────────────

describe('AlertDispatcher console mode', () => {
  it('logs alert to console when consoleEnabled is true', async () => {
    const dispatcher = new AlertDispatcher(true);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    await dispatcher.dispatch(baseAlert);
    expect(logSpy).toHaveBeenCalled();
  });

  it('does not log to console when consoleEnabled is false', async () => {
    const dispatcher = new AlertDispatcher(false);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    await dispatcher.dispatch(baseAlert);
    expect(logSpy).not.toHaveBeenCalled();
  });

  it('returns without error when no webhook configured', async () => {
    const dispatcher = new AlertDispatcher(false);
    await expect(dispatcher.dispatch(baseAlert)).resolves.toBeUndefined();
  });
});

// ── Slack Block Kit ────────────────────────────────────────────────────────

describe('AlertDispatcher Slack payload', () => {
  it('sends Block Kit attachments format to Slack URL', async () => {
    const { getBody } = mockFetchSuccess();
    const dispatcher = new AlertDispatcher(false, 'https://hooks.slack.com/services/T000/B000/xxx');
    await dispatcher.dispatch(baseAlert);

    const body = getBody() as Record<string, unknown>;
    expect(body).toHaveProperty('attachments');
    const attachments = body['attachments'] as Array<Record<string, unknown>>;
    expect(attachments).toHaveLength(1);
  });

  it('uses severity color in Slack attachment', async () => {
    const { getBody } = mockFetchSuccess();
    const dispatcher = new AlertDispatcher(false, 'https://hooks.slack.com/services/T000/B000/xxx');
    await dispatcher.dispatch({ ...baseAlert, severity: 'critical' });

    const body = getBody() as Record<string, unknown>;
    const attachment = (body['attachments'] as Array<Record<string, unknown>>)[0]!;
    expect(attachment['color']).toBe('#ff3b82'); // critical color
  });

  it('uses correct color for high severity', async () => {
    const { getBody } = mockFetchSuccess();
    const dispatcher = new AlertDispatcher(false, 'https://hooks.slack.com/services/T000/B000/xxx');
    await dispatcher.dispatch({ ...baseAlert, severity: 'high' });

    const attachment = ((getBody() as Record<string, unknown>)['attachments'] as Array<Record<string, unknown>>)[0]!;
    expect(attachment['color']).toBe('#ff6b6b');
  });

  it('includes blocks array in attachment', async () => {
    const { getBody } = mockFetchSuccess();
    const dispatcher = new AlertDispatcher(false, 'https://hooks.slack.com/services/T000/B000/xxx');
    await dispatcher.dispatch(baseAlert);

    const attachment = ((getBody() as Record<string, unknown>)['attachments'] as Array<Record<string, unknown>>)[0]!;
    expect(Array.isArray(attachment['blocks'])).toBe(true);
    expect((attachment['blocks'] as unknown[]).length).toBeGreaterThan(0);
  });

  it('includes idempotency key in Slack metadata', async () => {
    const { getBody } = mockFetchSuccess();
    const dispatcher = new AlertDispatcher(false, 'https://hooks.slack.com/services/T000/B000/xxx');
    await dispatcher.dispatch(baseAlert);

    const body = getBody() as Record<string, unknown>;
    const metadata = body['metadata'] as Record<string, unknown>;
    expect(typeof metadata?.['idempotencyKey']).toBe('string');
    expect(metadata?.['idempotencyKey']).toContain(baseAlert.projectId);
    expect(metadata?.['idempotencyKey']).toContain(baseAlert.ruleId);
  });

  it('includes timestamp in Slack attachment', async () => {
    const { getBody } = mockFetchSuccess();
    const dispatcher = new AlertDispatcher(false, 'https://hooks.slack.com/services/T000/B000/xxx');
    await dispatcher.dispatch(baseAlert);

    const attachment = ((getBody() as Record<string, unknown>)['attachments'] as Array<Record<string, unknown>>)[0]!;
    expect(attachment['ts']).toBeDefined();
    expect(typeof attachment['ts']).toBe('string');
  });
});

// ── Discord Embeds ─────────────────────────────────────────────────────────

describe('AlertDispatcher Discord payload', () => {
  it('sends embeds format to Discord URL', async () => {
    const { getBody } = mockFetchSuccess();
    const dispatcher = new AlertDispatcher(false, 'https://discord.com/api/webhooks/123/token');
    await dispatcher.dispatch(baseAlert);

    const body = getBody() as Record<string, unknown>;
    expect(body).toHaveProperty('embeds');
    const embeds = body['embeds'] as Array<Record<string, unknown>>;
    expect(embeds).toHaveLength(1);
  });

  it('Discord embed has correct color as integer for critical', async () => {
    const { getBody } = mockFetchSuccess();
    const dispatcher = new AlertDispatcher(false, 'https://discord.com/api/webhooks/123/token');
    await dispatcher.dispatch({ ...baseAlert, severity: 'critical' });

    const embed = ((getBody() as Record<string, unknown>)['embeds'] as Array<Record<string, unknown>>)[0]!;
    // #ff3b82 as integer
    expect(embed['color']).toBe(parseInt('ff3b82', 16));
  });

  it('Discord embed includes title with severity and project name', async () => {
    const { getBody } = mockFetchSuccess();
    const dispatcher = new AlertDispatcher(false, 'https://discord.com/api/webhooks/123/token');
    await dispatcher.dispatch(baseAlert);

    const embed = ((getBody() as Record<string, unknown>)['embeds'] as Array<Record<string, unknown>>)[0]!;
    expect(embed['title'] as string).toContain('CRITICAL');
    expect(embed['title'] as string).toContain('Test Protocol');
  });

  it('Discord embed includes fields for sender and risk score', async () => {
    const { getBody } = mockFetchSuccess();
    const dispatcher = new AlertDispatcher(false, 'https://discord.com/api/webhooks/123/token');
    await dispatcher.dispatch(baseAlert);

    const embed = ((getBody() as Record<string, unknown>)['embeds'] as Array<Record<string, unknown>>)[0]!;
    const fields = embed['fields'] as Array<Record<string, unknown>>;
    const fieldNames = fields.map((f) => f['name']);
    expect(fieldNames).toContain('风险评分');
    expect(fieldNames).toContain('发送者');
  });

  it('Discord embed includes USD estimate field when present', async () => {
    const { getBody } = mockFetchSuccess();
    const dispatcher = new AlertDispatcher(false, 'https://discord.com/api/webhooks/123/token');
    await dispatcher.dispatch(baseAlert);

    const embed = ((getBody() as Record<string, unknown>)['embeds'] as Array<Record<string, unknown>>)[0]!;
    const fields = embed['fields'] as Array<Record<string, unknown>>;
    expect(fields.some((f) => f['name'] === '估算损失')).toBe(true);
  });

  it('Discord embed includes timestamp', async () => {
    const { getBody } = mockFetchSuccess();
    const dispatcher = new AlertDispatcher(false, 'https://discord.com/api/webhooks/123/token');
    await dispatcher.dispatch(baseAlert);

    const embed = ((getBody() as Record<string, unknown>)['embeds'] as Array<Record<string, unknown>>)[0]!;
    expect(embed['timestamp']).toBe(baseAlert.createdAt);
  });

  it('Discord payload has username "Sui Guardian"', async () => {
    const { getBody } = mockFetchSuccess();
    const dispatcher = new AlertDispatcher(false, 'https://discord.com/api/webhooks/123/token');
    await dispatcher.dispatch(baseAlert);

    expect((getBody() as Record<string, unknown>)['username']).toBe('Sui Guardian');
  });
});

// ── Generic JSON webhook ───────────────────────────────────────────────────

describe('AlertDispatcher generic JSON webhook', () => {
  it('sends generic JSON format for unknown webhook URL', async () => {
    const { getBody } = mockFetchSuccess();
    const dispatcher = new AlertDispatcher(false, 'https://mypager.example.com/webhook');
    await dispatcher.dispatch(baseAlert);

    const body = getBody() as Record<string, unknown>;
    expect(body).toHaveProperty('alert');
    expect(body).toHaveProperty('text');
    expect(body).toHaveProperty('idempotencyKey');
  });

  it('generic webhook idempotencyKey includes project, rule, and timestamp', async () => {
    const { getBody } = mockFetchSuccess();
    const dispatcher = new AlertDispatcher(false, 'https://mypager.example.com/webhook');
    await dispatcher.dispatch(baseAlert);

    const key = (getBody() as Record<string, unknown>)['idempotencyKey'] as string;
    expect(key).toContain('test-project');
    expect(key).toContain('flash-loan-sequence');
    expect(key).toContain('2026-05-05');
  });
});

// ── Retry logic ────────────────────────────────────────────────────────────

describe('AlertDispatcher retry logic', () => {
  it('retries on server error (5xx) and eventually gives up', async () => {
    let callCount = 0;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      callCount++;
      return { ok: false, status: 503, statusText: 'Service Unavailable' } as Response;
    });
    vi.spyOn(globalThis, 'setTimeout').mockImplementation((fn) => { (fn as () => void)(); return 0 as unknown as ReturnType<typeof setTimeout>; });
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    const dispatcher = new AlertDispatcher(false, 'https://hooks.slack.com/services/T000/B000/xxx');
    await dispatcher.dispatch(baseAlert);

    expect(callCount).toBe(3); // MAX_RETRIES = 3
    expect(errorSpy).toHaveBeenCalled();
  });

  it('does NOT retry on 4xx client error', async () => {
    let callCount = 0;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      callCount++;
      return { ok: false, status: 400, statusText: 'Bad Request' } as Response;
    });
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    const dispatcher = new AlertDispatcher(false, 'https://hooks.slack.com/services/T000/B000/xxx');
    await dispatcher.dispatch(baseAlert);

    expect(callCount).toBe(1); // No retry on 4xx
    expect(errorSpy).toHaveBeenCalled();
  });

  it('succeeds on second attempt after transient error', async () => {
    let callCount = 0;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      callCount++;
      if (callCount === 1) return { ok: false, status: 503, statusText: 'Service Unavailable' } as Response;
      return { ok: true, status: 200, statusText: 'OK' } as Response;
    });
    vi.spyOn(globalThis, 'setTimeout').mockImplementation((fn) => { (fn as () => void)(); return 0 as unknown as ReturnType<typeof setTimeout>; });

    const dispatcher = new AlertDispatcher(false, 'https://hooks.slack.com/services/T000/B000/xxx');
    await dispatcher.dispatch(baseAlert);

    expect(callCount).toBe(2);
  });

  it('sends idempotency key as HTTP header', async () => {
    let capturedHeaders: Record<string, string> | null = null;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      capturedHeaders = init?.headers as Record<string, string>;
      return { ok: true, status: 200 } as Response;
    });

    const dispatcher = new AlertDispatcher(false, 'https://hooks.slack.com/services/T000/B000/xxx');
    await dispatcher.dispatch(baseAlert);

    expect(capturedHeaders?.['x-sui-guardian-idempotency-key']).toBeDefined();
    expect(capturedHeaders?.['x-sui-guardian-idempotency-key']).toContain(baseAlert.projectId);
  });
});
