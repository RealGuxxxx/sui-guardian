import { afterEach, describe, expect, it, vi } from 'vitest';

import { AlertDispatcher } from '../src/alert-dispatcher.js';
import type { Alert } from '../src/types.js';

const alert: Alert = {
  id: 'alert-1',
  createdAt: '2026-04-24T00:00:00.000Z',
  projectId: 'demo',
  projectName: 'Demo',
  ruleId: 'behavior:flashloan-like-attack',
  ruleName: '行为规则 / 闪电贷式攻击闭环',
  severity: 'critical',
  summary: 'flash attack',
  details: {},
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe('AlertDispatcher', () => {
  it('does not throw when webhook delivery fails', async () => {
    const dispatcher = new AlertDispatcher(false, 'https://example.com/webhook');
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
    } as Response);
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await expect(dispatcher.dispatch(alert)).resolves.toBeUndefined();
    expect(errorSpy).toHaveBeenCalled();
  });
});
