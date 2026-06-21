import { describe, expect, it, vi } from 'vitest';

import { callOpenAiJson } from '../src/ai/openai.js';

describe('callOpenAiJson', () => {
  it('parses output_text json', async () => {
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ output_text: '{"hello":"world"}' }),
    })) as unknown as typeof fetch;
    // @ts-expect-error test override
    globalThis.fetch = fetchMock;

    const result = await callOpenAiJson({
      client: { apiKey: 'k', baseUrl: 'https://example.com', model: 'm' },
      system: 's',
      user: 'u',
    });
    expect(result).toEqual({ hello: 'world' });
  });
});

