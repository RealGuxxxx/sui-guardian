import { errorMessage } from '../utils.js';

export interface OpenAiClientConfig {
  apiKey: string;
  baseUrl: string;
  model: string;
}

export async function callOpenAiJson(params: {
  client: OpenAiClientConfig;
  system: string;
  user: string;
}): Promise<unknown> {
  const url = new URL('/v1/responses', params.client.baseUrl).toString();
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${params.client.apiKey}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: params.client.model,
      input: [
        { role: 'system', content: [{ type: 'text', text: params.system }] },
        { role: 'user', content: [{ type: 'text', text: params.user }] },
      ],
      response_format: { type: 'json_object' },
    }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(`OpenAI request failed: ${response.status} ${JSON.stringify(payload)}`);
  }

  const outputText = (payload as { output_text?: unknown }).output_text;
  if (typeof outputText === 'string' && outputText.trim().length > 0) {
    return JSON.parse(outputText);
  }

  const output = (payload as { output?: unknown }).output;
  if (Array.isArray(output)) {
    for (const item of output) {
      const content = item && typeof item === 'object' ? (item as { content?: unknown }).content : undefined;
      if (!Array.isArray(content)) {
        continue;
      }
      for (const block of content) {
        if (!block || typeof block !== 'object') {
          continue;
        }
        const type = (block as { type?: unknown }).type;
        const text = (block as { text?: unknown }).text;
        if (type === 'output_text' && typeof text === 'string') {
          return JSON.parse(text);
        }
      }
    }
  }

  throw new Error(`OpenAI response missing output text: ${errorMessage(payload)}`);
}

