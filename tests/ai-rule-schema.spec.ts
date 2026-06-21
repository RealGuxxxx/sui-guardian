import { describe, expect, it } from 'vitest';

import { generatedRulesSchema } from '../src/ai/rule-schema.js';

describe('generatedRulesSchema', () => {
  it('parses minimal payload and applies defaults', () => {
    const parsed = generatedRulesSchema.parse({
      version: 'v',
      projectId: 'p',
      rules: {},
    });
    expect(parsed.projectId).toBe('p');
    expect(parsed.rules.functionGuards).toEqual([]);
    expect(parsed.rules.suppression?.duplicateWindowSeconds).toBe(600);
  });
});

