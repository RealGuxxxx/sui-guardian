import { describe, expect, it } from 'vitest';

import { runGenerateCli } from '../src/ai/cli.js';

describe('runGenerateCli', () => {
  it('requires OPENAI_API_KEY', async () => {
    await expect(runGenerateCli({
      argv: ['node', 'cli', '--projectId', 'demo', '--sourceRoot', '/tmp', '--deploymentsPath', '/tmp/a.json'],
      env: {},
    })).rejects.toThrow('Missing OPENAI_API_KEY');
  });
});

