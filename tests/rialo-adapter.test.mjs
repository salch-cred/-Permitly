import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { RialoAdapter } from '../packages/rialo/adapter.mjs';

test('mock Rialo adapter records finalized deterministic transaction', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'agentpermit-'));
  const adapter = new RialoAdapter({ mode: 'mock', dataDir: dir, chainId: 'test', programId: 'program' });
  const tx = await adapter.record('permit_issued', { id: 'p1', budgetCap: 100 });
  assert.equal(tx.status, 'finalized');
  assert.equal(tx.block, 1);
  assert.equal(tx.kind, 'permit_issued');
  assert.equal((await adapter.read('p1')).length, 1);
});
