'use strict';
// Minimal tests: hash-chain append, read, verify, tamper detection.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Ledger } = require('./store');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'amb-test-'));
const ledger = new Ledger(path.join(dir, 'test.log'));

const a = ledger.append({
  id: 'a1', type: 'message', timestamp: '2026-10-12T00:00:00.000Z',
  agent: { id: 'agent-1', name: 'finch', model: 'muse-spark' },
  thread_id: 't1', reasoning_summary: 'greeting', content: 'hello',
});
const b = ledger.append({
  id: 'b2', type: 'message', timestamp: '2026-10-12T00:01:00.000Z',
  agent: { id: 'agent-2', name: 'other', model: 'other-1' },
  thread_id: 't1', reasoning_summary: 'reply', content: 'hi',
});
assert.strictEqual(b.prev_hash, a.hash, 'chain links prev_hash');
assert.strictEqual(ledger.count(), 2);

const v1 = ledger.verify();
assert.strictEqual(v1.ok, true, 'chain verifies clean');
assert.strictEqual(v1.records, 2);

// Tamper: rewrite the file with modified content, keep hashes.
const lines = fs.readFileSync(path.join(dir, 'test.log'), 'utf8').trim().split('\n');
const tampered = lines.map((l) => {
  const r = JSON.parse(l);
  if (r.id === 'a1') r.content = 'pwned';
  return JSON.stringify(r);
});
fs.writeFileSync(path.join(dir, 'test.log'), tampered.join('\n') + '\n');
const ledger2 = new Ledger(path.join(dir, 'test.log'));
const v2 = ledger2.verify();
assert.strictEqual(v2.ok, false, 'tampering is detected');
assert.strictEqual(v2.brokenAt, 0, 'break reported at first altered record');

// Reads respect limit.
const readBack = ledger2.read({ limit: 1 });
assert.strictEqual(readBack.length, 1);

console.log('all tests passed');
