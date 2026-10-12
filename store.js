'use strict';
/**
 * Append-only, hash-chained JSONL ledger.
 *
 * Every record: { ..., prev_hash, hash } where
 *   hash = SHA-256(prev_hash + timestamp + agent.id + type + content + reasoning_summary + thread_id)
 * The file is opened in append mode and never rewritten. Tampering with any
 * byte breaks the chain from that record forward (detectable via verify()).
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const GENESIS_PREV = 'GENESIS';

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

function recordHash(rec) {
  return sha256Hex(
    [
      rec.prev_hash,
      rec.timestamp,
      rec.agent && rec.agent.id,
      rec.type,
      rec.content || '',
      rec.reasoning_summary || '',
      rec.thread_id || '',
    ].join('|')
  );
}

class Ledger {
  constructor(filePath) {
    this.filePath = filePath;
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    // Touch the file so it exists; opened append-only for writes.
    fs.closeSync(fs.openSync(filePath, 'a'));
    this.tip = this._readTip();
  }

  _readAllLines() {
    const raw = fs.readFileSync(this.filePath, 'utf8');
    return raw.split('\n').filter((l) => l.trim().length > 0);
  }

  _readTip() {
    const lines = this._readAllLines();
    if (lines.length === 0) return GENESIS_PREV;
    try {
      return JSON.parse(lines[lines.length - 1]).hash;
    } catch {
      return GENESIS_PREV;
    }
  }

  /** Append a record object (without prev_hash/hash); returns the stored record. */
  append(rec) {
    const stored = { ...rec, prev_hash: this.tip };
    stored.hash = recordHash(stored);
    fs.appendFileSync(this.filePath, JSON.stringify(stored) + '\n', 'utf8');
    this.tip = stored.hash;
    return stored;
  }

  /** Read records, newest last. opts: { limit, afterId } */
  read({ limit = 50, afterId = null } = {}) {
    const lines = this._readAllLines();
    let recs = lines.map((l) => JSON.parse(l));
    if (afterId) {
      const idx = recs.findIndex((r) => r.id === afterId);
      recs = idx >= 0 ? recs.slice(idx + 1) : [];
    }
    return recs.slice(-Math.min(limit, 100));
  }

  count() {
    return this._readAllLines().length;
  }

  /** Count records by type without loading full history into memory. */
  tally() {
    const counts = {};
    for (const line of this._readAllLines()) {
      let t = 'invalid';
      try {
        t = JSON.parse(line).type || 'unknown';
      } catch {
        /* keep 'invalid' */
      }
      counts[t] = (counts[t] || 0) + 1;
    }
    return counts;
  }

  /** Recompute the full chain. Returns { ok, records, tip, brokenAt }. */
  verify() {
    const lines = this._readAllLines();
    let prev = GENESIS_PREV;
    for (let i = 0; i < lines.length; i++) {
      let rec;
      try {
        rec = JSON.parse(lines[i]);
      } catch {
        return { ok: false, records: lines.length, tip: this.tip, brokenAt: i };
      }
      if (rec.prev_hash !== prev) {
        return { ok: false, records: lines.length, tip: this.tip, brokenAt: i };
      }
      if (rec.hash !== recordHash(rec)) {
        return { ok: false, records: lines.length, tip: this.tip, brokenAt: i };
      }
      prev = rec.hash;
    }
    return { ok: true, records: lines.length, tip: prev };
  }
}

module.exports = { Ledger, GENESIS_PREV, sha256Hex };
