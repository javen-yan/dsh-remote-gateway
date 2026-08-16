const crypto = require("crypto");

class PairingManager {
  constructor(options) {
    this.ttlMs = options.ttlMs;
    this.maxFailures = options.maxFailures;
    this.failureWindowMs = options.failureWindowMs;
    this.log = options.log || (() => {});
    this.failures = new Map();
    this.refresh();
  }

  refresh() {
    this.code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
    this.expiresAt = Date.now() + this.ttlMs;
    this.used = false;
    this.log(`pairing code generated, expires at ${new Date(this.expiresAt).toISOString()}`);
    return this.status();
  }

  status() {
    const now = Date.now();
    if (!this.used && this.expiresAt <= now) return this.refresh();
    return {
      expiresAt: this.expiresAt,
      ttlMs: Math.max(0, this.expiresAt - now),
      active: !this.used && this.expiresAt > now,
      code: this.code,
    };
  }

  isBlocked(address) {
    const now = Date.now();
    const record = this.failures.get(address);
    if (!record || record.resetAt <= now) return false;
    return record.count >= this.maxFailures;
  }

  noteFailure(address) {
    const now = Date.now();
    const current = this.failures.get(address);
    const next = !current || current.resetAt <= now
      ? { count: 1, resetAt: now + this.failureWindowMs }
      : { count: current.count + 1, resetAt: current.resetAt };
    this.failures.set(address, next);
    this.log(`pairing failed from ${address}; count=${next.count}`);
  }

  verify(input, address) {
    const now = Date.now();
    if (this.isBlocked(address)) return { ok: false, reason: "rate_limited" };
    if (this.used) return { ok: false, reason: "used" };
    if (this.expiresAt <= now) return { ok: false, reason: "expired" };
    const expected = Buffer.from(this.code);
    const actual = Buffer.from(String(input || ""));
    const matches = expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
    if (!matches) {
      this.noteFailure(address);
      return { ok: false, reason: "invalid" };
    }
    this.used = true;
    this.failures.delete(address);
    this.log(`pairing succeeded from ${address}`);
    return { ok: true };
  }
}

module.exports = { PairingManager };
