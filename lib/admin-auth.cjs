const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const DEFAULT_KEYLEN = 32;

function timingSafeEqualBase64(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const leftBuffer = Buffer.from(left, "base64");
  const rightBuffer = Buffer.from(right, "base64");
  if (leftBuffer.length !== rightBuffer.length) return false;
  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function hashPassword(password, salt) {
  return crypto.scryptSync(String(password), salt, DEFAULT_KEYLEN).toString("base64");
}

function createPasswordRecord(password) {
  const salt = crypto.randomBytes(16).toString("base64");
  return {
    version: 1,
    algo: "scrypt",
    salt,
    keylen: DEFAULT_KEYLEN,
    hash: hashPassword(password, salt),
    updatedAt: new Date().toISOString(),
  };
}

class AdminAuth {
  constructor(options) {
    this.file = options.file;
    this.log = options.log || (() => {});
    this.maxFailures = Number(options.maxFailures || 10);
    this.failureWindowMs = Number(options.failureWindowMs || 5 * 60 * 1000);
    this.failures = new Map();
  }

  isConfigured() {
    try {
      const record = JSON.parse(fs.readFileSync(this.file, "utf8"));
      return Boolean(record && record.algo === "scrypt" && record.salt && record.hash);
    } catch {
      return false;
    }
  }

  isBlocked(address) {
    const now = Date.now();
    const record = this.failures.get(address);
    return Boolean(record && record.resetAt > now && record.count >= this.maxFailures);
  }

  noteFailure(address) {
    const now = Date.now();
    const current = this.failures.get(address);
    const next = !current || current.resetAt <= now
      ? { count: 1, resetAt: now + this.failureWindowMs }
      : { count: current.count + 1, resetAt: current.resetAt };
    this.failures.set(address, next);
    this.log(`login failed from ${address}; count=${next.count}`);
  }

  verify(password, address) {
    if (this.isBlocked(address)) return { ok: false, reason: "rate_limited" };
    let record;
    try {
      record = JSON.parse(fs.readFileSync(this.file, "utf8"));
    } catch {
      return { ok: false, reason: "not_configured" };
    }
    if (!record || record.algo !== "scrypt" || !record.salt || !record.hash) {
      return { ok: false, reason: "not_configured" };
    }
    const actual = hashPassword(password || "", record.salt);
    const matches = timingSafeEqualBase64(actual, record.hash);
    if (!matches) {
      this.noteFailure(address);
      return { ok: false, reason: "invalid" };
    }
    this.failures.delete(address);
    this.log(`login succeeded from ${address}`);
    return { ok: true };
  }
}

function writePasswordFile(file, password) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(createPasswordRecord(password), null, 2));
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    // Best-effort on filesystems that do not support chmod.
  }
}

module.exports = { AdminAuth, createPasswordRecord, writePasswordFile };
