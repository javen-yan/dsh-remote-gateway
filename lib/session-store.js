const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function timingSafeEqualHex(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

class SessionStore {
  constructor(options) {
    this.file = options.file;
    this.maxAgeMs = options.maxAgeMs;
    this.log = options.log || (() => {});
    this.state = { sessions: [] };
    this.load();
  }

  load() {
    try {
      const text = fs.readFileSync(this.file, "utf8");
      const parsed = JSON.parse(text);
      if (parsed && Array.isArray(parsed.sessions)) this.state = parsed;
    } catch (error) {
      if (error.code !== "ENOENT") this.log(`session store read failed: ${error.message}`);
    }
    this.prune();
  }

  save() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    fs.writeFileSync(this.file, JSON.stringify(this.state, null, 2));
    try {
      fs.chmodSync(this.file, 0o600);
    } catch {
      // Best-effort on filesystems that do not support chmod.
    }
  }

  prune() {
    const now = Date.now();
    const before = this.state.sessions.length;
    this.state.sessions = this.state.sessions.filter((session) => session.expiresAt > now);
    if (this.state.sessions.length !== before) this.save();
  }

  create(meta) {
    this.prune();
    const token = crypto.randomBytes(32).toString("base64url");
    this.addSession({ ...meta, tokenHash: sha256(token) });
    return token;
  }

  createBound(subject, meta) {
    if (!subject) return false;
    this.prune();
    const subjectHash = sha256(subject);
    this.state.sessions = this.state.sessions.filter((session) => session.subjectHash !== subjectHash);
    this.addSession({ ...meta, subjectHash });
    return true;
  }

  addSession(meta) {
    const now = Date.now();
    this.state.sessions.push({
      id: crypto.randomUUID(),
      tokenHash: meta.tokenHash || "",
      subjectHash: meta.subjectHash || "",
      createdAt: now,
      lastSeenAt: now,
      expiresAt: now + this.maxAgeMs,
      userAgent: meta.userAgent || "",
      address: meta.address || "",
      username: meta.username || "",
    });
    this.save();
  }

  verify(token) {
    if (!token) return false;
    this.prune();
    const tokenHash = sha256(token);
    const session = this.state.sessions.find((candidate) => timingSafeEqualHex(candidate.tokenHash, tokenHash));
    if (!session) return false;
    session.lastSeenAt = Date.now();
    this.save();
    return true;
  }

  verifyBound(subject) {
    if (!subject) return false;
    this.prune();
    const subjectHash = sha256(subject);
    const session = this.state.sessions.find((candidate) => timingSafeEqualHex(candidate.subjectHash || "", subjectHash));
    if (!session) return false;
    session.lastSeenAt = Date.now();
    this.save();
    return true;
  }

  revokeAll() {
    this.state.sessions = [];
    this.save();
  }

  summary() {
    this.prune();
    return {
      count: this.state.sessions.length,
      sessions: this.state.sessions.map((session) => ({
        id: session.id,
        createdAt: session.createdAt,
        lastSeenAt: session.lastSeenAt,
        expiresAt: session.expiresAt,
        address: session.address,
        userAgent: session.userAgent,
        username: session.username,
      })),
    };
  }
}

module.exports = { SessionStore, sha256 };
