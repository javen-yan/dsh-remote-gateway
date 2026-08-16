const fs = require("fs");
const http = require("http");
const net = require("net");
const path = require("path");
const { randomBytes } = require("crypto");
const { AdminAuth } = require("./admin-auth");
const { PairingManager } = require("./pairing");
const { SessionStore, sha256 } = require("./session-store");

const COOKIE_NAME = "fnos_dsh_gateway";
const ADMIN_COOKIE_NAME = "fnos_dsh_admin";
const DEFAULT_PREFIX = "/app/deepseek_harness";
const STATIC_DIR = path.join(__dirname, "..", "static");

function appendLog(file, message) {
  if (!file) return;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.appendFileSync(file, `${new Date().toISOString()} ${message}\n`);
}

function parseCookies(header) {
  const result = new Map();
  for (const part of String(header || "").split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    result.set(part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1).trim()));
  }
  return result;
}

function readJsonBody(req, maxBytes = 4096) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error("request body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (chunks.length === 0) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res, status, body) {
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "content-length": payload.length,
  });
  res.end(payload);
}

function sendHtml(res, status, body) {
  const payload = Buffer.from(body, "utf8");
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "content-length": payload.length,
  });
  res.end(payload);
}

function safeWrite(socket, data, log) {
  if (!socket || socket.destroyed) return false;
  try {
    socket.write(data);
    return true;
  } catch (error) {
    if (log) log(`socket write failed: ${error.message}`);
    socket.destroy();
    return false;
  }
}

function writeWsFrame(socket, opcode, payload = Buffer.alloc(0)) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const header = [];
  header.push(0x80 | opcode);
  if (body.length < 126) {
    header.push(body.length);
  } else if (body.length < 65536) {
    header.push(126, (body.length >> 8) & 0xff, body.length & 0xff);
  } else {
    header.push(127, 0, 0, 0, 0, (body.length / 0x1000000) & 0xff, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff);
  }
  socket.write(Buffer.concat([Buffer.from(header), body]));
}

function parseWsFrames(buffer, onFrame) {
  let offset = 0;
  while (buffer.length - offset >= 2) {
    const first = buffer[offset];
    const second = buffer[offset + 1];
    let length = second & 0x7f;
    let cursor = offset + 2;
    if (length === 126) {
      if (buffer.length - cursor < 2) break;
      length = buffer.readUInt16BE(cursor);
      cursor += 2;
    } else if (length === 127) {
      if (buffer.length - cursor < 8) break;
      const high = buffer.readUInt32BE(cursor);
      const low = buffer.readUInt32BE(cursor + 4);
      length = high * 0x100000000 + low;
      cursor += 8;
    }
    const masked = Boolean(second & 0x80);
    let mask;
    if (masked) {
      if (buffer.length - cursor < 4) break;
      mask = buffer.subarray(cursor, cursor + 4);
      cursor += 4;
    }
    if (buffer.length - cursor < length) break;
    const payload = Buffer.from(buffer.subarray(cursor, cursor + length));
    if (masked) {
      for (let index = 0; index < payload.length; index += 1) payload[index] ^= mask[index % 4];
    }
    onFrame(first & 0x0f, payload);
    offset = cursor + length;
  }
  return buffer.subarray(offset);
}

function readStatic(name) {
  return fs.readFileSync(path.join(STATIC_DIR, name), "utf8");
}

const STATIC_FILES = {
  "/gateway/theme.css": { file: "theme.css", type: "text/css; charset=utf-8" },
  "/gateway/favicon.svg": { file: "favicon.svg", type: "image/svg+xml" },
};

function handleStaticFile(req, res, mode) {
  if (req.method !== "GET") return false;
  const pathname = new URL(mode.path, "http://gateway.local").pathname;
  const entry = STATIC_FILES[pathname];
  if (!entry) return false;
  const payload = fs.readFileSync(path.join(STATIC_DIR, entry.file));
  res.writeHead(200, {
    "content-type": entry.type,
    "cache-control": "no-store",
    "content-length": payload.length,
  });
  res.end(payload);
  return true;
}

function isHtmlRequest(req) {
  const accept = String(req.headers.accept || "");
  return req.method === "GET" && (accept.includes("text/html") || accept.includes("*/*"));
}

function clientAddress(req) {
  return String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
}

function trimUser(req) {
  const uid = String(req.headers["x-trim-userid"] || "").trim();
  if (!uid) return null;
  return {
    uid,
    username: String(req.headers["x-trim-username"] || "").trim(),
    isAdmin: String(req.headers["x-trim-isadmin"] || "").trim() === "true",
  };
}

function userAgentHash(req) {
  return sha256(String(req.headers["user-agent"] || "")).slice(0, 24);
}

function isSecureRequest(req) {
  return req.socket.encrypted || String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim() === "https";
}

function gatewayShim(prefix, websocketPort) {
  const prefixJson = JSON.stringify(prefix);
  const websocketPortJson = JSON.stringify(websocketPort ? String(websocketPort) : "");
  return `<script>(() => {
  const prefix = ${prefixJson};
  const websocketPort = ${websocketPortJson};
  const apiPath = "/api";
  const withPrefix = (pathname) => prefix && pathname.startsWith("/") && !pathname.startsWith(prefix + "/") ? prefix + pathname : pathname;
  const fallbackRandomUUID = () => {
    const bytes = new Uint8Array(16);
    if (window.crypto && typeof window.crypto.getRandomValues === "function") window.crypto.getRandomValues(bytes);
    else for (let i = 0; i < bytes.length; i += 1) bytes[i] = Math.floor(Math.random() * 256);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = [...bytes].map((value) => value.toString(16).padStart(2, "0"));
    return [hex.slice(0,4).join(""), hex.slice(4,6).join(""), hex.slice(6,8).join(""), hex.slice(8,10).join(""), hex.slice(10,16).join("")].join("-");
  };
  if (window.crypto && typeof window.crypto.randomUUID !== "function") {
    try { Object.defineProperty(window.crypto, "randomUUID", { value: fallbackRandomUUID, configurable: true }); }
    catch { if (typeof Crypto !== "undefined" && Crypto.prototype) Crypto.prototype.randomUUID = fallbackRandomUUID; }
  }
  const gatewayUrl = (url) => {
    const next = new URL(url, window.location.href);
    if (next.origin === window.location.origin) {
      if (next.pathname === apiPath || next.pathname.startsWith(apiPath + "/")) next.pathname = withPrefix(next.pathname);
      for (const root of ["/assets", "/plugins", "/favicon.svg", "/manifest.webmanifest"]) {
        if (next.pathname === root || next.pathname.startsWith(root + "/")) next.pathname = withPrefix(next.pathname);
      }
    }
    return next;
  };
  const nativeFetch = window.fetch.bind(window);
  window.fetch = (input, init) => input instanceof Request ? nativeFetch(new Request(gatewayUrl(input.url), input), init) : nativeFetch(gatewayUrl(input), init);
  const NativeWebSocket = window.WebSocket;
  class GatewayEventSocket extends EventTarget {
    constructor(url, streamUrl) {
      super();
      this.url = url;
      this.readyState = NativeWebSocket.CONNECTING;
      this._abort = new AbortController();
      this._connect(streamUrl);
    }
    async _connect(streamUrl) {
      try {
        const response = await fetch(streamUrl, {
          cache: "no-store",
          credentials: "same-origin",
          signal: this._abort.signal,
        });
        if (!response.ok || !response.body) throw new Error("stream open failed: HTTP " + response.status);
        if (this.readyState !== NativeWebSocket.CONNECTING) return;
        this.readyState = NativeWebSocket.OPEN;
        this.dispatchEvent(new Event("open"));
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        while (this.readyState === NativeWebSocket.OPEN) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let boundary;
          while ((boundary = buffer.indexOf("\\n\\n")) >= 0) {
            const raw = buffer.slice(0, boundary);
            buffer = buffer.slice(boundary + 2);
            const data = raw.split("\\n").filter((line) => line.startsWith("data:")).map((line) => line.slice(5).trimStart()).join("\\n");
            if (data) this.dispatchEvent(new MessageEvent("message", { data }));
          }
        }
      } catch (error) {
        if (!this._abort.signal.aborted) this.dispatchEvent(new Event("error"));
      } finally {
        this._close();
      }
    }
    send() {
      throw new Error("gateway event socket is downlink only");
    }
    close() {
      this._abort.abort();
      this._close();
    }
    _close() {
      if (this.readyState === NativeWebSocket.CLOSED) return;
      this.readyState = NativeWebSocket.CLOSED;
      this.dispatchEvent(new CloseEvent("close"));
    }
  }
  window.WebSocket = function(url, protocols) {
    const nextUrl = gatewayUrl(url);
    const eventPath = prefix && nextUrl.pathname.startsWith(prefix + "/api/events")
      ? nextUrl.pathname.slice(prefix.length)
      : nextUrl.pathname;
    if (eventPath === "/api/events" || eventPath.startsWith("/api/events.")) {
      if (prefix) {
        const streamUrl = new URL(prefix + "/gateway" + eventPath.slice("/api".length), window.location.href);
        return new GatewayEventSocket(nextUrl.toString(), streamUrl.toString());
      }
      if (websocketPort && nextUrl.origin === window.location.origin) {
        nextUrl.protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        nextUrl.hostname = window.location.hostname;
        nextUrl.port = websocketPort;
        nextUrl.pathname = eventPath;
      }
    }
    const next = nextUrl.toString();
    return protocols === undefined ? new NativeWebSocket(next) : new NativeWebSocket(next, protocols);
  };
  window.WebSocket.prototype = NativeWebSocket.prototype;
  for (const key of ["CONNECTING", "OPEN", "CLOSING", "CLOSED"]) Object.defineProperty(window.WebSocket, key, { value: NativeWebSocket[key] });
  if (window.EventSource) {
    const NativeEventSource = window.EventSource;
    window.EventSource = function(url, config) { return new NativeEventSource(gatewayUrl(url).toString(), config); };
    window.EventSource.prototype = NativeEventSource.prototype;
  }
})()</script>`;
}

function rewriteAbsolutePaths(text, prefix) {
  if (!prefix) return text;
  for (const root of ["/assets", "/plugins", "/favicon.svg", "/manifest.webmanifest", "/api"]) {
    const escaped = root.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    text = text
      .replace(new RegExp(`(["'=])${escaped}(?=([/?#"]|'))`, "g"), `$1${prefix}${root}`)
      .replace(new RegExp(`url\\(${escaped.replace(/\//g, "\\/")}`, "g"), `url(${prefix}${root}`);
  }
  return text;
}

function rewriteBody(contentType, body, prefix, websocketPort) {
  const type = String(contentType || "");
  if (!/(text\/html|text\/css|javascript)/i.test(type)) return body;
  let text = body.toString("utf8");
  if (/text\/html/i.test(type)) {
    text = rewriteAbsolutePaths(text, prefix);
    text = text.replace(/<link\s+rel=["']manifest["'][^>]*>\s*/i, "");
    if (!text.includes("window.__FNOS_DSH_GATEWAY__")) {
      text = text.replace(/<head>/i, `<head><script>window.__FNOS_DSH_GATEWAY__=true</script>${gatewayShim(prefix, websocketPort)}`);
    }
  } else {
    text = rewriteAbsolutePaths(text, prefix);
  }
  return Buffer.from(text, "utf8");
}

function shouldRewriteResponse(contentType) {
  return /(text\/html|text\/css|javascript)/i.test(String(contentType || ""));
}

function cookieHeader(name, token, cookiePath, maxAgeSeconds, secure) {
  return `${name}=${encodeURIComponent(token)}; Path=${cookiePath}; Max-Age=${maxAgeSeconds}; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
}

function clearCookieHeader(name, cookiePath, secure) {
  return `${name}=; Path=${cookiePath}; Max-Age=0; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
}

function probeUpstream(host, port) {
  return new Promise((resolve) => {
    const req = http.request({ host, port, path: "/", method: "HEAD", timeout: 1500 }, (res) => {
      res.resume();
      resolve(res.statusCode !== undefined && res.statusCode < 500);
    });
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });
    req.on("error", () => resolve(false));
    req.end();
  });
}

function createGateway(options) {
  const prefix = options.prefix || DEFAULT_PREFIX;
  const upstreamHost = options.upstreamHost || "127.0.0.1";
  const upstreamPort = Number(options.upstreamPort ?? 3080);
  const portHost = options.portHost || "0.0.0.0";
  const port = Number(options.port ?? 3081);
  const pathGatewayPort = Number(options.pathGatewayPort ?? 5666);
  const socketPath = options.socketPath;
  const logFile = options.logFile;
  const accessLogFile = options.accessLogFile;
  const dataDir = options.dataDir || process.cwd();
  const sessionMaxAgeSeconds = Number(options.sessionMaxAgeSeconds || 30 * 24 * 60 * 60);
  const adminSessionMaxAgeSeconds = Number(options.adminSessionMaxAgeSeconds || sessionMaxAgeSeconds);
  const adminPasswordFile = options.adminPasswordFile || path.join(dataDir, "gateway", "admin-password.json");
  const writableDirs = (options.writableDirs || []).filter(Boolean);
  const pathEnabled = Boolean(socketPath);
  const portEnabled = port > 0;
  const activeMode = pathEnabled ? "path" : "port";
  const websocketPort = pathEnabled && portEnabled ? port : 0;

  const log = (message) => appendLog(logFile, message);
  const access = (message) => appendLog(accessLogFile, message);
  const sessions = new SessionStore({ file: path.join(dataDir, "gateway", "devices.json"), maxAgeMs: sessionMaxAgeSeconds * 1000, log });
  const adminSessions = new SessionStore({ file: path.join(dataDir, "gateway", "admin-devices.json"), maxAgeMs: adminSessionMaxAgeSeconds * 1000, log });
  const adminAuth = new AdminAuth({ file: adminPasswordFile, log });
  const pairing = new PairingManager({
    ttlMs: Number(options.pairingTtlMs || 5 * 60 * 1000),
    maxFailures: Number(options.maxPairFailures || 10),
    failureWindowMs: Number(options.failureWindowMs || 5 * 60 * 1000),
    log,
  });

  function modeFor(req) {
    const url = req.url || "/";
    const isPathMode = url === prefix || url.startsWith(`${prefix}/`);
    const externalPrefix = isPathMode ? prefix : "";
    const strippedPath = isPathMode ? (url === prefix ? "/" : url.slice(prefix.length) || "/") : url;
    return {
      isPathMode,
      prefix: externalPrefix,
      path: strippedPath.startsWith("/") ? strippedPath : `/${strippedPath}`,
      cookiePath: isPathMode ? prefix : "/",
    };
  }

  function boundSubject(req, mode, scope) {
    const user = mode.isPathMode ? trimUser(req) : null;
    if (!user) return "";
    return `${scope}:trim:${user.uid}:ua:${userAgentHash(req)}`;
  }

  function isAuthenticated(req, mode) {
    if (mode.isPathMode) return sessions.verifyBound(boundSubject(req, mode, "gateway"));
    return sessions.verify(parseCookies(req.headers.cookie).get(COOKIE_NAME));
  }

  function isAdminAuthenticated(req, mode) {
    if (mode.isPathMode) return adminSessions.verifyBound(boundSubject(req, mode, "admin"));
    return adminSessions.verify(parseCookies(req.headers.cookie).get(ADMIN_COOKIE_NAME));
  }

  function requirePathIdentity(req, mode, res) {
    if (!mode.isPathMode || trimUser(req)) return true;
    log(`missing fnOS gateway identity for ${mode.path}`);
    sendJson(res, 403, {
      ok: false,
      reason: "missing_gateway_identity",
      message: "无法确认 fnOS 网关身份，请从 fnOS 应用入口打开。",
    });
    return false;
  }

  function redirectToPair(req, res, mode) {
    const target = encodeURIComponent(req.url || (mode.isPathMode ? `${prefix}/` : "/"));
    res.writeHead(302, { location: `${mode.prefix}/pair?next=${target}`, "cache-control": "no-store" });
    res.end();
  }

  function redirectToAdminLogin(req, res, mode) {
    const target = encodeURIComponent(req.url || `${mode.prefix}/gateway/admin`);
    res.writeHead(302, { location: `${mode.prefix}/gateway/admin-login?next=${target}`, "cache-control": "no-store" });
    res.end();
  }

  async function handleGatewayRoute(req, res, mode) {
    const pathname = new URL(mode.path, "http://gateway.local").pathname;
    const canManage = isAdminAuthenticated(req, mode);
    const adminConfigured = adminAuth.isConfigured();
    if (pathname === "/gateway/status" && req.method === "GET") {
      const upstreamOk = await probeUpstream(upstreamHost, upstreamPort);
      const host = String(req.headers.host || "");
      const hostname = host.split(":")[0] || "localhost";
      const pathHost = mode.isPathMode ? host : `${hostname}:${pathGatewayPort}`;
      const pairingStatus = pairing.status();
      const body = {
        upstreamOk,
        gatewayOk: true,
        version: require("../package.json").version,
        mode: activeMode,
        pathUrl: pathEnabled ? `http://${pathHost}${prefix}/` : "",
        portUrl: portEnabled ? `http://${hostname}:${port}/` : "",
        adminConfigured,
      };
      if (canManage) {
        body.pairing = pairingStatus;
        body.sessions = sessions.summary();
        body.adminSessions = adminSessions.summary();
        body.logs = {
          install: options.installLog || "",
          gatewayInstall: options.gatewayInstallLog || "",
          gateway: logFile || "",
          access: accessLogFile || "",
          dsh: options.dshLog || "",
          dshmarket: options.marketLog || "",
        };
        body.writableDirs = writableDirs;
      } else {
        body.pairing = { active: pairingStatus.active, expiresAt: pairingStatus.expiresAt, ttlMs: pairingStatus.ttlMs };
        body.sessions = { count: sessions.summary().count };
      }
      sendJson(res, 200, body);
      return true;
    }
    if (pathname === "/gateway/admin-login" && req.method === "POST") {
      try {
        const body = await readJsonBody(req);
        const result = adminAuth.verify(body.password, clientAddress(req));
        if (!result.ok) {
          const status = result.reason === "rate_limited" ? 429 : 401;
          sendJson(res, status, {
            ok: false,
            reason: result.reason,
            message: result.reason === "not_configured"
              ? "管理密码未设置，请先在 fnOS 应用配置中设置。"
              : "管理密码不正确。",
          });
          return true;
        }
        if (mode.isPathMode) {
          if (!requirePathIdentity(req, mode, res)) return true;
          const user = trimUser(req);
          adminSessions.createBound(boundSubject(req, mode, "admin"), {
            address: clientAddress(req),
            userAgent: req.headers["user-agent"],
            username: user.username || user.uid,
          });
          log(`admin session bound for fnOS user ${user.uid}`);
        } else {
          const token = adminSessions.create({ address: clientAddress(req), userAgent: req.headers["user-agent"] });
          res.setHeader("set-cookie", cookieHeader(ADMIN_COOKIE_NAME, token, mode.cookiePath, adminSessionMaxAgeSeconds, isSecureRequest(req)));
        }
        sendJson(res, 200, { ok: true });
      } catch (error) {
        sendJson(res, 400, { ok: false, message: error.message });
      }
      return true;
    }
    if (pathname === "/gateway/refresh-pair-code" && req.method === "POST") {
      if (!canManage) {
        sendJson(res, 401, { ok: false, error: "unauthorized" });
        return true;
      }
      pairing.refresh();
      sendJson(res, 200, { ok: true, pairing: pairing.status() });
      return true;
    }
    if (pathname === "/gateway/revoke-all" && req.method === "POST") {
      if (!canManage) {
        sendJson(res, 401, { ok: false, error: "unauthorized" });
        return true;
      }
        sessions.revokeAll();
        res.setHeader("set-cookie", [
          clearCookieHeader(COOKIE_NAME, "/", isSecureRequest(req)),
          clearCookieHeader(COOKIE_NAME, prefix, isSecureRequest(req)),
          clearCookieHeader(COOKIE_NAME, `${prefix}/`, isSecureRequest(req)),
        ]);
      sendJson(res, 200, { ok: true });
      return true;
    }
    if (pathname === "/gateway/pair" && req.method === "POST") {
      try {
        const body = await readJsonBody(req);
        if (mode.isPathMode && !requirePathIdentity(req, mode, res)) return true;
        const result = pairing.verify(body.code, clientAddress(req));
        if (!result.ok) {
          const status = result.reason === "rate_limited" ? 429 : 401;
          sendJson(res, status, { ok: false, reason: result.reason, message: "配对失败，请检查配对码。" });
          return true;
        }
        if (mode.isPathMode) {
          if (!requirePathIdentity(req, mode, res)) return true;
          const user = trimUser(req);
          sessions.createBound(boundSubject(req, mode, "gateway"), {
            address: clientAddress(req),
            userAgent: req.headers["user-agent"],
            username: user.username || user.uid,
          });
          const token = sessions.create({ address: clientAddress(req), userAgent: req.headers["user-agent"], username: user.username || user.uid });
          res.setHeader("set-cookie", cookieHeader(COOKIE_NAME, token, "/", sessionMaxAgeSeconds, isSecureRequest(req)));
          log(`gateway session bound for fnOS user ${user.uid}`);
        } else {
          const token = sessions.create({ address: clientAddress(req), userAgent: req.headers["user-agent"] });
          res.setHeader("set-cookie", cookieHeader(COOKIE_NAME, token, mode.cookiePath, sessionMaxAgeSeconds, isSecureRequest(req)));
        }
        pairing.refresh();
        sendJson(res, 200, { ok: true });
      } catch (error) {
        sendJson(res, 400, { ok: false, message: error.message });
      }
      return true;
    }
    return false;
  }

  function handlePairPage(req, res, mode) {
    const pathname = new URL(mode.path, "http://gateway.local").pathname;
    if (pathname === "/pair") {
      sendHtml(res, 200, readStatic("login.html"));
      return true;
    }
    if (pathname === "/gateway/admin-login") {
      sendHtml(res, 200, readStatic("admin-login.html"));
      return true;
    }
    if (pathname === "/gateway/admin") {
      if (!isAdminAuthenticated(req, mode)) {
        redirectToAdminLogin(req, res, mode);
        return true;
      }
      sendHtml(res, 200, readStatic("admin.html"));
      return true;
    }
    return false;
  }

  function proxyEventStream(req, res, mode, eventPath) {
    if (!isAuthenticated(req, mode)) {
      sendJson(res, 401, { ok: false, error: "unauthorized" });
      return;
    }
    const key = randomBytes(16).toString("base64");
    const upstream = net.connect(upstreamPort, upstreamHost);
    let pending = Buffer.alloc(0);
    let headersDone = false;
    let closed = false;
    const close = () => {
      if (closed) return;
      closed = true;
      upstream.destroy();
      res.end();
    };
    const sendEvent = (payload) => {
      if (closed || res.destroyed) return;
      res.write(`data: ${payload.toString("utf8").replace(/\r?\n/g, "\\n")}\n\n`);
    };
    upstream.on("connect", () => {
      const lines = [
        `GET ${eventPath} HTTP/1.1`,
        `Host: ${upstreamHost}:${upstreamPort}`,
        `Origin: http://${upstreamHost}:${upstreamPort}`,
        "Connection: Upgrade",
        "Upgrade: websocket",
        "Sec-WebSocket-Version: 13",
        `Sec-WebSocket-Key: ${key}`,
        "",
        "",
      ].join("\r\n");
      upstream.write(lines);
    });
    upstream.on("data", (chunk) => {
      pending = Buffer.concat([pending, chunk]);
      if (!headersDone) {
        const headerEnd = pending.indexOf("\r\n\r\n");
        if (headerEnd < 0) return;
        const headerText = pending.subarray(0, headerEnd).toString("latin1");
        pending = pending.subarray(headerEnd + 4);
        if (!/^HTTP\/1\.[01] 101\b/.test(headerText)) {
          log(`event stream upstream rejected ${eventPath}: ${headerText.split("\r\n")[0] || "no status"}`);
          res.writeHead(502, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
          close();
          return;
        }
        headersDone = true;
        res.writeHead(200, {
          "content-type": "text/event-stream; charset=utf-8",
          "cache-control": "no-store, no-transform",
          "connection": "keep-alive",
          "x-accel-buffering": "no",
        });
        if (typeof res.flushHeaders === "function") res.flushHeaders();
      }
      pending = parseWsFrames(pending, (opcode, payload) => {
        if (opcode === 0x1) sendEvent(payload);
        else if (opcode === 0x8) close();
        else if (opcode === 0x9) writeWsFrame(upstream, 0x0a, payload);
      });
    });
    upstream.on("error", (error) => {
      log(`event stream upstream error ${eventPath}: ${error.message}`);
      if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
      close();
    });
    upstream.on("close", close);
    req.on("close", close);
    res.on("error", close);
  }

  function proxyHttp(req, res, mode) {
    const headers = { ...req.headers };
    headers.host = `${upstreamHost}:${upstreamPort}`;
    headers.origin = `http://${upstreamHost}:${upstreamPort}`;
    delete headers["accept-encoding"];
    delete headers["x-forwarded-host"];
    delete headers["x-forwarded-proto"];

    const upstreamReq = http.request({ host: upstreamHost, port: upstreamPort, method: req.method, path: mode.path, headers }, (upstreamRes) => {
      const responseHeaders = { ...upstreamRes.headers };
      if (responseHeaders.location && mode.prefix && String(responseHeaders.location).startsWith("/")) {
        responseHeaders.location = `${mode.prefix}${responseHeaders.location}`;
      }
      if (!shouldRewriteResponse(responseHeaders["content-type"])) {
        res.writeHead(upstreamRes.statusCode || 502, responseHeaders);
        if (typeof res.flushHeaders === "function") res.flushHeaders();
        upstreamRes.pipe(res);
        return;
      }

      const chunks = [];
      upstreamRes.on("data", (chunk) => chunks.push(chunk));
      upstreamRes.on("end", () => {
        let body = Buffer.concat(chunks);
        body = rewriteBody(responseHeaders["content-type"], body, mode.prefix, websocketPort);
        delete responseHeaders["content-encoding"];
        delete responseHeaders["transfer-encoding"];
        responseHeaders["content-length"] = Buffer.byteLength(body);
        res.writeHead(upstreamRes.statusCode || 502, responseHeaders);
        res.end(body);
      });
    });
    upstreamReq.on("error", (error) => {
      log(`http proxy error: ${error.message}`);
      sendHtml(res, 502, `<h1>DeepSeek Harness unavailable</h1><p>${error.message}</p>`);
    });
    const hasBody = !["GET", "HEAD"].includes(req.method || "")
      && (headers["content-length"] || headers["transfer-encoding"]);
    if (hasBody) req.pipe(upstreamReq);
    else upstreamReq.end();
  }

  async function handle(req, res) {
    const mode = modeFor(req);
    const pathname = new URL(mode.path, "http://gateway.local").pathname;
    access(`${req.method} ${req.url} ${clientAddress(req)}`);
    if (req.method === "GET" && (pathname === "/gateway/events.mux" || pathname === "/gateway/events.host")) {
      proxyEventStream(req, res, mode, `/api/${pathname.slice("/gateway/".length)}`);
      return;
    }
    if (await handleGatewayRoute(req, res, mode)) return;
    if (handlePairPage(req, res, mode)) return;
    if (handleStaticFile(req, res, mode)) return;
    if (req.method === "GET" && pathname === "/favicon.svg") {
      proxyHttp(req, res, mode);
      return;
    }
    if (!isAuthenticated(req, mode)) {
      if (isHtmlRequest(req)) redirectToPair(req, res, mode);
      else sendJson(res, 401, { ok: false, error: "unauthorized" });
      return;
    }
    proxyHttp(req, res, mode);
  }

  function handleUpgrade(req, socket, head) {
    const mode = modeFor(req);
    access(`UPGRADE ${req.url} ${clientAddress(req)}`);
    if (!isAuthenticated(req, mode)) {
      log(`websocket unauthorized for ${req.url} from ${clientAddress(req)}`);
      safeWrite(socket, "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 12\r\n\r\nunauthorized", log);
      socket.end();
      return;
    }
    const upstream = net.connect(upstreamPort, upstreamHost, () => {
      const headers = { ...req.headers, host: `${upstreamHost}:${upstreamPort}`, origin: `http://${upstreamHost}:${upstreamPort}` };
      const lines = [
        `${req.method} ${mode.path} HTTP/${req.httpVersion}`,
        ...Object.entries(headers).map(([key, value]) => `${key}: ${value}`),
        "",
        "",
      ].join("\r\n");
      if (!safeWrite(upstream, lines, log)) return;
      if (head.length && !safeWrite(upstream, head, log)) return;
      socket.pipe(upstream).pipe(socket);
    });
    socket.on("error", (error) => {
      log(`websocket client socket error: ${error.message}`);
      upstream.destroy();
    });
    upstream.on("error", (error) => {
      log(`websocket proxy error: ${error.message}`);
      socket.destroy();
    });
    socket.on("close", () => upstream.destroy());
    upstream.on("close", () => socket.destroy());
  }

  function createServer() {
    const server = http.createServer((req, res) => {
      handle(req, res).catch((error) => {
        log(`request failed: ${error.stack || error.message}`);
        sendJson(res, 500, { ok: false, error: "gateway_error" });
      });
    });
    server.on("upgrade", handleUpgrade);
    return server;
  }

  function listen() {
    const servers = [];
    if (socketPath) {
      fs.mkdirSync(path.dirname(socketPath), { recursive: true });
      if (fs.existsSync(socketPath)) fs.unlinkSync(socketPath);
      const socketServer = createServer();
      socketServer.on("error", (error) => {
        log(`gateway socket listen error: ${error.message}`);
        process.nextTick(() => process.exit(1));
      });
      socketServer.listen(socketPath, () => {
        try {
          fs.chmodSync(socketPath, 0o660);
        } catch {}
        log(`gateway socket listening on ${socketPath}; prefix=${prefix}`);
      });
      servers.push(socketServer);
    }
    if (port > 0) {
      const tcpServer = createServer();
      tcpServer.on("error", (error) => {
        log(`gateway tcp listen error: ${error.message}`);
        process.nextTick(() => process.exit(1));
      });
      tcpServer.listen(port, portHost, () => {
        log(`gateway tcp listening on ${portHost}:${port}; upstream=http://${upstreamHost}:${upstreamPort}`);
      });
      servers.push(tcpServer);
    }
    return servers;
  }

  return { listen, pairing, sessions, adminSessions };
}

function startFromEnv() {
  createGateway({
    prefix: process.env.GATEWAY_PREFIX || DEFAULT_PREFIX,
    socketPath: process.env.SOCKET_PATH || "",
    portHost: process.env.GATEWAY_HOST || "0.0.0.0",
    port: process.env.GATEWAY_PORT || 3081,
    pathGatewayPort: process.env.GATEWAY_PATH_PORT || 5666,
    upstreamHost: process.env.UPSTREAM_HOST || "127.0.0.1",
    upstreamPort: process.env.UPSTREAM_PORT || 3080,
    dataDir: process.env.GATEWAY_DATA_DIR || process.cwd(),
    sessionMaxAgeSeconds: process.env.GATEWAY_SESSION_MAX_AGE_SECONDS,
    adminSessionMaxAgeSeconds: process.env.GATEWAY_ADMIN_SESSION_MAX_AGE_SECONDS,
    adminPasswordFile: process.env.GATEWAY_ADMIN_PASSWORD_FILE,
    pairingTtlMs: process.env.GATEWAY_PAIRING_TTL_MS,
    writableDirs: String(process.env.GATEWAY_WRITABLE_DIRS || "").split(":"),
    logFile: process.env.GATEWAY_LOGFILE,
    accessLogFile: process.env.GATEWAY_ACCESS_LOGFILE,
    installLog: process.env.INSTALL_LOGFILE,
    gatewayInstallLog: process.env.GATEWAY_INSTALL_LOGFILE,
    dshLog: process.env.DSH_LOGFILE,
    marketLog: process.env.MARKET_LOGFILE,
  }).listen();
}

if (require.main === module) startFromEnv();

module.exports = { createGateway, startFromEnv, COOKIE_NAME, ADMIN_COOKIE_NAME };
