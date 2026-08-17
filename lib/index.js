import crypto from "node:crypto";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { AdminAuth } = require("./admin-auth.cjs");

export const name = "fnos-access";
export const inject = ["webServer"];

const COOKIE_NAME = "fnos_dsh_access";
const SESSION_TTL_MS = Number(process.env.FNOS_ACCESS_SESSION_MAX_AGE_SECONDS || 30 * 24 * 60 * 60) * 1000;
const WS_TICKET_TTL_MS = 5 * 60 * 1000;
const sessions = new Map();
const wsTickets = new Map();

function now() {
  return Date.now();
}

function normalizePrefix(prefix) {
  const raw = String(prefix || "").trim();
  if (!raw || raw === "/") return "";
  return raw.startsWith("/") ? raw.replace(/\/+$/, "") : `/${raw.replace(/\/+$/, "")}`;
}

function parseCookies(header) {
  const result = {};
  for (const part of String(header || "").split(";")) {
    const index = part.indexOf("=");
    if (index <= 0) continue;
    result[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
  }
  return result;
}

function uaHash(req) {
  return crypto.createHash("sha256").update(String(req.headers["user-agent"] || "")).digest("base64url");
}

function remoteAddress(req) {
  return String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown").split(",")[0].trim();
}

function randomToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function tokenHash(token) {
  return crypto.createHash("sha256").update(String(token || "")).digest("base64url");
}

function cleanup() {
  const cutoff = now();
  for (const [token, session] of sessions) {
    if (session.expiresAt <= cutoff) sessions.delete(token);
  }
  for (const [ticket, record] of wsTickets) {
    if (record.expiresAt <= cutoff) wsTickets.delete(ticket);
  }
}

function activeSession(req) {
  cleanup();
  const token = parseCookies(req.headers.cookie)[COOKIE_NAME];
  if (!token) return null;
  const session = sessions.get(token);
  if (!session || session.expiresAt <= now() || session.ua !== uaHash(req)) {
    sessions.delete(token);
    return null;
  }
  return { token, session };
}

function setCookie(res, name, value, maxAgeSeconds, req) {
  const secure = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim() === "https";
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (secure) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearCookie(res, req) {
  setCookie(res, COOKIE_NAME, "", 0, req);
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, headers);
  res.end(body);
}

function sendJson(res, status, data) {
  send(res, status, JSON.stringify(data), {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
}

function redirect(res, location) {
  send(res, 302, "", { location, "cache-control": "no-store" });
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => {
      chunks.push(chunk);
      if (Buffer.concat(chunks).length > 8192) {
        reject(new Error("body_too_large"));
        req.destroy();
      }
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function loginPage(prefix, next, message = "") {
  const action = `${prefix}/fnos-access/login`;
  const safeNext = escapeHtml(next || `${prefix}/`);
  const safeMessage = message
    ? `<p class="error">${escapeHtml(message)}</p>`
    : "";
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DeepSeek Harness</title>
  <style>
    :root { color-scheme: light dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f6f7f9; color: #191b1f; }
    @media (prefers-color-scheme: dark) { body { background: #18191d; color: #f2f3f5; } .panel { background: #202227; border-color: #33363d; } input { background: #18191d; color: #f2f3f5; border-color: #3b3e46; } }
    .panel { width: min(360px, calc(100vw - 48px)); padding: 32px; border: 1px solid #dedfe3; border-radius: 20px; background: #fff; box-shadow: 0 18px 50px rgba(0,0,0,.08); }
    h1 { margin: 0 0 24px; font-size: 24px; line-height: 1.25; letter-spacing: 0; }
    label { display: block; margin-bottom: 8px; color: #7b7f89; font-size: 14px; }
    input { width: 100%; box-sizing: border-box; height: 44px; border: 1px solid #d7d9df; border-radius: 12px; padding: 0 14px; font-size: 16px; outline: none; }
    input:focus { border-color: #4f6bff; box-shadow: 0 0 0 3px rgba(79,107,255,.14); }
    button { width: 100%; height: 44px; margin-top: 16px; border: 0; border-radius: 12px; background: #4f6bff; color: #fff; font-size: 16px; font-weight: 650; cursor: pointer; }
    .error { margin: 0 0 14px; color: #d54545; font-size: 14px; }
  </style>
</head>
<body>
  <main class="panel">
    <h1>DeepSeek Harness</h1>
    ${safeMessage}
    <form method="post" action="${action}">
      <input type="hidden" name="next" value="${safeNext}">
      <label for="password">管理密码</label>
      <input id="password" name="password" type="password" autocomplete="current-password" autofocus required>
      <button type="submit">登录</button>
    </form>
  </main>
</body>
</html>`;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[char]));
}

function absoluteExternalPath(req, prefix, pathname) {
  const raw = String(req.headers["x-fnos-external-uri"] || req.url || "/");
  const current = new URL(raw, "http://fnos.local");
  const next = new URL(pathname, "http://fnos.local");
  if (prefix && !next.pathname.startsWith(prefix)) {
    next.pathname = `${prefix}${next.pathname}`;
  }
  next.search = current.search;
  return `${next.pathname}${next.search}`;
}

function injectIndex(html, prefix) {
  const safePrefix = JSON.stringify(prefix);
  const shim = `<script>
(function () {
  var prefix = ${safePrefix};
  function shouldRewrite(pathname) {
    return /^\\/(api|assets|plugins)(\\/|$)/.test(pathname) || pathname === "/favicon.svg" || pathname === "/manifest.webmanifest";
  }
  function withPrefix(value) {
    if (!prefix || typeof value !== "string") return value;
    if (value.charAt(0) === "/") {
      if (value.indexOf(prefix + "/") === 0 || value === prefix) return value;
      return shouldRewrite(value) ? prefix + value : value;
    }
    try {
      var url = new URL(value, location.href);
      if (url.host === location.host && shouldRewrite(url.pathname) && url.pathname.indexOf(prefix + "/") !== 0 && url.pathname !== prefix) {
        url.pathname = prefix + url.pathname;
        return url.href;
      }
    } catch (_) {}
    return value;
  }
  if (globalThis.__DSH_BOOT__ && Array.isArray(globalThis.__DSH_BOOT__.entries)) {
    globalThis.__DSH_BOOT__.entries = globalThis.__DSH_BOOT__.entries.map(function (entry) {
      if (!entry || typeof entry.url !== "string") return entry;
      var next = Object.assign({}, entry);
      next.url = withPrefix(entry.url);
      return next;
    });
  }
  if (!globalThis.crypto) globalThis.crypto = {};
  if (typeof globalThis.crypto.randomUUID !== "function") {
    globalThis.crypto.randomUUID = function () {
      return "10000000-1000-4000-8000-100000000000".replace(/[018]/g, function (c) {
        return (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16);
      });
    };
  }
  var originalFetch = globalThis.fetch;
  if (originalFetch) {
    globalThis.fetch = function (input, init) {
      if (typeof input === "string") input = withPrefix(input);
      else if (input && typeof input.url === "string") input = new Request(withPrefix(input.url), input);
      return originalFetch.call(this, input, init);
    };
  }
  var originalEventSource = globalThis.EventSource;
  if (originalEventSource) {
    globalThis.EventSource = function (url, options) {
      return new originalEventSource(withPrefix(url), options);
    };
    globalThis.EventSource.prototype = originalEventSource.prototype;
  }
  function wsTicket() {
    var xhr = new XMLHttpRequest();
    xhr.open("POST", withPrefix("/fnos-access/ws-ticket"), false);
    xhr.setRequestHeader("content-type", "application/json");
    xhr.send("{}");
    if (xhr.status !== 200) return "";
    try { return JSON.parse(xhr.responseText).ticket || ""; } catch (_) { return ""; }
  }
  var originalWebSocket = globalThis.WebSocket;
  if (originalWebSocket) {
    globalThis.WebSocket = function (url, protocols) {
      var next = typeof url === "string" ? url : String(url);
      if (next.indexOf("/api/events.") !== -1) {
        next = withPrefix(next);
        var ticket = wsTicket();
        if (ticket) next += (next.indexOf("?") === -1 ? "?" : "&") + "__fnos_dsh_ws=" + encodeURIComponent(ticket);
      }
      return protocols === undefined ? new originalWebSocket(next) : new originalWebSocket(next, protocols);
    };
    globalThis.WebSocket.prototype = originalWebSocket.prototype;
    Object.defineProperty(globalThis.WebSocket, "CONNECTING", { value: originalWebSocket.CONNECTING });
    Object.defineProperty(globalThis.WebSocket, "OPEN", { value: originalWebSocket.OPEN });
    Object.defineProperty(globalThis.WebSocket, "CLOSING", { value: originalWebSocket.CLOSING });
    Object.defineProperty(globalThis.WebSocket, "CLOSED", { value: originalWebSocket.CLOSED });
  }
})();</script>`;
  const rewritten = prefix ? html
    .replaceAll('"/plugins/', `"${prefix}/plugins/`)
    .replaceAll('"/assets/', `"${prefix}/assets/`)
    .replaceAll('href="/assets/', `href="${prefix}/assets/`)
    .replaceAll('src="/assets/', `src="${prefix}/assets/`)
    .replaceAll('href="/plugins/', `href="${prefix}/plugins/`)
    .replaceAll('src="/plugins/', `src="${prefix}/plugins/`)
    .replaceAll('href="/favicon.svg"', `href="${prefix}/favicon.svg"`)
    .replaceAll('href="/manifest.webmanifest"', `href="${prefix}/manifest.webmanifest"`)
    : html;
  return rewritten.includes("</head>") ? rewritten.replace("</head>", `${shim}</head>`) : `${shim}${rewritten}`;
}

function publicPath(pathname) {
  return pathname === "/fnos-access/login" || pathname === "/fnos-access/logout" || pathname === "/fnos-access/ws-ticket";
}

function rejectRequest(req, res, prefix) {
  const pathname = new URL(req.url || "/", "http://fnos.local").pathname;
  const acceptsHtml = String(req.headers.accept || "").includes("text/html");
  if (acceptsHtml && !pathname.startsWith("/api/")) {
    const next = encodeURIComponent(String(req.headers["x-fnos-external-uri"] || req.url || "/"));
    redirect(res, `${prefix}/fnos-access/login?next=${next}`);
    return;
  }
  sendJson(res, 401, { error: "unauthorized" });
}

export function apply(ctx) {
  const prefix = normalizePrefix(process.env.FNOS_ACCESS_PREFIX || "");
  const passwordFile = process.env.FNOS_ACCESS_PASSWORD_FILE || "";
  const auth = new AdminAuth({
    file: passwordFile,
    log: (message) => ctx.logger?.info?.(`[fnos-access] ${message}`),
  });

  function authenticate(req) {
    return Boolean(activeSession(req));
  }

  function authenticateTicket(req) {
    cleanup();
    const url = new URL(req.url || "/", "http://fnos.local");
    const ticket = url.searchParams.get("__fnos_dsh_ws");
    if (!ticket) return false;
    const record = wsTickets.get(ticket);
    if (!record || record.expiresAt <= now() || record.ua !== uaHash(req)) {
      wsTickets.delete(ticket);
      return false;
    }
    return true;
  }

  const gate = (req, surface) => {
    const pathname = new URL(req.url || "/", "http://fnos.local").pathname;
    if (publicPath(pathname)) return true;
    if (surface && String(surface.surface || surface).includes("websocket") && authenticateTicket(req)) return true;
    return authenticate(req);
  };

  ctx.webServer.fnosAccessGate = gate;
  ctx.webServer.fnosAccessPrefix = prefix;
  ctx.effect(() => ctx.webServer.tapIndex((html) => injectIndex(html, prefix)), "fnos-access: index shim");

  ctx.effect(() => ctx.webServer.register({ kind: "prefix", path: "/fnos-access", handler: async (req, res) => {
    const url = new URL(req.url || "/", "http://fnos.local");
    if (url.pathname === "/fnos-access/logout") {
      clearCookie(res, req);
      redirect(res, `${prefix}/fnos-access/login`);
      return;
    }
    if (url.pathname === "/fnos-access/ws-ticket") {
      const session = activeSession(req);
      if (!session) {
        sendJson(res, 401, { error: "unauthorized" });
        return;
      }
      const ticket = randomToken();
      wsTickets.set(ticket, {
        tokenHash: tokenHash(session.token),
        ua: uaHash(req),
        expiresAt: now() + WS_TICKET_TTL_MS,
      });
      sendJson(res, 200, { ticket, expiresAt: Date.now() + WS_TICKET_TTL_MS });
      return;
    }
    if (url.pathname !== "/fnos-access/login") {
      sendJson(res, 404, { error: "not_found" });
      return;
    }
    if (!auth.isConfigured()) {
      send(res, 503, loginPage(prefix, `${prefix}/`, "请先在 fnOS 应用配置中设置管理密码。"), {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
      });
      return;
    }
    const next = url.searchParams.get("next") || `${prefix}/`;
    if (req.method === "GET") {
      send(res, 200, loginPage(prefix, next), {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
      });
      return;
    }
    if (req.method !== "POST") {
      sendJson(res, 405, { error: "method_not_allowed" });
      return;
    }
    const body = new URLSearchParams(await parseBody(req));
    const result = auth.verify(body.get("password") || "", remoteAddress(req));
    if (!result.ok) {
      send(res, 401, loginPage(prefix, body.get("next") || next, "密码不正确，请重试。"), {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
      });
      return;
    }
    const token = randomToken();
    sessions.set(token, {
      ua: uaHash(req),
      createdAt: now(),
      expiresAt: now() + SESSION_TTL_MS,
    });
    setCookie(res, COOKIE_NAME, token, Math.floor(SESSION_TTL_MS / 1000), req);
    redirect(res, body.get("next") || next || `${prefix}/`);
  }}), "fnos-access: login routes");

  ctx.effect(() => () => {
    if (ctx.webServer.fnosAccessGate === gate) delete ctx.webServer.fnosAccessGate;
    if (ctx.webServer.fnosAccessPrefix === prefix) delete ctx.webServer.fnosAccessPrefix;
  });
}
