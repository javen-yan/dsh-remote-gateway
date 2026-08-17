const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const net = require("net");
const { AdminAuth } = require("./admin-auth.cjs");

const COOKIE_NAME = "fnos_dsh_access";

function log(file, message) {
  const line = `${new Date().toISOString()} ${message}\n`;
  if (file) fs.appendFile(file, line, () => {});
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

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[char]));
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > 8192) {
        reject(new Error("body_too_large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function loginPage(next, message = "") {
  const safeNext = escapeHtml(next || "/");
  const safeMessage = message ? `<p class="error">${escapeHtml(message)}</p>` : "";
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
    <form method="post" action="/fnos-access/login">
      <input type="hidden" name="next" value="${safeNext}">
      <label for="password">管理密码</label>
      <input id="password" name="password" type="password" autocomplete="current-password" autofocus required>
      <button type="submit">登录</button>
    </form>
  </main>
</body>
</html>`;
}

function polyfillScript() {
  return `<script>
(function () {
  var root = globalThis;
  var cryptoObject = root.crypto || {};
  var getRandomValues = typeof cryptoObject.getRandomValues === "function"
    ? cryptoObject.getRandomValues.bind(cryptoObject)
    : function (array) {
        for (var index = 0; index < array.length; index += 1) {
          array[index] = Math.floor(Math.random() * 256);
        }
        return array;
      };
  function randomUUID() {
    var bytes = new Uint8Array(16);
    getRandomValues(bytes);
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    var hex = [];
    for (var index = 0; index < 256; index += 1) {
      hex[index] = (index + 256).toString(16).slice(1);
    }
    return (
      hex[bytes[0]] + hex[bytes[1]] + hex[bytes[2]] + hex[bytes[3]] + "-" +
      hex[bytes[4]] + hex[bytes[5]] + "-" +
      hex[bytes[6]] + hex[bytes[7]] + "-" +
      hex[bytes[8]] + hex[bytes[9]] + "-" +
      hex[bytes[10]] + hex[bytes[11]] + hex[bytes[12]] + hex[bytes[13]] + hex[bytes[14]] + hex[bytes[15]]
    );
  }
  if (typeof cryptoObject.randomUUID !== "function") {
    try {
      Object.defineProperty(cryptoObject, "randomUUID", { configurable: true, value: randomUUID });
    } catch (_) {
      cryptoObject.randomUUID = randomUUID;
    }
  }
  if (!root.crypto) {
    try {
      Object.defineProperty(root, "crypto", { configurable: true, value: cryptoObject });
    } catch (_) {
      root.crypto = cryptoObject;
    }
  }
})();</script>`;
}

function injectHtml(html) {
  const script = polyfillScript();
  const headMatch = html.match(/<head[^>]*>/i);
  if (headMatch?.index !== undefined) {
    const insertAt = headMatch.index + headMatch[0].length;
    return `${html.slice(0, insertAt)}${script}${html.slice(insertAt)}`;
  }
  return html.includes("</head>") ? html.replace("</head>", `${script}</head>`) : `${script}${html}`;
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

function destroyQuietly(stream) {
  if (!stream || stream.destroyed) return;
  try { stream.destroy(); } catch {}
}

function endWithGatewayError(res) {
  if (res.destroyed || res.writableEnded) return;
  if (!res.headersSent) {
    res.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
  }
  res.end("DeepSeek Harness is not ready.");
}

function proxyHeaders(req, upstreamHost, upstreamPort) {
  const headers = { ...req.headers };
  headers.host = `${upstreamHost}:${upstreamPort}`;
  headers.origin = `http://${upstreamHost}:${upstreamPort}`;
  headers["x-forwarded-host"] = req.headers.host || "";
  headers["x-forwarded-proto"] = req.socket.encrypted ? "https" : "http";
  return headers;
}

function isHtmlResponse(headers) {
  return String(headers["content-type"] || "").toLowerCase().includes("text/html");
}

function activeSession(req, sessions) {
  const current = Date.now();
  for (const [token, session] of sessions) {
    if (session.expiresAt <= current) sessions.delete(token);
  }
  const token = parseCookies(req.headers.cookie)[COOKIE_NAME];
  if (!token) return null;
  const session = sessions.get(token);
  if (!session || session.expiresAt <= Date.now() || session.ua !== uaHash(req)) {
    sessions.delete(token);
    return null;
  }
  return session;
}

function rejectUnauthenticated(req, res) {
  const pathname = new URL(req.url || "/", "http://dsh.local").pathname;
  const acceptsHtml = String(req.headers.accept || "").includes("text/html");
  if (acceptsHtml && !pathname.startsWith("/api/") && !pathname.startsWith("/plugins/")) {
    redirect(res, `/fnos-access/login?next=${encodeURIComponent(req.url || "/")}`);
    return;
  }
  sendJson(res, 401, { error: "unauthorized" });
}

async function handleAccessRoute(req, res, auth, sessions, sessionMaxAgeSeconds) {
  const url = new URL(req.url || "/", "http://dsh.local");
  if (url.pathname === "/fnos-access/logout") {
    setCookie(res, COOKIE_NAME, "", 0, req);
    redirect(res, "/fnos-access/login");
    return true;
  }
  if (url.pathname !== "/fnos-access/login") return false;

  if (!auth.isConfigured()) {
    send(res, 503, loginPage("/", "请先在 fnOS 应用配置中设置管理密码。"), {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    });
    return true;
  }

  const next = url.searchParams.get("next") || "/";
  if (req.method === "GET") {
    send(res, 200, loginPage(next), {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    });
    return true;
  }
  if (req.method !== "POST") {
    sendJson(res, 405, { error: "method_not_allowed" });
    return true;
  }

  const body = new URLSearchParams(await parseBody(req));
  const result = auth.verify(body.get("password") || "", remoteAddress(req));
  if (!result.ok) {
    send(res, 401, loginPage(body.get("next") || next, "密码不正确，请重试。"), {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    });
    return true;
  }

  const token = randomToken();
  sessions.set(token, {
    ua: uaHash(req),
    createdAt: Date.now(),
    expiresAt: Date.now() + sessionMaxAgeSeconds * 1000,
  });
  setCookie(res, COOKIE_NAME, token, sessionMaxAgeSeconds, req);
  redirect(res, body.get("next") || next || "/");
  return true;
}

function proxyRequest(req, res, options, logfile, accessLogfile) {
  const upstream = http.request(options, (upstreamRes) => {
    const headers = { ...upstreamRes.headers };
    delete headers["content-length"];
    if (!isHtmlResponse(headers)) {
      res.writeHead(upstreamRes.statusCode || 502, headers);
      upstreamRes.on("error", (error) => {
        log(logfile, `http upstream response error ${req.method} ${req.url}: ${error.message}`);
        destroyQuietly(res);
      });
      upstreamRes.pipe(res);
      log(accessLogfile, `${req.method} ${req.url} -> ${upstreamRes.statusCode}`);
      return;
    }

    const chunks = [];
    upstreamRes.on("data", (chunk) => chunks.push(chunk));
    upstreamRes.on("end", () => {
      const body = injectHtml(Buffer.concat(chunks).toString("utf8"));
      headers["content-type"] = headers["content-type"] || "text/html; charset=utf-8";
      res.writeHead(upstreamRes.statusCode || 502, headers);
      res.end(body);
      log(accessLogfile, `${req.method} ${req.url} -> ${upstreamRes.statusCode}`);
    });
    upstreamRes.on("error", (error) => {
      log(logfile, `http upstream response error ${req.method} ${req.url}: ${error.message}`);
      destroyQuietly(res);
    });
  });
  upstream.on("error", (error) => {
    log(logfile, `http proxy error ${req.method} ${req.url}: ${error.message}`);
    endWithGatewayError(res);
  });
  req.on("error", (error) => {
    log(logfile, `http client request error ${req.method} ${req.url}: ${error.message}`);
    destroyQuietly(upstream);
  });
  req.on("aborted", () => {
    log(logfile, `http client aborted ${req.method} ${req.url}`);
    destroyQuietly(upstream);
  });
  res.on("error", (error) => {
    log(logfile, `http client response error ${req.method} ${req.url}: ${error.message}`);
    destroyQuietly(upstream);
  });
  res.on("close", () => {
    if (!res.writableEnded) destroyQuietly(upstream);
  });
  req.pipe(upstream);
}

function startFromEnv() {
  const upstreamHost = process.env.UPSTREAM_HOST || "127.0.0.1";
  const upstreamPort = Number(process.env.UPSTREAM_PORT || 3080);
  const host = process.env.GATEWAY_HOST || "0.0.0.0";
  const port = Number(process.env.GATEWAY_PORT || 3081);
  const logfile = process.env.GATEWAY_LOGFILE || "";
  const accessLogfile = process.env.GATEWAY_ACCESS_LOGFILE || "";
  const passwordFile = process.env.FNOS_ACCESS_PASSWORD_FILE || "";
  const sessionMaxAgeSeconds = Number(process.env.FNOS_ACCESS_SESSION_MAX_AGE_SECONDS || 30 * 24 * 60 * 60);
  const sessions = new Map();
  const auth = new AdminAuth({
    file: passwordFile,
    log: (message) => log(logfile, message),
  });

  const server = http.createServer(async (req, res) => {
    try {
      if (await handleAccessRoute(req, res, auth, sessions, sessionMaxAgeSeconds)) return;
    } catch (error) {
      log(logfile, `access route error ${req.method} ${req.url}: ${error.message}`);
      sendJson(res, 500, { error: "gateway_error" });
      return;
    }

    if (!activeSession(req, sessions)) {
      rejectUnauthenticated(req, res);
      return;
    }

    proxyRequest(req, res, {
      hostname: upstreamHost,
      port: upstreamPort,
      method: req.method,
      path: req.url || "/",
      headers: proxyHeaders(req, upstreamHost, upstreamPort),
    }, logfile, accessLogfile);
  });

  server.on("upgrade", (req, socket, head) => {
    if (!activeSession(req, sessions)) {
      socket.end([
        "HTTP/1.1 401 Unauthorized",
        "Connection: close",
        "Content-Type: application/json; charset=utf-8",
        "Content-Length: 24",
        "",
        '{"error":"unauthorized"}',
      ].join("\r\n"));
      return;
    }

    const upstream = net.connect(upstreamPort, upstreamHost, () => {
      const headers = proxyHeaders(req, upstreamHost, upstreamPort);
      const lines = [`${req.method} ${req.url || "/"} HTTP/${req.httpVersion}`];
      for (const [key, value] of Object.entries(headers)) {
        if (Array.isArray(value)) {
          for (const item of value) lines.push(`${key}: ${item}`);
        } else if (value !== undefined) {
          lines.push(`${key}: ${value}`);
        }
      }
      upstream.write(`${lines.join("\r\n")}\r\n\r\n`);
      if (head && head.length) upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
      log(accessLogfile, `WS ${req.url}`);
    });
    socket.on("error", (error) => {
      log(logfile, `ws client socket error ${req.url}: ${error.message}`);
      destroyQuietly(upstream);
    });
    socket.on("close", () => destroyQuietly(upstream));
    upstream.on("error", (error) => {
      log(logfile, `ws proxy error ${req.url}: ${error.message}`);
      destroyQuietly(socket);
    });
    upstream.on("close", () => destroyQuietly(socket));
  });

  server.on("clientError", (error, socket) => {
    log(logfile, `edge proxy client error: ${error.message}`);
    destroyQuietly(socket);
  });

  server.listen(port, host, () => {
    const address = server.address();
    const actualPort = address && typeof address === "object" ? address.port : port;
    log(logfile, `edge proxy listening on http://${host}:${actualPort}; upstream=http://${upstreamHost}:${upstreamPort}`);
  });
}

module.exports = { startFromEnv };
