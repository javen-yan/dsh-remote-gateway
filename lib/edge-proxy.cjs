const fs = require("fs");
const http = require("http");
const net = require("net");

function log(file, message) {
  const line = `${new Date().toISOString()} ${message}\n`;
  if (file) fs.appendFile(file, line, () => {});
}

function normalizePrefix(prefix) {
  const raw = String(prefix || "").trim();
  if (!raw || raw === "/") return "";
  return raw.startsWith("/") ? raw.replace(/\/+$/, "") : `/${raw.replace(/\/+$/, "")}`;
}

function stripPrefix(url, prefix) {
  if (!prefix) return url || "/";
  const raw = url || "/";
  if (raw === prefix) return "/";
  if (raw.startsWith(`${prefix}/`)) return raw.slice(prefix.length) || "/";
  return raw;
}

function rewriteLocation(location, prefix) {
  if (!prefix || !location) return location;
  if (location.startsWith("/")) return `${prefix}${location}`;
  try {
    const url = new URL(location);
    if (url.hostname === "127.0.0.1" || url.hostname === "localhost") {
      url.pathname = `${prefix}${url.pathname}`;
      url.host = "";
      url.protocol = "";
      return `${url.pathname}${url.search}${url.hash}`;
    }
  } catch {
    return location;
  }
  return location;
}

function proxyHeaders(req, upstreamHost, upstreamPort, prefix) {
  const headers = { ...req.headers };
  headers.host = `${upstreamHost}:${upstreamPort}`;
  headers.origin = `http://${upstreamHost}:${upstreamPort}`;
  headers["x-fnos-external-prefix"] = prefix;
  headers["x-fnos-external-uri"] = req.url || "/";
  headers["x-forwarded-host"] = req.headers.host || "";
  headers["x-forwarded-proto"] = req.socket.encrypted ? "https" : "http";
  return headers;
}

function startFromEnv() {
  const upstreamHost = process.env.UPSTREAM_HOST || "127.0.0.1";
  const upstreamPort = Number(process.env.UPSTREAM_PORT || 3080);
  const host = process.env.GATEWAY_HOST || "0.0.0.0";
  const port = Number(process.env.GATEWAY_PORT || 0);
  const socketPath = process.env.SOCKET_PATH || "";
  const prefix = normalizePrefix(process.env.GATEWAY_PREFIX || "");
  const logfile = process.env.GATEWAY_LOGFILE || "";
  const accessLogfile = process.env.GATEWAY_ACCESS_LOGFILE || "";

  const server = http.createServer((req, res) => {
    const upstreamPath = stripPrefix(req.url, prefix);
    const options = {
      hostname: upstreamHost,
      port: upstreamPort,
      method: req.method,
      path: upstreamPath,
      headers: proxyHeaders(req, upstreamHost, upstreamPort, prefix),
    };
    const upstream = http.request(options, (upstreamRes) => {
      const headers = { ...upstreamRes.headers };
      if (headers.location) headers.location = rewriteLocation(headers.location, prefix);
      res.writeHead(upstreamRes.statusCode || 502, headers);
      upstreamRes.pipe(res);
      log(accessLogfile, `${req.method} ${req.url} -> ${upstreamRes.statusCode}`);
    });
    upstream.on("error", (error) => {
      log(logfile, `http proxy error ${req.method} ${req.url}: ${error.message}`);
      if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
      res.end("DeepSeek Harness is not ready.");
    });
    req.pipe(upstream);
  });

  server.on("upgrade", (req, socket, head) => {
    const upstreamPath = stripPrefix(req.url, prefix);
    const upstream = net.connect(upstreamPort, upstreamHost, () => {
      const headers = proxyHeaders(req, upstreamHost, upstreamPort, prefix);
      const lines = [`${req.method} ${upstreamPath} HTTP/${req.httpVersion}`];
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
    upstream.on("error", (error) => {
      log(logfile, `ws proxy error ${req.url}: ${error.message}`);
      socket.destroy();
    });
  });

  if (socketPath) {
    try { fs.rmSync(socketPath, { force: true }); } catch {}
    server.listen(socketPath, () => {
      try { fs.chmodSync(socketPath, 0o666); } catch {}
      log(logfile, `edge proxy listening on unix:${socketPath}; upstream=http://${upstreamHost}:${upstreamPort}; prefix=${prefix || "/"}`);
    });
  } else if (port > 0) {
    server.listen(port, host, () => {
      log(logfile, `edge proxy listening on http://${host}:${port}; upstream=http://${upstreamHost}:${upstreamPort}; prefix=${prefix || "/"}`);
    });
  } else {
    throw new Error("SOCKET_PATH or GATEWAY_PORT must be configured.");
  }
}

module.exports = { startFromEnv };
