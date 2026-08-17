#!/usr/bin/env node
const fs = require("fs");
const path = require("path");

const nodeModules = process.argv[2] || "node_modules";
const root = path.resolve(nodeModules);

function read(file) {
  return fs.readFileSync(file, "utf8");
}

function write(file, text) {
  fs.writeFileSync(file, text);
}

function patchOnce(file, marker, anchor, replacement) {
  let text = read(file);
  if (text.includes(marker)) return;
  if (!text.includes(anchor)) {
    throw new Error(`Patch anchor not found in ${file}: ${anchor.slice(0, 100)}`);
  }
  text = text.replace(anchor, replacement);
  write(file, text);
}

function sanitizeOldFnosPatch(file) {
  let text = read(file);
  text = text.replace(
    `\t\t// fnOS patch: allow trusted-host authorities to access the Web configuration plane.\n\t\tif (method !== void 0 && PRIVILEGED_METHODS.has(method) && !isTrustedApiRequest(request, trustedHosts)) return new Response("forbidden", { status: 403 });`,
    `\t\tif (method !== void 0 && PRIVILEGED_METHODS.has(method) && !isTrustedApiRequest(request, [])) return new Response("forbidden", { status: 403 });`
  );
  write(file, text);
}

const connectionFile = path.join(root, "@deepseek-ai/dsh-client-connection/lib/index.js");
const modulesFile = path.join(root, "@deepseek-ai/dsh-client-modules/lib/index.js");
const hmrFile = path.join(root, "@deepseek-ai/dsh-client-hmr/lib/index.js");
const webserverFile = path.join(root, "@deepseek-ai/dsh-host-webserver/lib/index.js");

sanitizeOldFnosPatch(connectionFile);

patchOnce(
  webserverFile,
  "[fnos-access patch] fallback gate",
  `\t\t\tawait fallback(req, res);`,
  `\t\t\tconst gate = this.fnosAccessGate;
\t\t\tif (typeof gate === "function" && !gate(req, { surface: "fallback" })) {
\t\t\t\tconst acceptsHtml = String(req.headers.accept || "").includes("text/html");
\t\t\t\tif (acceptsHtml) {
\t\t\t\t\tconst prefix = String(req.headers["x-fnos-external-prefix"] || "");
\t\t\t\t\tconst next = encodeURIComponent(String(req.headers["x-fnos-external-uri"] || req.url || "/"));
\t\t\t\t\tres.writeHead(302, { location: \`\${prefix}/fnos-access/login?next=\${next}\`, "cache-control": "no-store" });
\t\t\t\t\tres.end();
\t\t\t\t} else {
\t\t\t\t\tres.writeHead(401, { "content-type": "application/json; charset=utf-8" });
\t\t\t\t\tres.end(JSON.stringify({ error: "unauthorized" }));
\t\t\t\t}
\t\t\t\treturn;
\t\t\t}
\t\t\t// [fnos-access patch] fallback gate
\t\t\tawait fallback(req, res);`
);

patchOnce(
  connectionFile,
  "[fnos-access patch] shared gate",
  `function rejectWebSocketUpgrade(socket) {
\tsocket.end([
\t\t"HTTP/1.1 403 Forbidden",
\t\t"Connection: close",
\t\t"Content-Type: text/plain; charset=utf-8",
\t\t"Content-Length: 9",
\t\t"",
\t\t"forbidden"
\t].join("\\r\\n"));
}
//#endregion`,
  `function rejectWebSocketUpgrade(socket) {
\tsocket.end([
\t\t"HTTP/1.1 403 Forbidden",
\t\t"Connection: close",
\t\t"Content-Type: text/plain; charset=utf-8",
\t\t"Content-Length: 9",
\t\t"",
\t\t"forbidden"
\t].join("\\r\\n"));
}
function fnosAccessAllowed(webServer, req, surface) {
\tconst gate = webServer && webServer.fnosAccessGate;
\treturn typeof gate !== "function" || gate(req, surface);
}
//#endregion
// [fnos-access patch] shared gate`
);

patchOnce(
  connectionFile,
  "[fnos-access patch] api gate",
  `\t\thandler: async (req, res) => {
\t\t\tif (!isTrustedApiRequest(req, trustedHosts)) {`,
  `\t\thandler: async (req, res) => {
\t\t\tif (!fnosAccessAllowed(ctx.webServer, req, { surface: "api" })) {
\t\t\t\tres.writeHead(401, { "content-type": "application/json; charset=utf-8" });
\t\t\t\tres.end(JSON.stringify({ error: "unauthorized" }));
\t\t\t\treturn;
\t\t\t}
\t\t\t// [fnos-access patch] api gate
\t\t\tif (!isTrustedApiRequest(req, trustedHosts)) {`
);

patchOnce(
  connectionFile,
  "[fnos-access patch] websocket gate",
  `\t\t\t\thandler: (req, socket, head) => {
\t\t\t\t\tif (!isTrustedApiRequest(req, trustedHosts)) {`,
  `\t\t\t\thandler: (req, socket, head) => {
\t\t\t\t\tif (!fnosAccessAllowed(apiCtx.webServer, req, { surface: "websocket" })) {
\t\t\t\t\t\trejectWebSocketUpgrade(socket);
\t\t\t\t\t\treturn;
\t\t\t\t\t}
\t\t\t\t\t// [fnos-access patch] websocket gate
\t\t\t\t\tif (!isTrustedApiRequest(req, trustedHosts)) {`
);

patchOnce(
  modulesFile,
  "[fnos-access patch] boot graph prefix",
  `function injectBootManifest(html, graph) {
\tconst script = \`<script>window.__DSH_BOOT__ = \${JSON.stringify(graph).replaceAll("<", "\\\\u003c")}<\\/script>\`;`,
  `function injectBootManifest(html, graph, prefix = "") {
\tconst bootGraph = prefix ? {
\t\t...graph,
\t\tentries: graph.entries.map((entry) => entry.url?.startsWith("/plugins/") ? {
\t\t\t...entry,
\t\t\turl: \`\${prefix}\${entry.url}\`
\t\t} : entry)
\t} : graph;
\t// [fnos-access patch] boot graph prefix
\tconst script = \`<script>window.__DSH_BOOT__ = \${JSON.stringify(bootGraph).replaceAll("<", "\\\\u003c")}<\\/script>\`;`
);

patchOnce(
  modulesFile,
  "[fnos-access patch] boot graph prefix source",
  `ctx.effect(() => ctx.webServer.tapIndex((html) => injectBootManifest(html, this.composed)), "client-modules: boot manifest injection");`,
  `ctx.effect(() => ctx.webServer.tapIndex((html) => injectBootManifest(html, this.composed, ctx.webServer.fnosAccessPrefix || "")), "client-modules: boot manifest injection");
\t\t// [fnos-access patch] boot graph prefix source`
);

patchOnce(
  modulesFile,
  "[fnos-access patch] plugin bundle gate",
  `\tserveBundle = async (req, res) => {
\t\tif (req.method !== "GET" && req.method !== "HEAD") {`,
  `\tserveBundle = async (req, res) => {
\t\tconst gate = this.ctx.webServer && this.ctx.webServer.fnosAccessGate;
\t\tif (typeof gate === "function" && !gate(req, { surface: "plugins" })) {
\t\t\tres.writeHead(401, { "content-type": "application/json; charset=utf-8" });
\t\t\tres.end(JSON.stringify({ error: "unauthorized" }));
\t\t\treturn;
\t\t}
\t\t// [fnos-access patch] plugin bundle gate
\t\tif (req.method !== "GET" && req.method !== "HEAD") {`
);

patchOnce(
  hmrFile,
  "[fnos-access patch] plugin events gate",
  `\t\t\thandler: (req, res) => {
\t\t\t\tif (req.method !== "GET" && req.method !== "HEAD") {`,
  `\t\t\thandler: (req, res) => {
\t\t\t\tconst gate = ctx.webServer.fnosAccessGate;
\t\t\t\tif (typeof gate === "function" && !gate(req, { surface: "plugins-events" })) {
\t\t\t\t\tres.writeHead(401, { "content-type": "application/json; charset=utf-8" });
\t\t\t\t\tres.end(JSON.stringify({ error: "unauthorized" }));
\t\t\t\t\treturn;
\t\t\t\t}
\t\t\t\t// [fnos-access patch] plugin events gate
\t\t\t\tif (req.method !== "GET" && req.method !== "HEAD") {`
);

for (const [file, marker] of [
  [webserverFile, "[fnos-access patch] fallback gate"],
  [connectionFile, "[fnos-access patch] shared gate"],
  [connectionFile, "[fnos-access patch] api gate"],
  [connectionFile, "[fnos-access patch] websocket gate"],
  [modulesFile, "[fnos-access patch] boot graph prefix"],
  [modulesFile, "[fnos-access patch] boot graph prefix source"],
  [modulesFile, "[fnos-access patch] plugin bundle gate"],
  [hmrFile, "[fnos-access patch] plugin events gate"],
]) {
  if (!read(file).includes(marker)) throw new Error(`Missing marker after patch: ${marker}`);
}

if (read(connectionFile).includes("fnOS patch: allow trusted-host authorities")) {
  throw new Error("Old fnOS trusted-host patch marker is still present.");
}
