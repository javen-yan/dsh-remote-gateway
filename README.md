# DSH fnOS Access

Shared fnOS access layer for DeepSeek Harness.

This package contains two pieces:

- a DSH web plugin, `@fnos/dsh-fnos-access`, installed into the `web` profile
- a thin edge proxy used by fnOS to expose either the App Center path entry or a LAN port entry

The proxy does not implement DSH business APIs. It only strips the fnOS path
prefix, forwards HTTP/WebSocket traffic to `127.0.0.1:3080`, and normalizes
`Host`/`Origin` to loopback. Authentication, path-prefix shims, the LAN
`crypto.randomUUID` polyfill, and route gating live inside the DSH plugin.

## fnOS Runtime

The fnOS FPK installs the bundled plugin with:

```sh
dsh plugin --profile web add file:$TRIM_APPDEST/runtime/node_modules/@fnos/dsh-fnos-access
```

The runtime build then patches official DSH route packages with deterministic
gate markers:

- fallback HTML/static gate
- `/api` RPC gate
- WebSocket upgrade gate
- `/plugins` bundle gate
- `/plugins/events` SSE gate

The build fails if any marker is missing.

## Access Model

- Path mode: `http://<NAS_IP>:5666/app/deepseek_harness/`
- Port mode: `http://<NAS_IP>:3081/`
- DSH upstream: `http://127.0.0.1:3080`
- Login page: `/fnos-access/login`
- Cookie: `fnos_dsh_access`, HttpOnly, SameSite=Lax

There is no pair-code flow. The browser signs in once with the management
password configured through the fnOS app settings, then continues directly into
the official DeepSeek Harness Web UI.
