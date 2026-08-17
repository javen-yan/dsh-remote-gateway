# DSH fnOS Access

Shared fnOS edge access layer for DeepSeek Harness.

This package is not installed into a DSH profile. It is bundled in the fnOS FPK
as an outer edge proxy dependency.

## fnOS Runtime

The fnOS FPK starts DSH on `127.0.0.1:3080` and starts this proxy on the App
Center URL entry port, normally `0.0.0.0:3081`.

## Access Model

- Entry: `http://<NAS_IP>:3081/`
- DSH upstream: `http://127.0.0.1:3080`
- Login page: `/fnos-access/login`
- Cookie: `fnos_dsh_access`, HttpOnly, SameSite=Lax

After login, the proxy forwards DSH's native root-path API, plugin bundles,
assets, SSE, and WebSocket traffic unchanged. It does not patch official DSH
server packages and does not rewrite path prefixes.
