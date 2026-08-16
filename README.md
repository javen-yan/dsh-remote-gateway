# DeepSeek Harness fnOS Gateway

Authenticated fnOS gateway plugin for DeepSeek Harness Web UI.

This package is consumed by the fnOS Full FPK build as a Git dependency:

```json
"@fnos/deepseek-harness-gateway": "git+https://github.com/javen-yan/dsh-remote-gateway.git"
```

The fnOS package embeds this plugin under `runtime/node_modules` during the
runtime build. The NAS device installs the already-bundled local copy with:

```sh
dsh plugin --profile web add file:$TRIM_APPDEST/runtime/node_modules/@fnos/deepseek-harness-gateway
```

The gateway supports:

- path mode through fnOS App Center: `/app/deepseek_harness/`
- port mode through LAN: `http://<NAS_IP>:3081/`
- separate admin login and device pairing sessions
- loopback proxying to the Harness process on `127.0.0.1:3080`
