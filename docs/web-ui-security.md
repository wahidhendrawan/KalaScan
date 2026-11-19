# Web UI and API security

`kalascan serve` is meant for a workstation or a trusted network. This page condenses what the server enforces and what you must configure. The full API is in `openapi.yaml` (served at `GET /openapi.yaml`).

## Bind and authenticate

```bash
# Loopback, no token: fine for one person on one machine
kalascan serve                                   # 127.0.0.1:3000

# Anything else needs a bearer token or users
KALASCAN_TOKEN=change-me kalascan serve --addr 0.0.0.0:3000
```

- On a non-loopback address the server **refuses to start** without `KALASCAN_TOKEN` or at least one user. `KALASCAN_ALLOW_UNAUTHENTICATED=1` opts out, for a network you fully trust only.
- Every route then needs `Authorization: Bearer <token>`. Whether auth is required is decided once, at startup: a server that started with a token or users keeps answering 401 without valid credentials when its last user is removed or its database cannot be read. The dashboard asks for the token once and keeps it in `sessionStorage` (this tab only, never persisted).
- `KALASCAN_TOKEN` is a legacy admin token. Prefer users:

```bash
kalascan user add ci --role operator      # prints the token once; stored as salted SHA-256
kalascan user list
kalascan user remove ci                   # the token stops working immediately
```

| Role | Can |
|---|---|
| `viewer` | read results and reports (`GET`) |
| `operator` | submit, cancel and delete scans |
| `admin` | everything, plus `GET /api/audit` |

Submit, cancel, delete, user changes and denied or forbidden requests are written to an append-only `audit_log`. Requests without valid credentials cannot fill it or hide other entries: at most 30 of them are logged per minute, the detail of any entry is cut at 512 characters, and `GET /api/audit` returns the newest 200 denied requests next to the newest 200 other entries.

## Browsers and other sites

The dashboard talks to its own origin only. The server sends no CORS headers and answers 403 to any request whose `Origin` is not the host it was addressed to (`Host`, or `X-Forwarded-Host` behind a reverse proxy), so a page on another site cannot queue scans or read results through a visitor's browser, even on a loopback server without a token. Scripts and CI send no `Origin` and are unaffected.

A loopback server without a token or users also answers only requests addressed to `localhost`, `127.0.0.1` or `[::1]` (the `Host` header) on every path, the dashboard page included, which stops DNS rebinding: a page whose domain re-resolves to `127.0.0.1` is same-origin to the browser but still sends its own domain as `Host`. If a local reverse proxy that does its own authentication forwards the public `Host`, configure a token, or set `KALASCAN_ALLOW_UNAUTHENTICATED=1`.

## What the API will and will not scan

- Remote targets only: Git URLs, `publisher.extension`, marketplace URLs, `npm:` / `pypi:` / `crates:` names. Local paths are refused; upload a package through `POST /api/scan/upload` instead. A target is never read from the server's disk: `budget.xlsx` is looked up on the marketplace even when a file of that name sits in the server's working directory.
- Hosts that resolve to loopback, private, link-local or CGNAT addresses (cloud metadata, admin ports) are refused, for the target and for download redirects, unless `KALASCAN_ALLOW_PRIVATE_TARGETS=1` (an internal Git server). An `llm_endpoint` sent with an API scan gets the same check, except the built-in local Ollama and 9Router defaults, and LLM requests do not follow redirects. Registry, marketplace and LLM requests made for an API scan check the address when the connection is opened, so a hostname that resolves to an internal address only later (DNS rebinding) is refused too. An HTTP(S) Git clone is pinned to the address checked when it starts (`http.curloptResolve`, git 2.37 or later) and follows no redirects; an ssh remote is checked once, when the scan is submitted.
- API, upload and resumed scans clone without the server user's git credentials (credential helpers, `~/.netrc`, ssh keys and agent): a private repository needs its credentials in the URL.
- Scans still queued or running when the server stops are resumed at the next start, under the two rules above as they stand then: one that no longer passes is marked `failed: not resumed`. So is a queued upload, because its extracted package is not kept across a stop.
- Server-side file options (`yara_dir`, `ignore`, `baseline`, `sandbox_image`, `rules`) are CLI-only and rejected by the API.
- Credentials in a repository or package URL (`https://user:token@host/...`) reach `git` or the download only; logs, the audit log, history, scan status and reports show the URL without them, also inside the error text of a failed scan. LLM API keys are stripped before a queued request is persisted. The dashboard keeps an AI provider key only when "Remember key in this browser" is switched on: it then sits in that browser's `localStorage`, readable by any script running on the dashboard's origin, and is deleted when the option is switched off.
- `GET /api/sbom?path=...` serves only directories under the server's working directory (canonicalized; 403 outside).

## Limits

| Env var | Default | Purpose |
|---|---|---|
| `KALASCAN_MAX_CONCURRENT_SCANS` | `4` | scans running at once; the rest queue FIFO |
| `KALASCAN_SCAN_TIMEOUT_SECS` | `900` | hard timeout per scan; exceeded scans are marked failed |
| `KALASCAN_SCAN_RATE_LIMIT` | `30` | submissions per minute (HTTP 429 beyond) |
| `KALASCAN_MAX_UPLOAD_MB` | `1024` | upload body cap; `0` disables the limit |
| `KALASCAN_HISTORY_LIMIT` | `500` | scans kept in SQLite; older finished scans are pruned |
| `KALASCAN_MEMORY_SCANS` | `100` | scans kept in the in-memory cache |

At most 64 scans are queued or running at once; further submissions get HTTP 429 until one finishes. A queued upload keeps its extracted package on disk (up to 512 MiB) while it waits.

On Ctrl-C or SIGTERM (`docker stop`) the server stops taking requests and removes the temp dirs of its queued and running scans. A `kill -9` or a crash leaves them in the temp directory.

Downloads are time- and size-capped; archive extraction counts bytes written (zip bombs) and refuses zip-slip paths and symlinks.

## Response headers

`Content-Security-Policy` (self-hosted assets only, no CDN), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. The UI's CSS is compiled into the binary, so the dashboard works offline.

## Observability

`GET /healthz` (liveness, used by the Docker `HEALTHCHECK`), `GET /metrics` (Prometheus) and `GET /openapi.yaml` are served without a token, like `/` and `/static/`; everything under `/api` requires one.

The server log on stderr holds one record per line: a line break inside a logged value (a target URL, a scan id, `git` output) is written as `\r` or `\n`.

## Docker

```bash
KALASCAN_TOKEN=change-me docker compose up -d
```

The image runs the same server with the same rules. The opt-in `--sandbox` pass needs Docker and the `kalascan-sandbox` image (`sandbox/Dockerfile`); its `sandbox_image` option is CLI-only.

## Reporting

Vulnerabilities in the server, the API tokens or the sandbox: see [SECURITY.md](https://github.com/wahidhendrawan/KalaScan/blob/main/SECURITY.md).
