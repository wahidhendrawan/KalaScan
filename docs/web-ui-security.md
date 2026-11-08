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
- Every route then needs `Authorization: Bearer <token>`. The dashboard asks for the token once and keeps it in `sessionStorage` (this tab only, never persisted).
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

Submit, cancel, delete, user changes and denied or forbidden requests are written to an append-only `audit_log`.

## What the API will and will not scan

- Remote targets only: Git URLs, `publisher.extension`, marketplace URLs, `npm:` / `pypi:` names. Local paths are refused; upload a package through `POST /api/scan/upload` instead.
- Hosts that resolve to loopback, private, link-local or CGNAT addresses (cloud metadata, admin ports) are refused, for the target and for download redirects, unless `KALASCAN_ALLOW_PRIVATE_TARGETS=1` (an internal Git server).
- Server-side file options (`yara_dir`, `ignore`, `baseline`, `sandbox_image`, `rules`) are CLI-only and rejected by the API.
- Credentials in a repository URL (`https://user:token@host/...`) reach `git` only; logs, the audit log, history and reports show the URL without them. LLM API keys are stripped before a queued request is persisted.
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

Downloads are time- and size-capped; archive extraction counts bytes written (zip bombs) and refuses zip-slip paths and symlinks.

## Response headers

`Content-Security-Policy` (self-hosted assets only, no CDN), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. The UI's CSS is compiled into the binary, so the dashboard works offline.

## Observability

`GET /healthz` (liveness, used by the Docker `HEALTHCHECK`), `GET /metrics` (Prometheus) and `GET /openapi.yaml` are served without a token, like `/` and `/static/`; everything under `/api` requires one.

## Docker

```bash
KALASCAN_TOKEN=change-me docker compose up -d
```

The image runs the same server with the same rules. The opt-in `--sandbox` pass needs Docker and the `kalascan-sandbox` image (`sandbox/Dockerfile`); its `sandbox_image` option is CLI-only.

## Reporting

Vulnerabilities in the server, the API tokens or the sandbox: see [SECURITY.md](../SECURITY.md).
