# Architecture

KalaScan is one Rust binary (`src/main.rs`, a thin entry point over the library in `src/lib.rs`) that runs as a CLI scanner, a GitHub Action and an Axum web server, with the same scan pipeline behind all three. This page maps the modules, walks through a scan, and documents the risk score exactly as `calculate_risk_score` in `src/lib.rs` computes it.

## Module map (`src/`)

| Area | Module | Role |
|---|---|---|
| Entry points | `lib.rs` | Scan orchestrator (`execute_scan_in`), CLI dispatch; `main.rs` only calls `kalascan::run()` |
| | `server.rs` | Axum routes, auth and security-header middleware, scan queue, upload endpoint |
| | `commands.rs` | The CLI subcommands (`scan`, `user`, `sbom`, `import`, `deps`, `installed`, `diff`, `rules`) and the text formatter |
| | `cli.rs` | clap definitions: `serve`, `scan`, `user`, `rules`, `sbom`, `installed`, `deps`, `diff`, `import` |
| Target acquisition | `vsix.rs` | Downloads and safely extracts VSIX / Open VSX / JetBrains / CRX / npm / PyPI packages (zip-slip, symlink and size guards); Git URLs are cloned with `git` |
| | `registry.rs` | npm / PyPI registry metadata: manifest confusion, install-script and provenance regressions, lapsed maintainer e-mail domains, AI-vendor repository impersonation |
| | `lockfile.rs` | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `requirements.txt`, `Cargo.lock` parsing for `kalascan deps` |
| Static analysis | `scanner.rs` | Rule loader (`rules/builtin.toml`, `--rules`, `rules/secrets.toml`), file walker and extension filter, regex pass, per-file `catch_unwind`, 4 MiB read cap |
| | `yara_engine.rs` | yara-x compiler and scanner; three built-in rules; GuardDog `path_include` / `ecosystem` meta; `--yara-dir` |
| | `entropy.rs` | Shannon high-entropy blobs, zero-width characters, Trojan Source bidi controls, Cyrillic homoglyphs |
| | `obfuscator.rs` | Decodes javascript-obfuscator style string tables so the rules see the real strings |
| | `correlate.rs` | Behaviour chains: proximity (4 KB) and per-package correlation of hard signals |
| | `zipslip.rs` | Variable-level taint tracking from archive entry names to filesystem writes |
| | `workflow.rs` | GitHub Actions checks: pwn request, script injection, unpinned actions |
| | `agent.rs` | AI agent files and MCP server code: hidden text, steering phrases, tool poisoning, hooks that run downloaded code |
| | `dataflow.rs` | Variable-level data flow in Python and JS: the whole environment, an SSH key or a browser store reaching a network call; a download reaching exec |
| | `git_history.rs` | Runs the static pass over earlier revisions of every file (`--git-history`) |
| Context and intel | `cve.rs` | Manifest / lockfile package extraction, OSV batch client (`--cve`), offline typo-squat and dependency-confusion checks |
| | `reputation.rs` | Listing spoofing, look-alike publishers, repackaged popular extensions, marketplace statistics |
| | `iocs.rs` | URL / IP extraction and URLhaus lookups (`URLHAUS_AUTH_KEY`) |
| | `attack.rs`, `ttp.rs` | ATT&CK technique tables, the written-out technique list of every finding, and the unified technique / tactic / kill-chain aggregation |
| | `taxonomy.rs` | MBC objectives and supply-chain attack vectors per finding; `kalascan rules --coverage` |
| Scoring | `score.rs` | Risk score models v1 and v2 and the score breakdown |
| Deep passes | `triage.rs` | PE / ELF / Mach-O metadata via goblin, section entropy, packer and import heuristics, optional capa / FLOSS / DIE |
| | `deobfuscate.rs` | Recursive base64 / hex / URL / PowerShell / char-code / ROT13 / XOR / gzip / zlib decoding |
| | `emulate.rs` | Bounded x86 / x64 entry-point emulation with iced-x86: API call tracing, stack strings |
| | `sandbox.rs` | Opt-in Docker runner, strace parser, install-hook tracing with bait credentials |
| | `ai_analyzer.rs` | Ollama / OpenAI / DeepSeek / 9Router / custom endpoint verdicts |
| CI helpers | `baseline.rs` | Finding fingerprints, `--baseline` files, `.kalascanignore` globs |
| | `diff.rs` | Capabilities a new version adds (`kalascan diff`) |
| | `installed.rs` | Discovers IDE and browser extensions on this machine (`kalascan installed`) |
| | `import.rs` | Nessus, Nmap, Burp, ZAP, Nuclei, Qualys and CSV report normalization (`kalascan import`) |
| Server | `auth.rs` | Users, salted token hashes, roles, audit helpers |
| | `db.rs` | SQLite history, migrations (schema v5), bounded retention |
| | `metrics.rs` | Prometheus counters and gauges (atomics) |
| Output | `export.rs`, `export/html.rs` | Markdown, HTML, SARIF, CSV, JUnit and GitHub-annotation exporters; risk levels |
| | `export/stix.rs`, `export/osv.rs` | STIX 2.1 bundle and OSV malicious-package record, for threat-intel tooling |

Rules are data: `rules/builtin.toml` (101 regex rules), `rules/secrets.toml` (208 gitleaks patterns, opt-in), `rules/yara/` (GuardDog rules) and `rules/popular_extensions.tsv` are embedded at compile time. See [detection-rules.md](detection-rules.md).

## Scan pipeline

`execute_scan_in` runs the same phases for the CLI, the API and the Action:

1. **Acquire the target.** A Git URL is cloned, a marketplace id or `npm:` / `pypi:` / `crates:` name is downloaded and extracted, a local path is scanned in place. Anything cloned, downloaded or uploaded is treated as someone else's code: build directories are scanned and inline `kalascan:ignore` markers are not honoured (`--untrusted` forces this for a local path).
2. **Changed-only filter** (`--changed-only --base-ref`): restrict the file set to the diff.
3. **Static pass** (`scanner.rs`): regex rules by category scope, YARA on every file, entropy and Unicode checks, `--secrets` patterns on scripts and config files. Files are scanned on a work-stealing pool with one YARA scanner per worker; each file runs inside `catch_unwind`, so a panic becomes a `Scanner Error` finding and a file over 4 MiB becomes an `Oversized File` finding instead of being skipped.
4. **Manifest and registry context**: offline typo-squat and dependency-confusion checks, listing identity, marketplace statistics, npm / PyPI registry metadata, IOC extraction (URLhaus when `URLHAUS_AUTH_KEY` is set), OSV advisories (`--cve`; `MAL-*` advisories become critical `Malicious Package` findings).
5. **Correlation** (`correlate.rs`): current-tree findings are combined into behaviour chains; history hits never complete a chain.
6. **Git history** (`--git-history`): the static pass over earlier revisions.
7. **Baseline and ignore filtering**: `.kalascanignore` globs, `--baseline --new-only`.
8. **Deep passes**: binary triage (`--deep-triage`), deobfuscation (`--deobfuscate`), emulation (`--emulate`), Docker sandbox (`--sandbox`); then TTP aggregation over everything found so far.
9. **AI analysis** (`--ai`): an LLM verdict that can only corroborate, never lower, the score.
10. **Risk score and export.**

## Risk model

`score::calculate` (`src/score.rs`) turns the finding list into a 0-100 score and a breakdown of the parts it is the sum of (`score_breakdown` in the JSON result). [scoring.md](scoring.md) has both models in full; in short, for the default (v1):

1. Each `(file, finding name)` pair counts once.
2. A behaviour chain and the few findings with no benign reading count as two criticals; everything else by its severity.
3. Critical findings: one 20, two or more `min(n x 35, 70)`. High `min(n x 5, 15)`, medium `min(n, 5)`.
4. Known vulnerabilities `min(n, 5)`, the deep passes together `min(sum, 20)`, a malicious AI verdict `min(risk / 2, 25)`.
5. The total is capped at 100.

Levels (`export::risk_score_to_level`): 0-29 **safe**, 30-69 **warning**, 70-100 **danger**. `--fail-on-risk N` exits 1 at `score >= N`; the GitHub Action defaults to 60. TTP coverage is reported but not scored, because it is derived from the same findings.

Consequences worth knowing: a single uncorroborated critical rule hit puts a clean repository at 20-40, and two put it at 70 or more. That is why new rules must ship `ignores` examples and pass the clean-corpus gate (`eval/`), and why a signal that only means something next to another one belongs in a chain rather than at `critical`.

`--score-model v2` replaces the tiers with a weight per finding, fitted on the evaluation corpus (`rules/weights.toml`). On the holdout it is level with v1 at the default gate and adds a usable range between 30 and 70; it is opt-in.

Findings are placed in ATT&CK (written out per finding in `src/attack.rs`), in MBC objectives and, where a finding is evidence of how code reached a package, in the supply-chain attack tree of Ladisa et al.: [coverage.md](coverage.md), printed by `kalascan rules --coverage`.

## Output formats

| `--format` | Use | Notes |
|---|---|---|
| `text` | terminal | default |
| `json` | automation | full result: `rule_matches`, `iocs`, `triage`, `ttp`, `risk_score`, ... |
| `sarif` | GitHub Code Scanning | SARIF 2.1.0 with `partialFingerprints` (`kalascan/v2`) that survive line moves |
| `md`, `html` | reports | the HTML report is self-contained |
| `csv`, `junit`, `github` | CI systems | CSV cells are formula-safe; `github` prints workflow annotations |
| `stix` | threat-intel platforms | STIX 2.1 bundle: an `indicator` per IOC, an `attack-pattern` per ATT&CK technique, `indicates` only where a finding's own line holds the URL; ids are stable per scan |
| `osv` | malicious-package reports | one OSV record (`x_KALASCAN-<scan id>`, not an assigned `MAL-` id) for an `npm:name@version` / `pypi:name==version` target; refused below the danger level or without an exact version |

The web API returns the same JSON (`GET /api/scan/{id}/status`) and serves every format at `/api/report/{id}/{format}`.

## Where things run

- **CLI** and **GitHub Action** (`action.yml`): `kalascan scan`, SARIF upload, `fail_on_risk` gate.
- **Web server** (`kalascan serve`): async scan queue, SQLite history, RBAC, Prometheus metrics, OpenAPI at `/openapi.yaml`. See [web-ui-security.md](web-ui-security.md).
- **Docker**: `ghcr.io/wahidhendrawan/kalascan` (linux/amd64, linux/arm64) and the optional `sandbox/Dockerfile` strace image.
