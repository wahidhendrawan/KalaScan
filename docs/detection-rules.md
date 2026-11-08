# Detection rules

KalaScan has three rule families. All are data, embedded at compile time. `kalascan rules` lists the regex rules with the ruleset version; `kalascan rules KS-SUP-009` explains one rule and prints its pattern.

| Family | Where | Count | When |
|---|---|---|---|
| Regex rules | `rules/builtin.toml` (ruleset version `2026.10.1`) | 89 | always; `--rules FILE` adds yours |
| Secret patterns | `rules/secrets.toml` (generated from gitleaks v8.30.1, MIT) | 208 | opt-in with `--secrets` |
| YARA rules | `src/yara_engine.rs` (3 built-in), `rules/yara/guarddog/` (2), `--yara-dir DIR` | | every file except prose |

## Regex rule format

```toml
[[rule]]
id = "KS-EXF-005"
name = "AWS Access Key"
severity = "critical"
category = "exfiltration"
description = "AWS Access Key ID detected — credential leak"
# Word boundaries: AKIA-shaped runs inside base64 blobs are not keys.
pattern = '''(?-u:\b)AKIA[0-9A-Z]{16}(?-u:\b)'''
matches = ['''AKIA1234567890123456''', '''key = "AKIAXXXXXXXXXXXXXXXX"''']
ignores = ['''fGh0AKIAAAB0AAAAAAAAAKMAa''']
```

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Stable identifier `KS-<AREA>-<NNN>`. Never reused or renumbered: baselines and SARIF key on the name, people on the id. |
| `name` | yes | Finding title in reports; chains and the risk model key on it. |
| `severity` | yes | `critical`, `high`, `medium` or `low` (weights in [architecture.md](architecture.md#risk-model)). |
| `category` | yes | Decides which files the rule runs on (table below). |
| `description` | yes | One line shown next to the finding. |
| `pattern` | yes | Rust `regex` syntax (no look-around, no back-references). Use `(?-u:\b)` instead of `\b`: a Unicode word boundary makes the engine fall back to its slowest mode on any non-ASCII byte, i.e. on most bundles. |
| `matches` | no | Strings the pattern must match. Verified when the rules load (`cargo test rule_examples`) and when `--rules` is parsed. |
| `ignores` | no | Strings the pattern must not match: the place to pin a fixed false positive. |
| `exclude_files` | no | File names the rule never runs on, e.g. `["package.json"]`. |
| `keywords` | no | Lower-case words, one of which must occur in the file before the regex runs (cheap prefilter, used by the secret rules). |
| `entropy`, `secret_group` | no | Minimum Shannon entropy of the capture group holding the secret (secret rules). |

A rule whose examples fail aborts the scan with the reason, so a typo in a pattern cannot silently match nothing.

### Id prefixes and categories

| Prefix | `category` | Files scanned | Rules |
|---|---|---|---|
| `KS-EXF` | `exfiltration` | script extensions and manifest files | 22 |
| `KS-ACC` | `file_access` | script extensions | 11 |
| `KS-EXE` | `obfuscation` | every scanned file | 30 |
| `KS-SUP` | `supply_chain`, `npm_hook` | every scanned file; `npm_hook` only `package.json` | 11 |
| `KS-RAN` | `ransomware` | every scanned file | 5 |
| `KS-REC` | `recon` | every scanned file | 3 |
| `KS-NET` | `network` | every scanned file | 3 |
| `KS-INS` | `install_hook` | `setup.py` only (code there runs at `pip install`) | 2 |
| `KS-FSW` | `file_write` | every scanned file | 2 |
| `GL-*` | `secret` | script extensions, manifests and config files (`.env`, `*.yml`, `*.json`, `.npmrc`, ...) | 208 |

"Script extensions" is `CRITICAL_EXTENSIONS` in `src/scanner.rs`: `.py .js .ts .mjs .cjs .jsx .tsx .sh .bat .ps1 .psm1 .vbs .php .java .kt .rb .go .rs .lua .pl .cs .swift .groovy .gradle .yml .yaml` (`.yml` / `.yaml` get only the exfiltration, network, supply-chain and secret rules). "Manifest files" are `package.json`, `setup.py`, `manifest.json`, `plugin.xml`, `extension.vsixmanifest`, `Dockerfile`, `Makefile`, `Justfile` (case-insensitive). A category name not listed here (for example `custom` in your own rules file) runs on every scanned file. YARA runs on every file except prose (`.md`, `.rst`, `.txt`, `.adoc`), which routinely quotes IOC strings.

### Writing a rule that survives the clean corpus

- Anchor it. `KS-RAN-004` matched the CISA KEV column name `ransomware_use` in a clean application because its pattern had no word boundary.
- Prefer a chain to a high severity. `src/correlate.rs` combines two hard signals within 4 KB of each other (or anywhere in one package) into one critical chain finding; a single soft signal stays `medium` or `high` and cannot push a clean repository over the CI gate by itself.
- Add an `ignores` example for every false positive you fix, then run `python3 eval/run_eval.py --only clean` (see `eval/README.md`). CI fails a PR that pushes any clean sample to risk 50.
- Severity guide: `critical` = no benign reading (exfiltration endpoint, encoded command, credential theft); `high` = rarely benign inside a package; `medium` = common in legitimate code (`process.env`, loopback IPs, `exec()`); `low` = informational.

## Custom rules

```bash
kalascan scan ./repo --rules my-rules.toml
```

Same format; `matches` / `ignores` are checked on load. `--rules` is CLI-only: the web API refuses server-side file options.

## Secret rules (`--secrets`)

`rules/secrets.toml` is generated from gitleaks' `config/gitleaks.toml` by `rules/gen_secret_rules.py` (`python3 rules/gen_secret_rules.py > rules/secrets.toml`; do not edit by hand). 208 rules are kept; 14 are skipped because they need a gitleaks allowlist, are path rules, have no regex, or exceed Rust's regex size limit. Each rule keeps gitleaks' entropy threshold and keyword prefilter. Findings are `medium` and never join a chain: a hard-coded token is a leak, not malware. `.gitleaks.toml` allow-lists this file so the repository's own gitleaks scan does not match the patterns against themselves.

## YARA rules

- Built-in (`src/yara_engine.rs`): `ReverseShellGeneric`, `CryptoDrainerGeneric`, `DiscordWebhookStealer`.
- `rules/yara/guarddog/`: rules from DataDog GuardDog (Apache-2.0; `LICENSE` and `NOTICE` are kept alongside).
- `--yara-dir DIR` loads your own `.yar` files. GuardDog conventions are honoured: `path_include = "*.py,*/setup.py"` in `meta` limits a rule to matching paths, and `ecosystem == "npm"` / `"pypi"` in the condition limits it to one package type.
- YARA runs on every non-prose file, including binaries, so it is the place for byte patterns the regex pass cannot express.

## Findings that are not rules

Entropy and Unicode checks (`src/entropy.rs`), behaviour chains (`src/correlate.rs`), zip-slip taint tracking, GitHub Actions workflow checks, registry and reputation checks, OSV advisories, IOC lookups and the deep passes produce findings with fixed names (`Oversized File (partially scanned)`, `Scanner Error (file not analysed)`, `Malicious Package`, chain names, ...). They have no `KS-` id and are not listed by `kalascan rules`; their weights are in the risk model.
