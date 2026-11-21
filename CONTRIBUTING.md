# Contributing to KalaScan

Thanks for helping make KalaScan a better scanner.

## Development setup

```bash
git clone https://github.com/wahidhendrawan/KalaScan.git
cd KalaScan
cargo test --locked                            # unit tests + rule examples (Rust 1.95+)
cargo run -- scan /path/to/repo --format json  # headless scan
cargo run -- serve                             # web UI on http://127.0.0.1:3000
```

Or with Docker: `docker compose up -d --build`.

## Project layout

- [docs/architecture.md](docs/architecture.md): module map, scan pipeline, risk model, output formats
- [docs/detection-rules.md](docs/detection-rules.md): rule TOML format, ids, YARA and secret rules
- [docs/web-ui-security.md](docs/web-ui-security.md): running the server safely
- [eval/README.md](eval/README.md): the labelled corpus and how detection quality is measured

## Before contributing

- Search existing issues and pull requests first.
- Security vulnerabilities: follow [SECURITY.md](SECURITY.md); do not open a public issue.
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- Never commit live malware, real credentials or private indicators. Malicious samples enter the eval corpus by reference only (`eval/corpus.json` names a package and version; `eval/fetch_malicious.sh` downloads it locally).

## How to contribute

### Add or change a regex rule

1. Edit `rules/builtin.toml`. Take the next free id in the category (`KS-EXF-023`, ...); never reuse or renumber an id, baselines and SARIF key on it.
2. Give the rule at least one `matches` example and, for anything that could fire on ordinary code, an `ignores` example. `cargo test rule_examples` runs them.
3. Run the false-positive gate: `cargo build --release --locked && python3 eval/run_eval.py --only clean --threshold 50 --max-fpr 0 --allow-errors`. CI fails a PR that pushes any clean sample to risk 50.
4. If the rule only means something next to another one, add the pair as a chain in `src/correlate.rs` instead of raising its severity.

### Add a YARA rule

Put a `.yar` file under `rules/yara/` (the GuardDog `path_include` / `ecosystem` meta keys are honoured) or ship it to users through `--yara-dir`. The three built-in rules live in `src/yara_engine.rs`.

### Add a scanner report format

`src/import.rs`: add a content sniffer (the format is detected from the content, never the extension) and a parser that yields the common finding struct. Add a small synthetic fixture under `tests/fixtures/import/`.

### Report a false positive

Use the "False positive" issue template with the rule id (`kalascan rules <id>` explains it), the public package, extension or repository, and the matched line.

## Guidelines

- Keep `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings` and `cargo test --locked` green. CI also runs `cargo deny check`, a scan of this repository with the built binary, the clean-corpus gate and the security scans.
- Add a test for every behaviour change; rule changes are tested by their examples.
- A new parser of untrusted input (an archive, a report or lockfile format) gets a fuzz target under `fuzz/`: `cp Cargo.lock fuzz/Cargo.lock && cargo +nightly fuzz run <target> -- -max_total_time=60` (needs `cargo install cargo-fuzz`; on macOS use `fuzz run -s none <target>`). The Fuzz workflow runs every target weekly.
- A known limitation gets a `shortcut: <limit>, <when to upgrade>` comment rather than silence.
- Conventional commit messages: `feat:`, `fix:`, `docs:`, `ci:`, `chore:`.
- Add a line under `[Unreleased]` in `CHANGELOG.md` for every user-facing change.

## Pull requests

1. Branch from `main`; keep the change focused, with no unrelated formatting or generated files.
2. Fill in the pull request template: what, why, how it was tested, and for rule changes the effect on recall and false positives.
3. CI must pass: build, clippy, tests, cargo-deny, the eval gate (on `src/`, `rules/`, `eval/` changes) and the security scans.

## Ruleset versions

A ruleset is what decides a verdict: the rule files in `rules/` (regex, YARA, weights, the popular-extension list) and the detection modules in `src/` (`scanner`, `correlate`, `score`, `obfuscator`, `registry`, `reputation`, `agent`, `dataflow`, `deobfuscate`, `entropy`, `iocs`, `triage`, `cve`, `yara_engine`, `zipslip`). It changes only as a new version, and a version ships with its measurement.

1. A pull request that touches one of those files bumps `RULESET_VERSION` in `src/scanner.rs` (the CI `ruleset` job fails otherwise). A change there that moves no verdict, such as a refactor or a test, gets the `ruleset-unchanged` label instead.
2. The new version is measured in a throwaway VM (eval/README.md) and recorded with `run_eval.py --summary eval/results/<version>.json`; `cargo test` fails without that file. The summary also records the binary's detection fingerprint, a hash of those rule files and modules made at build time (`build.rs`; `kalascan rules` prints it), so a result names the code it came from even if the version was not raised. Nothing checks the two against each other: a comment edit changes the fingerprint.
3. One ruleset version per minor release. Rule work collects on a branch and is measured once, not after each rule.
4. Before rules are tuned, a new holdout is drawn, so the next count is on samples nobody has read.

## Releasing (maintainers)

1. Bump `version` in `Cargo.toml` and `CITATION.cff`; move the `[Unreleased]` notes in `CHANGELOG.md` to a `## [x.y.z] - YYYY-MM-DD` section and add its compare link.
2. Push the tag `vx.y.z`. `release.yml` refuses a tag that does not match `Cargo.toml` or has no CHANGELOG section, builds the four binaries, and attaches the SBOM, cosign signatures and provenance attestation; the release body is the CHANGELOG section.
3. Update the Homebrew tap formula.
