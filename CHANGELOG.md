# Changelog

All notable changes to KalaScan are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/). Releases before 1.8.0 were not
published on GitHub; their features are listed with version markers in `README.md`.

## [Unreleased]

## [1.27.0] - 2026-11-23

### Added
- A result carries `warnings` when a pass that was asked for failed or was cut short: the OSV lookup, the AI call, a registry lookup, agent text past the AI budget. They show in the text, Markdown and HTML reports and as a banner in the web UI, and are stored with the scan (database schema 6). The list is absent when nothing failed.
- `kalascan deps` lists a lockfile entry it cannot scan (a registry mirror, git, a URL or a file, an unpinned `requirements.txt` line) as not scanned, and such an entry fails `--fail-on-risk` unless `--allow-skipped`; in the JSON it is an element with `"skipped": "<reason>"` and a null `risk_score`. The GitHub Action has the matching `allow_skipped` input. `npm-shrinkwrap.json` is read like `package-lock.json`.
- CI runs the tests on Windows and macOS, `eval/run_eval.py --self-test`, and compiles the fuzz targets.
- `kalascan scan` takes a local `.tgz`, `.tar.gz` or `.whl` (`./pkg-1.0.0.tgz`), unpacked by its content through the same capped extractors as a registry download.
- A finding carries a rule id made from its name (`discord-webhook`): `rule_id` in the JSON, the last column of the CSV, `ruleId` in SARIF. The JSON, SARIF (`fullDescription`, `help`, `helpUri`) and the web UI add the rule's description, ATT&CK techniques and MBC objectives where the rules hold them.
- The GitHub Action, run at a release tag, downloads that release's binary and checks its sha256 instead of compiling (it falls back to `cargo install`), and writes the risk score and verdict findings to the job summary. `kalascan scan --output` prints one line with the risk score and the critical findings and chains.
- The Docker image is also published as `:<version>` for each release tag.
- `eval/evasion.py`: nine new rewrites (`comment-between`, `base64-variable`, `base64-split`, `zlib-layer`, `hex-layer`, `xor-layer`, `string-table`, `source-other-file`, `npm-run-hook`), 59 more variants, and `--check-syntax`, which parses every variant (`node --check`, `ast`, `sh -n`). Five old rewrites wrote code that does not parse and were fixed: `#fetch(` is now a private class field, `fe'+'tch(` and `\x66etch(` reach the name through `globalThis[…]`, `getattr` or a string, the thousand spaces go after a Python call's `(`, and only JavaScript is minified onto one line. Their old counts measured broken files.

### Changed
- Ruleset 2026.11.16. Holdout 725 of 1,109 and rolling holdout 62 of 131 as before, no sample lost or gained; `dev` 772 of 1,061 (771); 0 of 3,822 clean samples flagged and none changed score; 272 of the 618 live releases, as before; 0 of the 1,491 releases the watch never flagged that could still be fetched. The evasion suite, with the new rewrites, went from 181 to 211 of 212; two rewrites stacked, 1,649 of 1,693.
  - A chain's two parts are as near as the code between them: comment lines and `/* */` blocks that open a line do not count toward the 4 KB, and a reverse shell's pipe may sit beside the process start rather than the socket.
  - Encoded payloads: a base64 or hex blob in a variable of the file that a decoder is handed by name, a blob cut in pieces (`'…' + '…'`, Python's adjacent strings), zlib or gzip under the encoding (512 KiB inflated at most), and character codes XORed with one constant (`[…].map(c => c ^ 23)`) are decoded and scanned as code.
  - Names reached through a string: `globalThis['ev'+'al'](`, `getattr(os, 'system')` and `__import__('builtins').exec` are read as the call they make. An obfuscator string table under mangled names (`a`, `b`) is read by its shape.
  - Data flow follows one relative import: a function of another file of the package that returns a secret counts as the importing file's own (`require('./x')`, `import … from './x'`, `from .x import f`). The other direction, a secret handed to an imported wrapper around a request, was built and dropped: it flagged four releases of an agent runtime that hands its environment to the session host it starts.
  - Agent skills: a script the skill's text runs by relative path (`python scripts/setup.py`, `./install.sh`) counts as run by the skill, and an encoded command in the text (`echo … | base64 -d | sh`) is read as what it decodes to.
  - A new `low` finding, `Several Kinds of Credential Store Read`: three kinds (browser or Discord profile, wallet, SSH keys, password manager, editor session, the whole environment) read within 4 KB in one file. It is in no chain and cannot make a verdict; this ruleset measures how often it fires: 9 holdout and 12 `dev` malicious samples, 1 clean sample (in `dev`).
- `--cve` and `kalascan sbom` use the versions the lockfile pins, transitive packages included, when the repository has a lockfile `kalascan deps` reads; an unpacked package keeps its manifest. The SBOM of an npm project with a lockfile grows to the whole tree.
- `--format` and `--llm-provider` reject an unknown value (and `kalascan.toml`'s `format`) instead of falling back to text: `--format JSON` on `installed`, `deps` and `diff` printed text before.
- The built-in YARA rules are compiled once per process: twenty scans in one process went from about 7 s to 3 s (debug build).
- SARIF `ruleId` of a finding whose name carries a value is the rule's alone: `Typo-squat Suspect: x` is `typo-squat-suspect`. GitHub Code Scanning reopens such alerts once.
- The HTML report loads nothing: the stylesheet that came from a CDN is inline.
- `KALASCAN_HOME` places the database of `serve` and `user` (a scan writes none) and is documented; the Docker image runs as root as before, with `--user` and `KALASCAN_HOME` documented for a volume that allows it.
- Ruleset 2026.11.15: no rule changed, what a scan reads did. Every count is the same as with ruleset 2026.11.14: holdout 725 of 1,109, `dev` 771 of 1,061, 0 of 3,823 clean samples, 272 of the 618 live releases, evasion suite 151 of 153; of the 1,500 releases the watch never flagged, 1,495 could still be fetched and none reaches 50. Under the threshold 12 clean samples change score, 7 of them down.
  - In a package, a file an install script hands to an interpreter (`"postinstall": "node install.txt"`) and an extensionless file a relative `require` loads are read as code. `.cmd`, `.mts`, `.cts` and `.pyw` are code files.
  - A file whose data-flow pass stopped on a multi-byte character (`∫`, `·`) was reported as `Scanner Error (file not analysed)` and not read. It is analysed now; seven clean PyPI samples had such files.
  - Binary triage and `--deobfuscate` walk the same directories as the rules, `node_modules/` included.
- A report lists at most 20 findings of one rule in one file, then one `Repeated Finding (further hits not listed)` (severity `info`) with the count, and about 100,000 findings per scan. Chains are computed from every hit first and the score does not change. A scan with `--baseline` lists all of them, so `--new-only` still sees a new hit past the twentieth.
- `kalascan guard` refuses an install when `package.json` or `pyproject.toml` declares dependencies and no lockfile it reads pins them, when the lockfile has entries it cannot scan, and when the tree npm resolves adds a package that is not from registry.npmjs.org.
- `eval/run_eval.py` fails a run in which more than 5% of the samples could not be scanned, also with `--allow-errors`: a binary that does not start used to pass `--max-fpr 0 --allow-errors`.

### Fixed
- Unpacking: a registry target or marketplace id is never read from a local file of the same name; `extension/` is the scan root only for a VSIX, so a wheel or JAR cannot hide code beside such a directory; whatever an archive ships at `.sdist` is scanned as package code and cannot pass for the sdist's `setup.py`; the size limits of a `.tar.gz` count the size a PAX record gives an entry and bound the decompressed stream; file data after a PAX header is no longer rewritten.
- Manifests (`package.json`, `requirements.txt`, `Cargo.lock`, `PKG-INFO`) are read only as regular files inside the scanned tree, 8 MiB at most: a symlink out of the tree is not followed.
- Scans that did not finish: chain pairing and the wallet-glob check were quadratic in the hits of one file (a one-line 2 MiB file took minutes), and a `Cargo.lock` entry, an AI response and an npm target with multi-byte characters could panic. In the web UI a scan that panics ends as `failed: scan panicked: …` and is not requeued.
- On Windows, paths in findings use `/`, so a finding under `node_modules\` is not taken for the package's own code.
- On Windows, a file an install script or a `require` names was looked up with `\` against paths spelled with `/`, so it was never read as code.
- `url` 2.5.9 (RUSTSEC-2026-0592, a stack overflow in `Url::origin()`; KalaScan does not call it).
- The repository checks out with LF line ends on every platform (`.gitattributes`).
- The Dependabot auto-merge workflow acts only on a run from this repository and merges only the commit CI tested.

## [1.26.0] - 2026-11-22

### Added
- A PyPI release scanned by name (`pypi:name==version`) is read from its wheel with its sdist's `setup.py` beside it, at `.sdist/setup.py`: pip runs that file wherever no wheel fits, with `--no-binary`, and in tools that build from source. It is a unit of its own, so what it does at install pairs inside it and never with the wheel's application code. Only that file: the whole sdist had flagged clean packages through tests, Makefiles and release scripts (ruleset 2026.11.13).

### Changed
- Ruleset 2026.11.14. Every count is the same as with ruleset 2026.11.13: holdout 725 of 1,109, `dev` 771 of 1,061, 0 of 3,823 clean samples, 272 of the 618 live releases, 0 of 1,496 releases the watch never flagged. Under the threshold, 68 of 1,357 clean PyPI samples score higher, none above 20.
  - A download cradle, remote executable or systemd unit inside a `long_description` string still open on its line (`long_description = '…'`, or Poetry's `'long_description': '…'`) is the package's README, not code.
  - Built, measured and not shipped, again: install-time chains only where the install hook reaches (roadmap item 16). On ruleset 2026.11.13 it lost 4 holdout and 6 `dev` samples and cleared 23 live releases, all by `Chain: Install-time Exfiltration`.
- `docx-form` and `psutil`, clean holdout samples whose findings had been read, moved to `dev`.
- `docs/roadmap.md` lists what was built and what was measured and not built; the open items were removed.

## [1.25.0] - 2026-11-22

### Added
- `--ai` reads AI agent skills by meaning: when a scan has agent files (`SKILL.md`, `CLAUDE.md`, `.cursorrules`, …), their text (12,000 characters at most, a root `SKILL.md` first) goes to the model with a prompt of its own, and a malicious verdict at risk 70 or more on that text counts as a verdict (70). Measured with DeepSeek: holdout skills 49 of 102 instead of 19, 0 of 478 clean skills flagged (two flagged clean skills were read and moved to `dev`). The text leaves the machine; use a local model for private repositories.
- A rolling holdout: `sample_malicious.py --ref` draws from the files of a branch that `HEAD` lacks (the DataDog dataset's unmerged sync branch; entries record the commit, which `fetch_malicious.sh` checks out), and `--added-after COMMIT` from what pypi_malregistry added since a commit. The first draw, 294 samples, went half into the holdout (`rolling-2026-11`) and half into `dev` (`tune-rolling-2026-11`).

### Changed
- Ruleset 2026.11.13, tuned on the `dev` half of the rolling draw. Rolling holdout 62 of 131 (38 with ruleset 2026.11.12); holdout 725 of 1,109 (697), no sample lost; `dev` 771 of 1,061 (737); 0 of 3,823 clean samples flagged; of the 618 new releases flagged since the watch started, 272 reach 50 (270); evasion suite 151 of 153.
  - Data flow: a download returned by a helper of the file counts at a sink that runs code in this process (`exec(_transfer(url))`), not inside a string literal, and not at a process start.
  - Rules: `WhatsApp Channel Followed by Library Code`, `Install Script Calls a Native Addon`, `Process Started Detached or Without a Window`, `Cloudflare Access TCP Client`; `Make File Executable` reads `os.chmod(f, 0o755)` and `stat.S_IEXEC`.
  - Chains: `setup.py` starting a process windowless or in its own session is an install-time payload; Python's drop-and-execute (`os.chmod` of the file a detached `Popen` starts); `Chain: Hidden Python Process` (`pythonw` picked just before a start with `CREATE_NO_WINDOW`); `Chain: Dropped Binary Behind a Cloudflare Access Tunnel`.
  - Built, measured and not shipped: scanning a PyPI release's sdist beside its wheel. It flagged 3 of 3,821 clean samples and 6 of 1,493 new releases and can gain no malicious sample of the corpus (eval/README.md).
- npm's `0.0.0-stage` placeholders are not samples: seven left the corpus (six holdout, all missed) and `sample_malicious.py` skips them.
- `eval/watch_outcome.py` counts npm's `0.0.1-security` takedown placeholders as taken down before the scan, not as missed. Early reading, one day in: 1 of 12 releases OSV names malicious had been flagged.

## [1.24.0] - 2026-11-21

### Changed
- Ruleset 2026.11.12: a second round of false positives, from reading the 389 new npm and PyPI releases that ruleset 2026.11.11 still flagged. Of the 618 releases flagged by any build since the watch started, 270 still reach risk 50. Holdout 659 of 984 as before, no sample lost or gained; `dev` 688 of 929 (three lost, read and on record); 0 of 3,823 clean samples flagged; evasion suite 151 of 153.
  - Data flow: a request to a loopback URL is not a sink, and a method is a network sink only on a network client. The environment handed to a child process is not sent, a name reassigned to a clean value is clean, and a field read off a group (`(options.env ?? process.env).NAME`) is one setting. `known_hosts`, `config`, `authorized_keys` and `*.pub` under `.ssh` are not secrets. A response's status is not its body, the options object of `spawn` is not the command, and `npx name@${version}` is a self-update.
  - Chains: `Remote Executable Download` is not an exfiltration channel. A vendored Python package (`site-packages/<name>/`, `_vendor/<name>/`, `vendor/<name>/`) is a unit of its own. Tests and fixtures pair across the package only when the install hook names or runs them. `Chain: Drop and Execute Binary` skips a launcher that starts the binary its package ships and hands its arguments on. A chain's context names both files.
  - Agent files: a steer and what it steers towards sit within 4 KB of each other; a hidden comment is not a second steer for the phrase inside it; a comment shown in a fenced code block is not hidden; a security tool's pattern table is not `Chain: Weaponised AI Agent`.
  - Rules: a download cradle, `Remote Executable Download` or systemd unit handed to a log line or an exception is shown, not run. `curl … | python3 -c '…'` is a cradle only if the one-liner runs what it reads. Eight more official installer hosts. 100.64.0.0/10 is not a public address. Decode-and-run templates for a child process (`node -e "eval(Buffer.from('${n}','base64'))"`, a bootstrap that decodes `sys.argv`) carry no payload. `Python Import-Obfuscated Loader` needs `exec`, a second decode or a literal. The obfuscator's string-table needles match whole words. A Discord webhook needs its full path; a wallet name in a list of globs is not wallet access.
  - Wider: the cradle rule reads `| sudo bash` and `bash -c "$(curl …)"`, and a vendor name that is only the user part of a URL (`https://claude.ai@host/`) is not the vendor.
  - Built, measured and not shipped: install-time chains only in files the install hook reaches. It lost 6 holdout and 4 `dev` samples whose chain is a hook and a network call that share a package and nothing else. Three smaller changes were dropped and five narrowed for the holdout as well; the first build with everything had lost 14 holdout samples (eval/README.md, "What was still flagged, read by class").

## [1.23.0] - 2026-11-21

### Added
- `kalascan watch --log FILE` appends one JSON line per scanned release, flagged or not (time, target, risk, strong findings, ruleset). `eval/watch_outcome.py` compares those releases, after a wait, with OSV's malicious-package records and with what the registries still serve: the first measurement on releases nobody had judged yet. A prospective run started on 2026-11-20; its outcome can be read from 2026-12-20 (eval/README.md).
- Encoded literals are read as code: what `atob`, `Buffer.from(…, 'base64' | 'hex')`, `b64decode`, `bytes.fromhex` and `echo … | base64 -d` literals decode to is scanned with the same rules, chains and data flow, two layers deep, so `eval(Buffer.from(blob, 'base64'))` is judged by its payload. Character codes handed to a decoder of the package's own (`_d([104,116,…])`) are read as the string they spell. Evasion suite: 151 of 153 variants caught (147).
- The data-flow pass follows calls inside a file: a wrapper around a network call is a sink for its argument, and a call of a function that returns a secret, or what it collected from its argument, carries it; TypeScript's compiled `__awaiter` functions and `.then()` callbacks are followed.

### Changed
- Ruleset 2026.11.11, in two rounds. The second came from reading what `kalascan watch` flagged in one day of new npm and PyPI releases (574 of 21,257); 360 of those 574 still reach risk 50.
  - Data flow: `'.ssh'` as a path part is a secret source. The environment counts where the whole of it is serialised or sent; one variable of it, or a helper called with it, is one setting. `spawn` with downloaded data among its arguments is a download-and-execute only with an inline-code flag or a shell, and a `fetch(` inside a string is not a download. A route decorator is not a request.
  - Official installers: a vendor URL with no path was not recognised; eighteen domains of agent CLIs and developer tools joined the list.
  - Install-time chains: `Remote Executable Download`, the download cradle and `Systemd User Service Installed` count only in what the install hook runs; a `package.json` of a shipped template and a module that is only named `setup.py` are not install hooks.
  - Score v1: an AWS key pair and a GitHub token written into a package are one critical finding together.
  - `Trojan Source Bi-Directional Character` skips a control alone between quotes and the isolates of localisation libraries; `b64decode + exec Chain` skips a command template joined from a variable; `Account Enumeration Command` skips a highlighter's keyword list.
  - Holdout 659 of 984 (packages and extensions 640 of 882, from 639 of 883; one sample was read and moved to `dev`), `dev` 691 of 929, 0 of 3,823 clean samples flagged. A change that counted one critical rule once per package cost two holdout samples and was dropped (eval/README.md).
- GitHub Action: `all_dependencies: "true"` scans every package the lockfiles pin, for a scheduled job.
- `kalascan rules` prints a detection fingerprint, a hash of the rule files and detection modules the binary was built from; `run_eval.py --summary` and `kalascan watch --log` record it.
- `eval/evasion.py --stacked` measures every seed under two rewrites in a row: 792 of 810 caught. A template literal cut by an empty interpolation (`` `id_${''}rsa` ``) is read as the name it spells.
- `docs/roadmap.md`: what is planned by priority, and what was measured and not built.

### Fixed
- Data flow: a `{` inside a function's parameter list (`function f(state = {}, env = process.env)`) was read as the function's body, which bound `env` to the environment from a default value.
- `eval/fetch_npmstudy.py` no longer leaves a truncated tarball that looks fetched when it is interrupted.
- npm tarballs with an empty size field in an entry header (npm's `0.0.0-stage` placeholders) could not be unpacked; they are read as GNU tar and npm read them.

## [1.22.0] - 2026-11-20

### Added
- `Chain: Agent Setup from Throwaway Host` and `Chain: Agent Setup from Password-Protected Archive`: a skill or other agent file whose setup step installs a "required" tool from free app hosting or a paste site (`*.vercel.app`, `glot.io`, …), or from an archive with its password beside it, the ClawHub lure of 2026.
- Eval corpus: AI agent skills. 204 malicious from the DataDog dataset (`sample_malicious.py --ecosystem ai-skills`, split by author) and 482 clean from GitHub, pinned to a commit (`sample_clean.py --skills`, `--skills-repo`; fetched with `eval/fetch_skills.py`, scanned with `run_eval.py --skills`). First contact: 9 of 204 malicious caught, 6 of 487 clean flagged (1.2%). With ruleset 2026.11.10: 65 of 204, holdout 19 of 102 (19%, 12-27), no clean skill flagged.
- Eval corpus: a tuning batch of 200 npm packages from January to July 2026 (`tune-npm2-2026-11`, dev): 152 caught; the misses are mostly payloads in a dependency and packages without code, and no rule was written from them. Scanning siblings pinned to an exact version was measured: no clean package flagged, and no miss it would catch; not built.
- Eval corpus: a second draw of 297 Open VSX extensions (`openvsx-random2-2026-11`). First contact: 15 of 295 flagged (5.1%, 3.1-8.2); 9 fixed, 6 flagged by design left out.

### Changed
- Ruleset 2026.11.10. `Trojan Source Bi-Directional Character` skips binary lines and a bidi control that opens Arabic or Hebrew text; `Code Hidden Behind Whitespace Padding` counts only whitespace runs of 4 KiB or more; the obfuscated string-table chains no longer read `iex` inside a longer word, `credentials` / `withCredentials` alone or a bundled JSON table as steps; `Repackaged Copy of Popular Extension` accepts the repository's owner as publisher; `Shadow Copy Deletion` needs the destructive command, not the tool's name; `wasmtime.dev`, `openclaw.ai` and `SAP-samples` count as official installers. Holdout: 658 of 985 (67%, 64-70), of which packages and extensions 639 of 883 as before and AI agent skills 19 of 102; 0 of 3,425 clean holdout samples flagged.
- The CI false-positive gate fetches and scans the clean AI skills and the second extension draw on the weekly and manual runs; pull requests skip them.

## [1.21.0] - 2026-11-19

### Added
- `kalascan guard -- pip install <package>` scans every distribution the install would add, resolved by pip from wheel metadata only (`--dry-run --only-binary :all: --report -`: no sdist is built, no `setup.py` runs); it falls back to the named packages when pip cannot resolve that way.

- Evasion suite: eight more rewrites from public write-ups (`atob` layer, template literals, unicode escapes in identifiers, computed member calls, dynamic `import()`, `importlib`, `exec(compile(…))`, a `node -e` install hook). All 31 new variants were caught on their first run; 147 of 153 in all (96%).

- `kalascan scan https://open-vsx.org/extension/<ns>/<name>/<version>` scans that version instead of the latest.
- Eval corpus: 249 IDE extensions drawn at random from Open VSX (`sample_clean.py --openvsx`). First contact: 6 of 247 clean extensions flagged (2.4%, 1.1-5.2); one more hides a payload that reports the user's prompts and was left out.

### Changed
- Ruleset 2026.11.9. `Repackaged Copy of Popular Extension` no longer fires on the extension-samples starter repository or on the author republishing under a reordered handle; `Chain: Reconnaissance Beacon` pairs host reconnaissance with a hardcoded IP URL only in one file, at most 200 lines apart; `Password Manager Access` no longer matches `connectionCredentials.database`. Holdout recall unchanged (639 of 883), 0 of 2,665 clean holdout packages flagged.
- The CI false-positive gate skips the 1,993-package random draw on pull requests (`run_eval.py --skip-set`); the weekly and manual runs still scan every clean sample.

### Fixed
- Eval harness: an archive with two manifests at the same depth was scanned from whichever directory came first; it now scans their common parent. One `dev` sample had been caught for the wrong reason.

### Security
- `Cargo.lock` moves wasmtime (through yara-x) to 48.0.9 for RUSTSEC-2026-0566 to RUSTSEC-2026-0573.

## [1.20.0] - 2026-11-19

### Added
- Evaluation: a second npm source. `eval/fetch_npmstudy.py` reads samples out of the replication package of the ASE 2026 study "How Effective Are NPM Malicious Package Detectors?" (CC BY 4.0) with HTTP range requests, `sample_malicious.py --npmstudy` draws names the DataDog dataset does not have, `run_eval.py --npmstudy` scans them. The new holdout set `npmstudy-2026-11` (200 npm packages, mostly 2021-2024) scores 159 of 200 (80%, 73-85); the holdout is 639 of 883 (72%, 69-75).
- CI job `ruleset`: a pull request that changes a rule file or a detection module (CONTRIBUTING.md lists them) must bump `RULESET_VERSION`, or carry the `ruleset-unchanged` label when no verdict moves; `cargo test` fails while `eval/results/<version>.json` is missing. CONTRIBUTING.md, "Ruleset versions": one ruleset version per minor release, measured once.
- Evaluation: 2,000 more clean packages drawn at random from npm and PyPI (`random2-2026-11`, holdout). First contact: 18 of 1,993 flagged, of which 4 were registry spam and 14 benign: 0.7% (0.4-1.2), and 19 of 2,584 (0.7%, 0.5-1.1) with the earlier draws. GuardDog 3.2.0 measured again on the whole holdout: 608 of 883 against KalaScan's 639, and 133 of 453 clean packages against 0 (eval/README.md).
- `kalascan watch --ecosystem npm|pypi`: scans what the registry publishes as it is published (npm's changes feed, PyPI's recent-updates feed), prints releases at or above `--min-risk` and with `--osv-dir` writes OSV records for them.
- `kalascan deps --base-ref REF` scans only the packages the lockfiles did not pin at a git ref; the GitHub Action's `new_dependencies: "true"` runs it against the pull request's base.
- `kalascan guard -- npm install <package>` scans the whole tree the install would add, at the versions npm picks (resolved first with `--package-lock-only --ignore-scripts`, which installs and runs nothing), instead of the named packages only.
- Name checks (ruleset 2026.11.8): typo-squats are compared with the 1,000 most-downloaded npm and PyPI packages (`rules/popular_packages.tsv`, `rules/gen_popular_packages.py`) plus the hand-picked targets, and also match the same words reordered (`styles-ansi`) and a scoped name without its scope (`trace-mapping`). In the operator's own manifests: `Dependency on a Node Built-in Name` (`fs`, `child_process`) and, with `--cve`, `Dependency Name Unclaimed on the Registry` (an unscoped name nobody has registered; dependency confusion and AI-invented names). Both are severity low. Coverage of the supply-chain attack tree: 7 vectors direct, 20 partial, 1 gap (was 6, 17 and 5).

### Fixed
- Security: API scans could reach an internal address through a hostname that resolves to one (or re-resolves to one, DNS rebinding) after the submit-time check. Registry, marketplace and LLM requests made for an API scan now check the address when the connection opens, and an HTTP(S) Git clone is pinned to the checked address with redirects off (`http.curloptResolve`, git 2.37 or later).
- False positives found by `watch` on new releases (ruleset 2026.11.8): AWS's documented example key (`AKIAIOSFODNN7EXAMPLE`), a site under the `.sh` top-level domain read as a shell-script download, public DNS resolvers (`https://1.1.1.1/dns-query`) read as an IP-addressed server, and `exec(base64.b64decode('{encoded}'))` in a command template, where a format placeholder stands where a payload would be.
- False positives found in the random draw (ruleset 2026.11.8): the data-flow pass read `mock.patch(…)` as an HTTP PATCH, took a process handle started with `env=` to hold the environment, and counted a `.pub` public key as a secret; `Crypto Wallet Access` fired on a link to MetaMask's Chrome Web Store page; ollama.com and cmake.org installers are vendor downloads; a `systemctl --user enable` printed for the user to run is not persistence; a Telegram URL whose token is a written placeholder (`/bot<TOKEN>/`) no longer makes an install script an exfiltration chain; `nested b64decode` no longer fires on a variable named `base64_bytes`.

### Changed
- `rules/weights.toml` refitted for ruleset 2026.11.8.

### Measured, not built
- Combosquats (a popular name plus a word, `lodash-utils`): 9% of the malicious and 9% of the clean npm names in the corpus have that form.
- Registry metadata at publish time (new package, version burst, publisher change, no repository, long-dormant release) on the npm samples' stored registry documents: no signal or pair separates the missed samples from clean npm packages (eval/README.md).

## [1.19.0] - 2026-11-19

### Added
- Detection (ruleset 2026.11.7), from reading the newest npm samples the rules missed: `Shuffled String Loader` (a packer's swap-shuffle decoder), `String Table Behind Kana Identifiers`, `Code Piped Into a Detached Interpreter` (a detached `node` with no script, fed on stdin) and `Shell Script Encoded in the Manifest` (a base64 `#!/bin/…` in `package.json`), each scored as a chain; `Chain: Obfuscated Code Appended to Readable Source` (one javascript-obfuscator line closing a file of ordinary code) and `Chain: Executable Copied Under a System Process Name` (`SearchApp.exe`, `svchost.exe`, … next to a file copy; the name on its own is the medium finding `System Process Name Assigned`) and `Chain: Hidden Bundled Binary Started Detached` (a native executable in a dot-directory of the package, plus a detached spawn). `dev` 480 → 490 of 626, holdout 478 → 480 of 683 (70%, 67-74), dated August 2026 or later 87 → 89 of 195 (46%, 39-53), clean 0 of 822. Of the 44 newest `dev` samples that were missed, 30 have no malicious code in their own files (eval/README.md, "Reading the newest misses").

### Changed
- `rules/weights.toml` refitted for ruleset 2026.11.7.

## [1.18.0] - 2026-11-19

### Added
- Detection (ruleset 2026.11.6): `Chain: Malicious New Dependency`. A scan of `npm:name@version` looks up the dependencies that version added (all of them for a package with five versions or fewer), and scans, one hop deep and three at most, the ones first published 30 days or less before it; a dependency at risk 50 or more is a finding on the package. Monorepo siblings and platform builds are skipped, and an established dependency costs one request cut off at 256 KB. Measured by replay on the dataset: 12 holdout and 11 `dev` samples that have nothing malicious in their own files (`debug-fmt` → `debug-glitz`, the hijacked `@mastra/*` → `easy-day-js`), 0 of 394 clean npm packages.
- Evaluation: `run_eval.py --since DATE` reports the holdout malware dated on or after a day as its own line and as `holdout/since-DATE` in the results file. Dated August 2026 or later: 87 of 195 (45%, 38-52), against 70% for the whole holdout.
- Evaluation: `"set": "late-2026-11"`, the 26 npm names dated August 2026 or later that were left in the dataset, in the holdout (13 of 26). The holdout is 478 of 683 (70%, 66-73); clean 0 of 822.
- `eval/sample_malicious.py --before DATE`, so a tuning batch can stay behind the newest holdout samples.

## [1.17.0] - 2026-11-18

### Added
- Detection (ruleset 2026.11.5), from a batch of 200 npm packages dated 2026 and the `dev` samples GuardDog catches and KalaScan missed: `Code Decoded From a Number Array and Evaluated` (`eval(function(s,n){…fromCharCode…}([40,109,…]))`, the payload of the compromised `autotel-*`, `awaitly-postgres` and `@redhat-cloud-services` releases; a verdict on its own); `Chain: Platform Binary Under Another Name` (an npm launcher whose command, wrapper and per-platform packages carry another name than the package, with an install hook: the `stardrop` packages); `Chain: SSH Key Planted` (a hard-coded public key written to `authorized_keys`); `Module Name Decoded From Base64` (`require(Buffer.from('ZnM=','base64').toString())`, a lead); `Code Hidden Behind Whitespace Padding`. `new (Function.constructor)("require", …)`, `axios_1.default.get(…)`, `lib.request({hostname: …})` and `run('uname -a')` are now recognised.
- Evaluation: a new holdout set drawn before those rules (`"set": "fresh2-2026-11"`, 200 samples: 150 npm from 2026, 50 PyPI from pypi_malregistry) and a separate npm tuning batch in `dev` (`"set": "tune-npm-2026-11"`, 200 samples). The holdout went from 444 to 465 of 657 (68% → 71%), `fresh2-2026-11` from 138 to 156 of 196, npm in the holdout from 201 to 221 of 361; the tuning batch from 139 to 166 of 200. Clean still 0 of 822 (three clean holdout packages flagged by a first version were fixed and moved to `dev`), no sample's score went down, evasion suite unchanged.
- Detection (ruleset 2026.11.4), from a batch of malicious IDE extensions: `Agent CLI Run With Permissions Disabled` (Amazon Q, Claude Code, Codex or Gemini CLI started with approvals off; a lead, every agent harness has it) and `Chain: Weaponised AI Agent` (the same next to a prompt that asks for deletion or for keys and wallets: `amazon-q-vscode` 1.84.0); `Split child_process Name` (`'child_proc'` + `'ess'` in an obfuscator's string table), which counts as process execution in the chains; `DNS TXT Query` and `Chain: DNS Tunnel Command Execution` (TXT answers handed to `eval` / `exec`); `Global Git Hooks Path Set` and `Chain: Git Hook Persistence` (`git config --global core.hooksPath` towards a directory the code fills).
- Evaluation: a tuning batch of 24 IDE extensions in `dev` (`"set": "tune-ext-2026-11"`, every extension name in the DataDog dataset not used before). 9 → 13 of 23. The holdout did not move (306 of 461, extensions 32 of 48); clean still 0 of 822, evasion suite unchanged.
- Evaluation: two ideas measured and not built. The registry checks replayed on the registry documents of 454 npm samples fire on one missed holdout sample, and provenance dropped with a new publisher also happened in 5 of 394 clean packages. Install hooks that hand off to another package (`npx other`, aliased dependencies) are 1 and 5 samples.
- Evaluation: GuardDog 3.2.0 run again on the whole corpus (see `eval/README.md`).
- `eval/sample_malicious.py --ecosystem ide_extensions`.

### Changed
- An oversized file is read with whitespace runs longer than 64 bytes collapsed before it is cut: 11 MB of invisible padding pushed a payload between the two ends the scanner read (`utils-mf`).
- Of a file over the 4 MiB scan limit the first 3 MiB and the last 1 MiB are scanned, not only the start: code appended to a large bundle was out of sight.

### Fixed
- `VS Code Extension Side-loading` matched a command descriptor (`{command: "workbench.extensions.installExtension", arguments: [id]}`), where the installed thing is not visible. Found on `github.copilot-chat` once the end of its bundle was read.

## [1.16.0] - 2026-11-18

### Added
- Detection (ruleset 2026.11.3): `Decrypted Code Executed` (`exec(Fernet(…).decrypt(…))`, the PyPI stealer loader), `Builtin Name Built From Characters` (`getattr(__builtins__, oct.__str__()[…] + …)`), `Code Imported From Disguised Archive` (a zip of Python modules named `server.crt` or `_websocket.typed`, loaded through `zipimport` or `sys.path`); all three are verdicts on their own. `Systemd User Service Installed` and `Chain: Install-time Persistence` (an install script that leaves a user service behind); `npm Maintainer Package Enumeration` and `Chain: npm Worm` (list every package an account maintains, then `npm publish`); javascript-obfuscator output recognised by its `['\x..']===undefined` decoder check; pinggy tunnels as an exfiltration endpoint; `npm publish` run through a script's own wrapper.
- Evaluation: a tuning batch of 150 samples in `dev` (`"set": "tune-fresh-2026-11"`: 100 npm from 2026, 50 PyPI from pypi_malregistry). Before the changes it scored 96, after them 120. On the untouched holdout: 281 → 306 of 461 (66%, 62-71), `fresh-2026-11` 78 → 89 of 159, `malregistry-2026-11` 70 → 83 of 95; clean still 0 of 822, no sample's score went down, evasion suite unchanged.
- Evaluation: a holdout set drawn after the last rule change (`"set": "fresh-2026-11"`, 161 samples: 100 npm and 1 PyPI dated August 2026 or later, 60 PyPI from pypi_malregistry). Ruleset 2026.11.2 catches 78 of 159 (49%, 41-57), npm 37 of 100; the whole holdout is now 281 of 461 (61%, 56-65), clean still 0 of 822.
- Evaluation: the sandbox measured once, in a throwaway isolated VM. Same counts as the static scan at every threshold, 0 of 822 clean flagged: the payloads the rules miss run on import or app start, not at install.

### Changed
- `eval/run_eval.py` refuses `--flag=--sandbox` unless `--disposable-vm` is passed too, and refuses `--summary` with it.

### Fixed
- `eval/fetch_malicious.sh` failed on sample paths with spaces.

## [1.15.0] - 2026-11-18

### Added
- Detection: the rules also run on each file with string disguises undone (`'fe'+'tch'`, `\x66` / `\u0066` escapes, `String.fromCharCode(…)` and `bytes([…]).decode()` literals, a reversed literal, `obj['name']`), and a hit that only shows up there is reported on its line.
- Detection: `Chain: Web Page Published as a Package` (an npm package whose entry point is an HTML or SVG document with script written into it: phishing pages and cloned sites served from the registry's CDNs); `Base64-Encoded URL`; `Buffer Decode + eval` (Node's `eval(Buffer.from(blob, 'base64'))`, a lead rather than a verdict); javascript-obfuscator output with mangled names is recognised by its decoder.
- Evaluation: a tuning batch of 80 npm packages dated August 2026 or later in `dev` (`"set": "tune-recent-2026-11"`). Measured on the untouched holdout with ruleset 2026.11.2: 193 → 202 of 302 malicious samples caught (67%, 61-72), the newest npm samples 24 → 31 of 60, and still 0 of 822 clean packages flagged. `eval/results/2026.11.2.json` is the first record written by a run.
- `--format stix`: a STIX 2.1 bundle of the scan (identity, report, one indicator per IOC, an attack-pattern per ATT&CK technique, `indicates` relationships where a finding's matched line holds the URL). Ids are stable for the same scan. Also at `/api/report/{id}/stix`.
- `--format osv`: an OSV malicious-package record (`x_KALASCAN-<scan id>`, a local id, not an assigned MAL- id) for an `npm:name@version` or `pypi:name==version` scan that reached the danger level; refused otherwise. Also at `/api/report/{id}/osv` (422 when refused).
- Evasion-resistance eval (`eval/evasion.py`, `docs/evasion.md`): 10 inert seed packages x 20 rewrites from public malware write-ups, measuring how often a caught payload stays caught. 108 of 122 variants (89%) were still caught at risk 50 when first measured, with string-construction rewrites the weak spot (62%); after the changes below it is 116 of 122 (95%) and 85%. `--baseline eval/evasion-baseline.json` fails when a caught variant is lost.
- `docs/methodology.md`: what KalaScan claims and does not, the threat model, how detection quality is measured, how to reproduce the numbers and the known limits.
- Evaluation: `eval/run_eval.py --summary FILE` writes the aggregate counts of a run (per split and sample set, thresholds 30 / 50 / 70 with Wilson bounds, errors; no sample names). `eval/results/` holds one file per ruleset version.
- `score_breakdown` in the JSON result (and one line in text and Markdown reports): the score model and the parts the risk score is the sum of. Stored with the scan (database schema v5).
- `--score-model v2` (also `score_model` in `kalascan.toml` and in API requests): a weight per finding, fitted on the `dev` split of the evaluation corpus by `eval/fit_weights.py` (`rules/weights.toml`), combined with the accumulation THOR uses; known vulnerabilities are counted apart from the score. On the holdout it is level with v1 at the default gate (193 of 302 malicious, 0 of 457 clean) and adds a range between 30 and 70 that v1 does not have, so v1 stays the default. `docs/scoring.md` has the model and the numbers.
- SARIF rules carry `security-severity` (and the `security` tag), so GitHub Code Scanning shows critical / high / medium / low and its severity gate applies.
- `kalascan rules --coverage` and `docs/coverage.md`: which vectors of the supply-chain attack tree of Ladisa et al. (IEEE S&P 2023) KalaScan covers (6 direct, 17 partial, 5 gaps, 6 payload only, 16 out of scope), and the ATT&CK techniques, MBC objective and vector of every finding. `kalascan rules <id>` prints them for one rule.
- Detection: `Chain: Dependency Confusion Install Hook` (an install script in a package whose version is all nines); `Char-Code Encoded API Name` (`require`, `child_process`, `process` or a URL spelled as decimal character codes); name and version are read from a wheel's `METADATA`, so typo-squat and dependency-confusion checks work on what pip installs.
- Evaluation: 95% Wilson intervals on every rate; `--rule-stats` (hits per class and likelihood ratio for every finding); a second, independent malicious source (100 PyPI packages from pypi_malregistry) and 60 npm packages dated August 2026 or later, both in the holdout; `eval/sample_malicious.py` to draw such sets; 299 more random clean packages in `dev`. Holdout misses are counted, not listed.
- `kalascan guard -- <install command>`: scans what `npm` / `pnpm` / `yarn` / `bun`, `pip` / `uv` or `code` / `cursor` / `windsurf --install-extension` would fetch and runs the command only when nothing reaches `--fail-on-risk` (default 50). `npm ci` and a bare `npm install` audit the lockfile. A package that cannot be scanned blocks the install.
- Data flow inside one Python or JS file: the whole environment, an SSH key or a browser / wallet store followed through variables to a network call, and a download followed to `exec` / `eval` / `new Function` / `node -e`. Reported as `Chain: Credential Exfiltration` / `Chain: Download and Execute`.
- Detection: npm install scripts that run `curl` / `nslookup` next to `$(whoami)` or a dependency-confusion version; dependencies given as an http(s) tarball on someone's own server (`Remote URL Dependency`, PhantomRaven); `setup.py` code that calls a capture service at module level; `Chain: Install-time Reconnaissance` (user or host name read by a `setup.py` install hook); DNS lookups of a host name built from data; shell `whoami` / `hostname` and `os.uname().nodename` as host recon; Telegram bot tokens outside a URL; `__import__('zlib')` / `__import__('base64')` loaders. Code decoded straight into exec is scored like a chain.
- `kalascan installed` also scans the MCP and hook configs of Cursor, Windsurf, Claude Code, Claude Desktop, VS Code and Gemini CLI (of `~/.claude.json`, only its MCP servers).
- Evaluation corpus: a tuning batch of 100 malicious samples (every 2026 PyPI package not used before, 19 from 2025, 40 npm from 2026) in the `dev` split, `"set": "tune-2026-11"`. Measured on the untouched holdout: 82 → 94 of 147 malicious samples caught (PyPI 22 → 33 of 48), none lost, and still 0 of 526 clean packages flagged.
- AI agent files and MCP servers: `SKILL.md`, `CLAUDE.md`, `AGENTS.md`, Cursor and Copilot rule files, MCP configs and Claude Code settings and hooks are scanned for hidden text (Unicode tags, zero-width and bidi characters, directives in HTML comments), instructions to hide actions from the user or override earlier instructions, and the builtin download, exfiltration and credential rules. MCP server code gets the same instruction checks on its tool descriptions. New chains: `Chain: Malicious Agent Instruction` and `Chain: Agent Config Runs Remote Code`.
- `kalascan installed` also lists Claude Code plugins (`~/.claude/plugins/cache`) and skills (`~/.claude/skills`).
- Evaluation corpus: 299 clean packages drawn at random from all of npm and PyPI (`eval/sample_clean.py`), not picked. One legitimate package among them was flagged (fixed below); the clean set is now 526 samples.
- Sandbox: a simulated network inside the isolated container. Names resolve to a loopback stand-in that answers DNS and accepts HTTP and TLS, so the report shows the hosts, request lines and TLS server names a sample asked for, and each host becomes a `sandbox-host` indicator. The container still has no network.
- Sandbox: `--sandbox-runtime <NAME>` / `KALASCAN_SANDBOX_RUNTIME` runs the container under another OCI runtime, for example gVisor's `runsc`.
- Fuzz targets (`fuzz/`, cargo-fuzz) for the report importers, lockfile parsers, archive extraction, rule files, text analyzers, binary triage and emulation, the deobfuscator and the strace parser, with a weekly Fuzz workflow.
- `eval/run_eval.py --scanner guarddog` measures GuardDog on the same corpus.
- Evaluation corpus: 120 fresh malicious samples (2026 npm and PyPI packages, extensions) join the holdout split. The published detection rate is now the holdout figure, 82 of 147 (56%); the earlier 26 of 27 came from too few samples.

### Security
- A failed package download no longer shows credentials from its URL in the scan status, history, reports or the server log.
- A server that started with a token or users keeps requiring auth when its last user is removed or its database cannot be read; it used to grant anonymous admin. `kalascan user remove` prints a note when it removes the last user.
- Requests without valid credentials write at most 30 audit rows per minute, audit details are cut at 512 characters, and `GET /api/audit` returns the newest 200 denied requests plus the newest 200 other entries, so a flood of 401s cannot hide real actions.
- On a loopback server without auth, the DNS-rebinding Host check covers every path, including the dashboard page `/` that embeds scan history.
- Each server log record is one line: CR and LF inside logged values are written as `\r` and `\n`.
- Web API: a target shaped like a marketplace id (`budget.xlsx`) is no longer read from the server's working directory; only the CLI opens a local package file.
- `kalascan serve`: scans resumed after a restart are checked against the current target rules again (`KALASCAN_ALLOW_PRIVATE_TARGETS` included). One that no longer passes is marked `failed: not resumed`, as is a queued upload.
- `kalascan serve`: at most 64 scans are queued or running at once; further submissions get HTTP 429.
- API scans: `llm_endpoint` gets the same internal-address refusal as the scan target, except the built-in local Ollama and 9Router defaults; `KALASCAN_ALLOW_PRIVATE_TARGETS=1` allows it. LLM requests no longer follow redirects, and replies are read through a 1 MiB cap.
- `--git-history`: a file larger than 1 MiB in an old commit is no longer read into memory before it is skipped.
- API, upload and resumed scans run `git clone` / `git fetch` without the server user's credential helpers, `~/.netrc`, ssh keys or agent, and without prompting. Private repositories need credentials in the URL. The CLI is unchanged.
- Sandbox: at most 2 MiB of container stdout and 64 KiB of stderr are held; a container that prints more is stopped and its truncated trace analysed.
- Text output of `scan`, `import`, `diff` and the `deps` package column shows control characters from scanned content as escapes, continues embedded line breaks under `|`, and never starts a line with `::`; `--format github` escapes ESC and other control characters.

### Fixed
- `kalascan serve` stops cleanly on Ctrl-C or SIGTERM (`docker stop`) and removes the temp dirs of its queued and running scans.
- The triage, correlation, deobfuscation and emulation passes run on the blocking pool, so a one-CPU server keeps answering (`/healthz` included) during a scan and the scan timeout can fire.
- ATT&CK techniques of KalaScan's own findings are written out per finding instead of guessed from keywords in the name: `GitHub Actions Script Injection` was Process Injection, `Make File Executable` a script interpreter, and install-time findings were all Event Triggered Execution.
- Four false positives found in a fresh random draw of 297 clean packages: a link to a `.sh` source line inside a webpack `eval` module, a `curl … .EXE` in `circle.yml` counted as reachable from an npm install script, a curl command line kept in a variable read as downloaded content, and zc.buildout's `bootstrap.py` fetching `ez_setup.py`. With the first draw the measured rate on random packages is 5 in 595 (0.8%, 0.4-2.0).
- The eval harness scanned a `sources/` checkout instead of the wheel for some PyPI samples.
- `Chain: Reconnaissance Beacon` no longer fires on a hostname read plus the Telegram API host: agents and bots call it with the user's own token. A bot token written into the code still counts. Malicious recall is unchanged.
- CI: the `false-positives` check runs on every pull request and skips the scan when no detection code or corpus changed. With a paths filter it never reported on Dockerfile- or workflow-only PRs, so Dependabot updates could not be merged.

### Changed
- The Detection eval workflow also runs weekly, so registry drift under the fixed clean corpus shows up without a pull request.
- An oversized package download reports "Response too large" instead of "Package too large".
- Timestamps come from the `time` crate (already in the dependency tree) instead of `chrono`, which RustSec lists as unmaintained (RUSTSEC-2026-0543). New timestamps end in `Z` instead of `+00:00`; both are RFC 3339.
- The crate is a library (`src/lib.rs`) with a thin binary (`src/main.rs`), so the fuzz targets can call the parsers. No behaviour change.

### Changed
- ATT&CK mapping follows Enterprise ATT&CK v20.1: findings formerly under the Defense Evasion tactic are reported under Stealth or Defense Impairment, `T1562` / `T1562.001` / `T1562.006` became `T1685` (Disable or Modify Tools), `T1070.001` / `T1070.002` became `T1685.005` / `T1685.006`, and `T1036.005` and `T1176` carry their current names. Reports and SARIF exported by earlier versions keep the old ids.

### Added
- Dashboard: "Remember key in this browser" keeps the AI provider API key (one per provider) in the browser's localStorage. Off by default; switching it off deletes the saved keys. Switching provider no longer carries a typed key over to another provider.

### Fixed
- Dashboard: the rule count is the real number of built-in rules (it said "50+"), and the "0 code exec" claim is gone: nothing runs unless the sandbox is switched on.
- Dashboard: scan progress shows the server's state and the elapsed time instead of an invented percentage.
- Dashboard: package files can be dropped onto the upload area; the label offered it but only clicking worked.
- Dashboard: errors appear in the page instead of browser alerts.
- Dashboard: keyboard focus is visible on every control, and the upload area and history entries can be reached and activated with the keyboard.

## [1.14.0] - 2026-11-15

### Added
- `kalascan deps` reads `yarn.lock` (classic and Berry), `pnpm-lock.yaml` (v5-v9), `uv.lock` and `Cargo.lock`, and keeps results in `~/.cache/kalascan` (`KALASCAN_CACHE_DIR`) so a package is downloaded and scanned once per KalaScan and ruleset version; `--no-cache` scans everything again.
- `crates:name[@version]` scan targets (crates.io), for `scan`, `diff`, `deps` and the API.
- `Chain: Phishing Redirect Package`: an npm package with no dependencies whose only code sends the browser to a hard-coded site.
- A name cut across two `splitStrings` pieces of a javascript-obfuscator string table (`readF` + `ileSy`) is put back together.
- javascript-obfuscator string tables encoded with `rc4` are decrypted with the keys found at the call sites, so the `Chain: Obfuscated Credential Theft` / `Obfuscated Download and Execute` checks cover them.
- CLI integration tests for `diff`, `deps`, `installed`, `rules`, `sbom`, `import` and the web API (upload, status polling, local-path refusal), all offline.
- CI scans the repository with the freshly built binary (`.kalascanignore` lists the files that hold detection signatures).

### Changed
- The popular-extension list behind `Repackaged Copy of Popular Extension` covers the 10,000 most-installed extensions (was 2,000). Detection on the eval corpus: 85 of 100 malicious samples (was 81), still 0 of 227 clean ones.
- `src/main.rs` is split: the web server moved to `src/server.rs`, the CLI subcommands to `src/commands.rs`, the HTML report to `src/export/html.rs`. No behaviour change.

### Security
- The web server no longer sends permissive CORS headers (`Access-Control-Allow-Origin: *`) and refuses requests from another origin with 403. Before, any web page open in the same browser could queue scans on a loopback server without a token and read its results.
- A loopback server without a token or users answers only requests whose `Host` is `localhost`, `127.0.0.1` or `[::1]` (DNS rebinding).

### Fixed
- `./.kalascanignore` is applied only to a checkout scanned in place. It used to filter every target scanned from that directory, so a pattern such as `src/*` hid findings in downloaded packages; `--ignore <FILE>` still applies to any target.
- Piping output into a command that stops reading (`kalascan scan . --format json | head`) no longer ends in a panic message and exit 101; the run exits 141, as a SIGPIPE death would.

## [1.13.0] - 2026-11-08

### Added
- `kalascan import <FILE>` normalizes Nessus, Nmap, Burp Suite, OWASP ZAP, Nuclei, Qualys and CSV scanner reports into one finding format (`--format text|json|sarif`, `--fail-on`); XML entity declarations are refused.
- `kalascan.toml` configuration file so a team can commit its scan policy (threshold, rules, YARA directory, ignore file, baseline); command-line flags override it.
- `--max-commits` and `--since` bound `--git-history` scans.
- CLI integration tests that run the `kalascan` binary and check output formats and exit codes.
- `[profile.release]` for a smaller, faster release binary; `rust-version = "1.95"` declares the minimum supported Rust.
- `deny.toml` and a `cargo-deny` CI job: RustSec advisories fail the build, licences must be on the allow-list, duplicate crate versions are reported.
- Dependabot restored for Cargo, Docker and GitHub Actions: one grouped minor/patch PR per week with a 7-day cooldown, auto-merged after CI passes.
- Release pipeline: the tag must match `Cargo.toml` and have an entry in this file; the release body is taken from it; a CycloneDX SBOM of the source tree, keyless cosign signatures (`*.sigstore.json`) and a SLSA build-provenance attestation are attached to every release.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CITATION.cff`, `docs/` (architecture, detection rules, web UI security), issue and pull request templates, OpenSSF Scorecard workflow.

### Changed
- The regex pass covers more source files (`.jsx .tsx .rb .go .rs .lua .pl .psm1 .cs .swift .groovy .gradle`), CI files (`.yml` / `.yaml`, exfiltration / network / supply-chain / secret rules only) and `Dockerfile` / `Makefile` / `Justfile`, so an application repository no longer scores 0 because none of its files were looked at.
- `KS-RAN-004` (Ransom Note) matches whole words only and is `high`; it becomes the critical `Chain: Ransomware` when it sits within 4 KB of a file-encryption rule. In the risk score a single unchained critical finding counts 20 instead of 35; chains and multiple criticals still reach the 70 cap.
- In-place repository scans run only YARA on vendored or minified code (`*.min.js`, `*bundle*.js`, `vendor/`, `dist/`, `node_modules/`), which removed the regex noise from bundled third-party JavaScript.
- `--git-history` reports each finding once, at the commit where it first appeared, instead of once per revision of the file.
- SARIF `tool.driver` carries the KalaScan version; CLI JSON fills `duration_ms`.
- `Cargo.toml` uses the SPDX id `GPL-3.0-only`; `Cargo.lock` picks up the RustSec fixes for rustls, rustls-webpki, wasmtime and crypto-bigint.

### Fixed
- `RUST_LOG` is honoured (the log filter was hard-coded to `kalascan=info`).
- The weekly Security scan no longer fails on historical gitleaks fingerprints from rule examples.

## [1.12.0] - 2026-10-31

### Added
- Registry metadata checks for npm and PyPI packages: manifest confusion, install-script and provenance regressions between versions, lapsed maintainer e-mail domains, AI-vendor repository impersonation.
- `kalascan deps [PATH]` scans every version pinned by `package-lock.json`, `poetry.lock`, `Pipfile.lock` or `requirements.txt`.
- `--secrets`: 208 credential patterns converted from gitleaks (`rules/secrets.toml`, MIT), medium severity, config files included.
- Obfuscator string-table decoding, install-time sandbox tracing of npm scripts / `setup.py` / `.pth` files, GuardDog YARA conventions (`path_include`, `ecosystem`) in `--yara-dir`.
- Rules: fetch-then-eval download cradles, npm `install` scripts as install hooks, hex-encoded API names chained with host recon, aliased `os` / `subprocess` imports in `setup.py`, destructured `child_process`.

### Changed
- Work-stealing scan with one YARA scanner per worker and ASCII word boundaries (drawio: 17 s to 2 s).
- Baseline fingerprints no longer include line numbers; `--update-baseline` writes the file, `--new-only` only reads it.
- `tera` dropped (69 crates); the UI templates use plain substitution. `openapi.yaml` takes its version from the binary.
- Recall on the eval corpus 74 to 81 of 100 malicious samples, 0 of 227 clean false positives.

### Fixed
- Scanner evasions: multibyte context no longer panics and drops a worker's findings; a `/*` string no longer hides later matches; build directories and `kalascan:ignore` markers only apply to the operator's own checkout (`--untrusted` for third-party code on disk).
- Exports: CSV cells never start a formula, JUnit drops XML-illegal control characters, SARIF locations are URIs, Markdown escapes every cell.
- `install.sh` verifies the checksum; the GitHub Action builds from its own ref; README examples run as written.
- Low-entropy rule examples so the gitleaks gate passes.

### Security
- Downloads are time- and size-capped and zip totals count bytes written; API targets on internal hosts are refused; credentials in repository URLs are redacted from logs, history and reports.

## [1.11.0] - 2026-10-31

### Added
- 8 new rules and 5 behaviour chains: remote-code loaders (`new Function('require', …)` + fetch), VS Code extension side-loading, AI API traffic hijack (`ANTHROPIC_BASE_URL` persisted to shell profiles), system discovery, npm spam publishers, escaped `eval` payloads.
- Repackaged copies of the 2,000 most-installed VS Code extensions are flagged through their `repository` field (`rules/popular_extensions.tsv`).
- Dependency-confusion versions, install-time exfiltration and payload chains, zip-slip taint tracking, GitHub Actions workflow checks (pwn request, script injection, unpinned actions), `npm:` / `pypi:` registry targets.
- `kalascan installed`, `kalascan diff`, `kalascan rules`; rules as data in `rules/builtin.toml` with stable ids and examples verified on load; `--rules` for custom rules.
- Labelled eval corpus (`eval/`) with a false-positive gate in CI; IOC extraction with URLhaus lookups; listing and publisher reputation checks.
- `SECURITY.md`.

### Changed
- Eval corpus grown to 100 malicious + 227 clean samples; held-out recall 65% (was 58%), 0 false positives on the 227 clean packages.
- Docker images build natively per architecture and are merged into one manifest; every GitHub Action is pinned to a commit SHA.
- Dependency updates: zip 9, rusqlite 0.41, toml 1.1, tokio 1.54, yara-x 1.22.1, Rust 1.98 image. The local scan database is no longer tracked.

### Fixed
- False positives found by the clean corpus (greedy PowerShell / `bcdedit` regexes, web3 IPC paths, bidi regex ranges, official installers, firebase-tools); legitimate extensions no longer score 100.
- Entropy scanner panic on multi-byte tokens; VSIX entries over 128 MiB are truncated instead of failing the scan; installed-extension tampering is detected.
- Upload body cap raised to 1 GiB; stale `:latest` Docker tags.

### Security
- The API rejects local paths and CLI-only options; `serve` refuses an unauthenticated non-loopback address; git option injection through `base_ref` / `repo_url` is rejected; the spoofable `github.actor` check in CI was fixed.

## [1.10.0] - 2026-10-25

### Added
- `GET /api/sbom[?path=…]`: CycloneDX 1.5 SBOM for a directory under the server working directory (auth required; paths outside it are refused after canonicalization).
- Dashboard bearer token: every fetch attaches the token held in `sessionStorage` (tab-scoped, never persisted) and prompts once on 401.
- linux/arm64 Docker image; the GHCR package is made public after each push.

### Changed
- UI templates and `static/app.css` are embedded in the binary, so `kalascan serve` works from any directory.
- Every remaining hard-coded version string derives from `CARGO_PKG_VERSION`; `openapi.yaml` documents `/api/sbom` and `/api/audit`.

### Fixed
- `POST /scan` with only `repo_url` no longer fails deserialization (LLM fields default).
- Body limit raised so real `.vsix` uploads work; the installer resolves assets through the API and was simplified once the repository went public.

## [1.9.0] - 2026-10-25

### Added
- Parallel file scanning (up to 16 threads) with deterministic finding order.
- `kalascan sbom <dir> [-o file]`: CycloneDX 1.5 SBOM from manifests and lockfiles, offline.
- One-line install script (`install.sh`) for the prebuilt release binaries.

### Changed
- Engine and version strings derive from `CARGO_PKG_VERSION`.
- Clippy-clean code base; CI enforces `-D warnings`; the release matrix caches cargo; the Docker builder no longer needs pkg-config / libssl-dev.

## [1.8.0] - 2026-10-25

### Added
- Multi-user RBAC: `users` table with viewer / operator / admin roles, `kalascan user add|list|remove`, tokens stored as salted SHA-256 and shown once; `KALASCAN_TOKEN` remains a legacy admin token.
- Append-only `audit_log` and the admin-only `GET /api/audit`.
- Prometheus `GET /metrics`, `GET /healthz` liveness endpoint, `GET /openapi.yaml`.
- Export formats `csv`, `junit` and `github` (Actions annotations) for `--format` and `/api/report/{id}/{format}`.
- `kalascan rules` lists the ruleset; `kalascan rules <name>` explains a rule.

### Changed
- Schema v3; queued scans persist their request (API keys stripped) and resume on boot; `KALASCAN_HISTORY_LIMIT` (500) and `KALASCAN_MEMORY_SCANS` (100) bound storage.
- Release builds use rustls so the aarch64 Linux target builds; the GitHub release is created before the assets are uploaded.

### Fixed
- `openapi.yaml` is copied into the Docker builder stage.

[Unreleased]: https://github.com/wahidhendrawan/KalaScan/compare/v1.27.0...HEAD
[1.27.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.26.0...v1.27.0
[1.26.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.25.0...v1.26.0
[1.25.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.24.0...v1.25.0
[1.24.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.23.0...v1.24.0
[1.23.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.22.0...v1.23.0
[1.22.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.21.0...v1.22.0
[1.21.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.20.0...v1.21.0
[1.20.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.19.0...v1.20.0
[1.19.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.18.0...v1.19.0
[1.18.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.17.0...v1.18.0
[1.17.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.16.0...v1.17.0
[1.16.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.15.0...v1.16.0
[1.15.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.14.0...v1.15.0
[1.14.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.13.0...v1.14.0
[1.13.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.11.0...v1.12.0
[1.11.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.10.0...v1.11.0
[1.10.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.9.0...v1.10.0
[1.9.0]: https://github.com/wahidhendrawan/KalaScan/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/wahidhendrawan/KalaScan/releases/tag/v1.8.0
