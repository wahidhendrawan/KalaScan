# Evasion resistance

When a payload KalaScan catches is rewritten the way attackers rewrite package
malware, how often is it still caught? `eval/evasion.py` measures it: 10 inert
seed packages (npm, PyPI, VS Code), each the shape a rule looks for but pointing
only at reserved names (`evil.example`, `webhook.site` with an all-zero id,
placeholder tokens), crossed with 20 mutators drawn from public write-ups. No
fixture is ever executed; the scanner only reads files.

```bash
cargo build                                   # CARGO_TARGET_DIR per eval/README.md
python3 eval/evasion.py --kalascan target/debug/kalascan
python3 eval/evasion.py --baseline eval/evasion-baseline.json   # gate a change
```

Each seed scores >= 50 unmutated, or the runner refuses it. `--baseline` exits 1
when a (seed, mutator) pair that was caught in the baseline is no longer caught,
so a rule change cannot silently lose robustness. The evasions below are
**findings to publish, not rules to re-tune**: detection rules were not changed
to improve these numbers.

## Seeds

| seed | eco | detects |
|---|---|---|
| `npm-install-dl-exec` | npm | postinstall runs a `fetch(...).then(eval)` download cradle |
| `npm-cred-exfil` | npm | reads `~/.ssh/id_rsa` + `process.env`, POSTs to a webhook |
| `npm-reverse-shell` | npm | `net.Socket` piped to `child_process` spawn of `/bin/sh` |
| `npm-dep-confusion` | npm | version `99.99.99` + preinstall `curl`/`whoami` probe |
| `pypi-import-loader` | pypi | `exec(__import__('zlib').decompress(__import__('base64')...))` |
| `pypi-setup-hook` | pypi | `cmdclass` install override running `whoami` / `os.uname` |
| `pypi-cred-exfil` | pypi | reads `~/.ssh/id_rsa`, `requests.post` to a webhook |
| `pypi-download-cradle` | pypi | setup.py `os.system('curl ... | sh')` |
| `vscode-token-steal` | extension | `vscode.authentication.getSession` then POST to a webhook |
| `npm-discord-stealer` | npm | Discord leveldb read + Discord webhook exfil |

## Result (debug build, ruleset 2026.11.1, score model v1, T=50)

| mutation category | still caught | mutators |
|---|---|---|
| file placement and naming | 24/24 (100%, 86-100) | main-as-doc, no-extension, git-dir-archive, pth-file |
| comment and whitespace | 18/18 (100%, 82-100) | hash-prefixed-js, block-comment-earlier, thousand-spaces, line-continuation |
| indirection | 16/16 (100%, 81-100) | alias-require, globalThis, getattr-import, second-file |
| packaging | 29/30 (97%, 83-99) | node-modules-dir, minify-one-line, pad-past-dataflow |
| string construction | 21/34 (62%, 45-76) | split-concat, hex-escape, char-codes, base64-layer, reversed-strings |
| **all** | **108/122 (89%, 82-93)** | |

95% Wilson intervals in brackets. A mutator that cannot touch a seed (e.g.
`.pth` on an npm seed, `getattr-import` on JS) is skipped, not counted as caught,
so the denominators are real cross products minus skips.

### What each category shows

- **File placement and naming — no gap.** Moving the payload into a file the
  manifest runs (`.txt` `main`, extensionless `#!` `bin`), into a top-level
  `.git/` directory of an archive, or into a `.pth` file does not hide it. The
  scanner decides what is code by what runs, not by extension
  (`runs_as` / `package_entry_points`, src/scanner.rs:566, 602), and scans a
  package's `.git` (`skip_dir`, src/scanner.rs:349). These are the four evasions
  fixed earlier; all stay caught (git-dir 10/10, hash-prefixed 5/5, doc/no-ext
  10/10, pth 4/4).

- **Comment and whitespace — no gap.** A `#`-prefixed JS line is a private member,
  not a comment; a `/*` mid-line with no `*/` before the hit, 1000 leading spaces,
  and shell line continuation all stay caught. The comment check only treats a
  line as commented when it *opens* with the marker and the block is still open
  (`is_comment_only_line`, src/scanner.rs:1103).

- **Indirection — no gap.** Aliasing `require`, `globalThis['pro'+'cess']`,
  `getattr(__import__('os'),'system')`, and splitting the payload into a second
  imported module all stay caught, because the host-identity / webhook / socket
  rules still fire on the parts the indirection does not touch.

- **Packaging — one gap.** Minifying onto one line and padding past the 64 KB
  data-flow limit (src/dataflow.rs:126) stay caught: the regex layer carries them
  even where the data-flow pass bows out. The one miss is a `setup.py` moved under
  `node_modules/dep/` (below).

- **String construction — the real weak spot (62%).** Rewriting API-name strings
  defeats the literal regex rules for seeds whose detection hinges on one name.

## Evading pairs, grouped by the limit each hits

All 14 misses are in string construction plus one packaging case.

**1. Literal API names split across a `+` (`fe'+'tch`, `requ'+'ire`).** 5 pairs:
`npm-install-dl-exec`(5), `npm-cred-exfil`(6), `npm-reverse-shell`(21),
`vscode-token-steal`(0), `npm-discord-stealer`(21). The built-in rules match
literal names (`fetch\(`, `require(...child_process...)`, `getSession`,
rules/builtin.toml) and `rule_spans` runs them on raw file text with no
concatenation folding on the default path (src/scanner.rs:234). `--deobfuscate`
is opt-in and the eval runs the default pipeline.

**2. JS base64 via `Buffer.from(x,'base64')`.** 5 pairs: all JS seeds under
`base64-layer` — `npm-install-dl-exec`(11), `npm-cred-exfil`(7),
`npm-reverse-shell`(7), `vscode-token-steal`(7), `npm-discord-stealer`(7). The
`b64decode + exec` chain (KS-EXE-003, rules/builtin.toml) keys on `atob` /
`b64decode` / `from_base64`, not Node's `Buffer.from(...,'base64')`, so only
`eval() Usage` (high) remains and the score falls to ~7. The Python form of the
same mutator (`exec(base64.b64decode(...))`) **is** caught — KS-EXE-003 sees
`b64decode` — which is why this is a JS-only gap.

**3. Encoded single API name outside the enumerated set.** 3 pairs, all on
`npm-install-dl-exec`: `hex-escape`(5), `char-codes`(10), `reversed-strings`(10).
The `Hex-Encoded API Name` (KS-EXE-030) and `Char-Code Encoded API Name`
(KS-EXE-032) rules enumerate fixed byte sequences (`require`, `child_process`,
`https://`, `fetch(` …); a bare hex/char-code/reversed `fetch` is not one of them,
so this fetch-then-eval seed drops below 50 while seeds with a second strong
signal survive the same mutator.

**4. Install hook in a nested package unit.** 1 pair: `pypi-setup-hook` under
`node-modules-dir`(17). Correlation runs install-time chains only for the root
unit (`correlate_unit` is called with `hooks_run = unit.is_empty() && ...`,
src/correlate.rs:341,346; gated at 369/385/405), because a bundled dependency's
own `setup.py` does not run at the top package's `pip install`. Moving the payload
into `node_modules/dep/setup.py` therefore drops the `Chain: Install-time
Reconnaissance` and leaves only non-decisive findings. This one is close to
correct behaviour, not a pure miss — but it is still a measurable way to push a
caught seed under threshold, so it is recorded.

## Takeaway

Placement, comment/whitespace, indirection and packaging tricks do not hide a
payload from KalaScan — the earlier hardening holds. String construction is where
recall drops: literal-name regexes are blind to split names, and the encoded-name
and base64 rules cover a fixed vocabulary that a one-signal payload can step
outside (notably JS `Buffer.from(...,'base64')`). Seeds with two independent
strong signals survive these mutators; single-signal payloads do not. The
baseline (`eval/evasion-baseline.json`) pins the 108 caught pairs so none of this
robustness is lost by accident.
