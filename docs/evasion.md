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
so a rule change cannot silently lose robustness.

The suite was measured twice. The first run (ruleset 2026.11.1) was published as
found: 108 of 122, with string construction at 62%. The scanner was then changed
for the two largest groups of evasions, and the second run (ruleset 2026.11.2) is
the table below. **Read the second number with that in mind**: these mutators
are now known to the scanner, so it says the fixes work, not how the scanner
does against a rewrite nobody has tried on it yet. New mutators are the way to
ask that again.

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

## Result (ruleset 2026.11.2, score model v1, T=50)

| mutation category | first run (2026.11.1) | now (2026.11.2) | mutators |
|---|---|---|---|
| file placement and naming | 24/24 | 24/24 (100%, 86-100) | main-as-doc, no-extension, git-dir-archive, pth-file |
| comment and whitespace | 18/18 | 18/18 (100%, 82-100) | hash-prefixed-js, block-comment-earlier, thousand-spaces, line-continuation |
| indirection | 16/16 | 16/16 (100%, 81-100) | alias-require, globalThis, getattr-import, second-file |
| packaging | 29/30 | 29/30 (97%, 83-99) | node-modules-dir, minify-one-line, pad-past-dataflow |
| string construction | 21/34 (62%) | 29/34 (85%, 70-94) | split-concat, hex-escape, char-codes, base64-layer, reversed-strings |
| **all** | **108/122 (89%)** | **116/122 (95%, 90-98)** | |

95% Wilson intervals in brackets. A mutator that cannot touch a seed (e.g.
`.pth` on an npm seed, `getattr-import` on JS) is skipped, not counted as caught,
so the denominators are real cross products minus skips.

### What changed between the two runs

- **The rules also run on the text with string disguises undone**
  (`obfuscator::plain`, used by `scan_bytes` in src/scanner.rs): `'fe'+'tch'`
  joined, `\x66` and `\u0066` escapes decoded, `String.fromCharCode(…)` and
  `bytes([…]).decode()` literals decoded, a reversed literal turned back, and
  `obj['name']` read as `obj.name`. A hit that only shows up there is reported on
  its line. This closed all five split-name pairs and the hex-escape and
  reversed-string pairs.
- **`Buffer Decode + eval` (KS-EXE-034)** names Node's
  `eval(Buffer.from(blob,'base64'))`. It is a critical finding that does not
  count twice, so alone it is a lead (27 here), not a verdict: see below.

### What each category shows

- **File placement and naming — no gap.** Moving the payload into a file the
  manifest runs (`.txt` `main`, extensionless `#!` `bin`), into a top-level
  `.git/` directory of an archive, or into a `.pth` file does not hide it. The
  scanner decides what is code by what runs, not by extension
  (`runs_as` / `package_entry_points`, src/scanner.rs), and scans a
  package's `.git` (`skip_dir`, src/scanner.rs). These are the four evasions
  fixed earlier; all stay caught (git-dir 10/10, hash-prefixed 5/5, doc/no-ext
  10/10, pth 4/4).

- **Comment and whitespace — no gap.** A `#`-prefixed JS line is a private member,
  not a comment; a `/*` mid-line with no `*/` before the hit, 1000 leading spaces,
  and shell line continuation all stay caught. The comment check only treats a
  line as commented when it *opens* with the marker and the block is still open
  (`is_comment_only_line`, src/scanner.rs).

- **Indirection — no gap.** Aliasing `require`, `globalThis['pro'+'cess']`,
  `getattr(__import__('os'),'system')`, and splitting the payload into a second
  imported module all stay caught, because the host-identity / webhook / socket
  rules still fire on the parts the indirection does not touch.

- **Packaging — one gap.** Minifying onto one line and padding past the 64 KB
  data-flow limit (`MAX_BYTES`, src/dataflow.rs) stay caught: the regex layer carries them
  even where the data-flow pass bows out. The one miss is a `setup.py` moved under
  `node_modules/dep/` (below).

- **String construction: still the weakest (85%).** What remains is a payload
  wholly inside a base64 blob in a package with no other signal.

## Evading pairs, grouped by the limit each hits

Six pairs evade.

**1. The whole payload in a base64 blob that is evaluated, JS only.** 4 pairs
under `base64-layer`, each scoring 27: `npm-cred-exfil`, `npm-reverse-shell`,
`vscode-token-steal`, `npm-discord-stealer`. `Buffer Decode + eval` fires, and
nothing else is visible. It is deliberately not a verdict by itself: a
legitimate commercial extension (Quokka) ships exactly this shape, a base64
blob of obfuscated code passed to `eval`, as licence protection, and a rule that
flags the four seeds flags it too. The Python form
(`exec(base64.b64decode(...))`) is caught, and so is the npm seed whose blob is
run from an install script (`Chain: Install-time Payload Execution`).
`--deobfuscate` decodes such blobs and is opt-in.

**2. A call through a character-code string.** 1 pair: `npm-install-dl-exec`
under `char-codes` (10). The mutator turns `fetch(…)` into
`String.fromCharCode(102,…)(…)`, which is not valid JavaScript (a string is
not callable), so the undone text reads `'fetch'(…)` and the download-cradle
rule does not match it. The valid spelling, `globalThis[String.fromCharCode(…)](…)`,
is undone to `globalThis.fetch(…)` and caught.

**3. Install hook in a nested package unit.** 1 pair: `pypi-setup-hook` under
`node-modules-dir` (17). Correlation runs install-time chains only for the root
unit (`correlate_unit`, src/correlate.rs), because a bundled dependency's own
`setup.py` does not run at the top package's `pip install`. This is close to
correct behaviour, not a pure miss, and is recorded because it is a measurable
way to push a caught seed under the threshold.

## Takeaway

Placement, comment and whitespace, indirection and packaging tricks do not hide
a payload from KalaScan. Split and encoded names no longer do either. What still
does is putting the entire payload inside one encoded blob in a package that
shows nothing else: the scanner reports the blob and leaves the verdict to a
second signal. The baseline (`eval/evasion-baseline.json`) pins the 116 caught
pairs.
