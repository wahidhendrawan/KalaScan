# Evasion resistance

When a payload KalaScan catches is rewritten the way attackers rewrite package
malware, how often is it still caught? `eval/evasion.py` measures it: 10 inert
seed packages (npm, PyPI, VS Code), each the shape a rule looks for but pointing
only at reserved names (`evil.example`, `webhook.site` with an all-zero id,
placeholder tokens), crossed with 37 mutators drawn from public write-ups. No
fixture is ever executed; the scanner only reads files.

```bash
cargo build                                   # CARGO_TARGET_DIR per eval/README.md
python3 eval/evasion.py --kalascan target/debug/kalascan
python3 eval/evasion.py --baseline eval/evasion-baseline.json   # gate a change
python3 eval/evasion.py --check-syntax        # every variant parses (node, ast, sh -n)
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
ask that again, and a third run (ruleset 2026.11.8) did: eight mutators written
for it and never run against the scanner before (`atob-layer`,
`template-literal`, `unicode-escape`, `bracket-member`, `dynamic-import`,
`importlib`, `compile-exec`, `node-e-hook`) gave 31 variants, and the first run
caught all 31. No rule was changed for them.

A fourth round (ruleset 2026.11.16) did it again, after first checking that
every variant parses: five rewrites had been writing code that does not
(`#fetch(`, `fe'+'tch(`, `\x66etch(`, a Python line opened with spaces,
Python joined onto one line), and were rewritten to valid code. Nine new
rewrites brought the suite to 212 variants, and **ruleset 2026.11.15 caught
181 of them (85%)** on the first run. Ruleset 2026.11.16 was changed for
those misses and catches 211.

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

## Result (score model v1, T=50)

| mutation category | first run (2026.11.1) | after the fixes (2026.11.2) | with the eight new mutators (2026.11.8) | mutators |
|---|---|---|---|---|
| file placement and naming | 24/24 | 24/24 (100%, 86-100) | 25/25 (100%, 87-100) | main-as-doc, no-extension, git-dir-archive, pth-file, node-e-hook |
| comment and whitespace | 18/18 | 18/18 (100%, 82-100) | 18/18 (100%, 82-100) | hash-prefixed-js, block-comment-earlier, thousand-spaces, line-continuation |
| indirection | 16/16 | 16/16 (100%, 81-100) | 31/31 (100%, 89-100) | alias-require, globalThis, getattr-import, second-file, bracket-member, dynamic-import, importlib, compile-exec |
| packaging | 29/30 | 29/30 (97%, 83-99) | 29/30 (97%, 83-99) | node-modules-dir, minify-one-line, pad-past-dataflow |
| string construction | 21/34 (62%) | 29/34 (85%, 70-94) | 44/49 (90%, 78-96) | split-concat, hex-escape, char-codes, base64-layer, reversed-strings, atob-layer, template-literal, unicode-escape |
| **all** | **108/122 (89%)** | **116/122 (95%, 90-98)** | **147/153 (96%, 92-98)** | |

With ruleset 2026.11.11 (encoded literals read as code, below): string
construction 48/49 (98%, 89-100), **all 151/153 (99%, 95-100)**; the other
categories as in the last column.

The suite as it stands, 37 mutators (the five broken ones rewritten, nine
added: `comment-between`, `base64-variable`, `base64-split`, `zlib-layer`,
`hex-layer`, `xor-layer`, `string-table`, `source-other-file`, `npm-run-hook`):

| mutation category | first run (2026.11.15) | ruleset 2026.11.16 |
|---|---|---|
| file placement and naming | 27/27 | 27/27 (100%, 88-100) |
| comment and whitespace | 23/27 | 27/27 (100%, 88-100) |
| indirection | 33/34 | 34/34 (100%, 90-100) |
| packaging | 24/25 | 24/25 (96%, 80-99) |
| string construction | 74/99 | 99/99 (100%, 96-100) |
| **all** | **181/212 (85%, 80-90)** | **211/212 (100%, 97-100)** |

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
  package's `.git` (`skip_dir`, src/scanner.rs). Since ruleset 2026.11.15 that
  includes a file an install script hands to an interpreter
  (`"postinstall": "node install.txt"`, `script_files`) and an extensionless
  file a relative `require` loads; neither is a mutator of the suite yet. These are the four evasions
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

One pair evades with ruleset 2026.11.16, the third below. Of the 31 the first
run of the larger suite missed, 9 were a payload XORed with one constant, 13
a blob in a variable, in pieces or under zlib, 4 a long comment before the
send, 3 a name reached through `globalThis[…]` or `getattr`, 1 a secret read
by a function of another module. What closed them: `obfuscator::layers`
follows a blob handed to a decoder by name, joins pieces, inflates zlib or
gzip and undoes a one-constant XOR over character codes; `obfuscator::plain`
reads `globalThis['eval'](`, `getattr(x, 'name')` and
`__import__('builtins').exec` as the call they make; a chain's distance
leaves out comment lines; the data-flow pass follows one relative import to
a function that returns a secret. These are known to the scanner now: the
next new rewrite is the honest test.

Two pairs evaded with ruleset 2026.11.11; six did before it.

**1. The whole payload in a base64 blob that is evaluated, JS only: closed.**
4 pairs under `base64-layer` scored 27 until ruleset 2026.11.10 (`npm-cred-exfil`,
`npm-reverse-shell`, `vscode-token-steal`, `npm-discord-stealer`): `Buffer Decode
+ eval` fired and nothing else was visible, and the wrapper alone could not be a
verdict, because a legitimate commercial extension (Quokka) ships the same
shape as licence protection. Since ruleset 2026.11.11 what a base64 or hex
literal decodes to is scanned as code of the file (`obfuscator::layers`,
`layer_findings` in src/scanner.rs): the rules, the chains and the data-flow
pass run on the decoded text, two layers deep, and report on the literal's
line. The four seeds are caught by their payloads; a blob whose content shows
nothing stays a lead.

**2. A call through a character-code string: a broken mutator, fixed.** 1 pair:
`npm-install-dl-exec` under `char-codes` (10) until ruleset 2026.11.15. The
mutator turned `fetch(…)` into `String.fromCharCode(102,…)(…)`, which is not
valid JavaScript (a string is not callable). It now writes
`globalThis[String.fromCharCode(…)](…)`, which runs, and is caught.

**3. Install hook in a nested package unit, still evading by design.** 1 pair: `pypi-setup-hook` under
`node-modules-dir` (17). Correlation runs install-time chains only for the root
unit (`correlate_unit`, src/correlate.rs), because a bundled dependency's own
`setup.py` does not run at the top package's `pip install`. This is close to
correct behaviour, not a pure miss, and is recorded because it is a measurable
way to push a caught seed under the threshold.

## Two rewrites at once

An author who tests against the scanner does not stop at one rewrite.
`eval/evasion.py --stacked` applies two mutators in a row to every seed, each
pair of mutators once. With the 37 mutators that is 1,693 variants where both
apply, and **1,649 are caught (97%, 97-98)** with ruleset 2026.11.16. Most of
the 44 that evade stack `string-table` (24), which moves every string into
one array, with a second rewrite of what is left; next come
`source-other-file` (10) and `node-modules-dir` (9). With the 28 mutators
before it was 792 of 810 (98%, 97-99) from ruleset 2026.11.11 to 2026.11.15.
It is a measurement, not part of the baseline gate.

Of the 810, the 18 that evaded were the two single evaders above carried into their stacks
(12 with `char-codes`, whose output is not valid JavaScript; 7 with
`node-modules-dir`, one of them both). The first run, before this ruleset's
last change, had 26: eight more were `template-literal` stacked with a second
string rewrite, a name cut by an empty interpolation (`` `id_${''}rsa` ``) in a
file whose other names were split or escaped too. `obfuscator::plain` now
drops an interpolation of nothing.

## Takeaway

Placement, comment and whitespace, indirection and packaging tricks do not hide
a payload from KalaScan. Split and encoded names no longer do either, and a
payload inside a base64 or hex literal is read. What the suite does not have is
a layer the scanner cannot undo without running code: a cipher with a real
key, a blob assembled at run time, a payload fetched later. The baseline
(`eval/evasion-baseline.json`) pins the 211 caught pairs.
