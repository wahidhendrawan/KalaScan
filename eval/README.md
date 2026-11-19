# Detection eval

`corpus.json` lists labelled samples:

- **malicious**: real packages from the [DataDog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) (npm, PyPI, VS Code extensions), picked with a fixed seed, 260 PyPI packages from a second, independent source, [pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry) (`"source": "malregistry"`), and 200 npm packages from a third, [the ASE 2026 npm study](https://doi.org/10.6084/m9.figshare.31869370) (`"source": "npmstudy"`, CC BY 4.0).
- **clean**: popular npm / PyPI packages and VS Code extensions, fetched from the public registries. Several were chosen because they look suspicious on the surface: install scripts that download binaries, local dev servers, SSH tooling, telemetry. Entries with `"set": "random-2026-11"` were not picked but drawn at random from all of npm and PyPI (`eval/sample_clean.py`, see below).

Each sample has a `split`. Rules were tuned while looking at `dev`. `holdout` was added afterwards and never used for tuning, so its numbers are the honest estimate.

```bash
cargo build --release
eval/fetch_malicious.sh ~/kalascan-corpus ~/kalascan-malregistry   # blobless clones
eval/fetch_npmstudy.py ~/kalascan-npmstudy                          # 200 tarballs, read out of a 4.8 GB zip by range requests
python3 eval/run_eval.py --dataset ~/kalascan-corpus --malregistry ~/kalascan-malregistry --npmstudy ~/kalascan-npmstudy --out before.json
# ...change rules...
python3 eval/run_eval.py --dataset ~/kalascan-corpus --malregistry ~/kalascan-malregistry --npmstudy ~/kalascan-npmstudy --compare before.json
```

Every rate is printed with its 95% Wilson interval. `--rule-stats` adds, for each finding, how many malicious and clean packages of a split it fired on and the likelihood ratio between the two. Without `--malregistry` the second source is left out.

**Holdout misses are counted, not listed.** A sample somebody has looked at stops being a holdout sample, so the miss list and the score changes show `dev` only (`--show-holdout` overrides this; move what you then read to `dev`). On 2026-11-17, before this was the default, one run printed the names and rule names of ten missed `malregistry` samples. No rule or weight was changed in response; they stay in the holdout.

The malicious samples are **live malware**. `run_eval.py` scans them statically and extracts archives into a temp dir with the dataset password. Keep the corpus outside the repo. `--flag=--sandbox` executes them; the harness refuses it unless `--disposable-vm` is passed as well, and that flag is a promise: a throwaway VM with no host file sharing (below).

CI (`.github/workflows/eval.yml`) runs only the clean half, as a false-positive gate: `--only clean --max-fpr 0`, on every pull request that touches `src/`, `rules/`, `eval/` or `Cargo.lock`.

Results at threshold 50 (ruleset 2026.11.7, score model v1, measured 2026-11-19; 95% interval in brackets; the aggregate is in [`results/2026.11.7.json`](results/2026.11.7.json)):

| split | malicious recall | clean false positives |
|---|---|---|
| dev | 490/626 (78%, 75-81) | 0/369 (0%, 0-1) |
| holdout | 639/883 (72%, 69-75) | 0/453 (0%, 0-1) |
| holdout, dated 2026-08-01 or later | 89/195 (46%, 39-53) | |

**The last row is the one to expect on new malware.** It is every holdout sample whose file name in the DataDog dataset carries a date of August 2026 or later (`run_eval.py --since 2026-08-01`): 194 npm packages and one PyPI package, from four sets. npm in the holdout dated before August is at 148 of 193 (77%). The gap is what tuning on the same months is worth: the batches the rules were written from are mostly January to June, and so is `fresh2-2026-11`.

Five tuning batches of new samples joined `dev` in November (below), which is why its rate moves with each one.

The holdout by sample set:

| holdout set | what it is | malicious recall |
|---|---|---|
| original | 147 samples: the 27 first ones and 120 added in November 2026 | 105/147 (71%, 64-78) |
| `recent-2026-11` | 60 npm packages dated 2026-08-01 or later, the newest in the dataset | 33/60 (55%, 42-67) |
| `malregistry-2026-11` | 100 PyPI packages from pypi_malregistry whose names the DataDog dataset does not have; 5 archives do not unpack | 83/95 (87%, 79-93) |
| `fresh-2026-11` | 161 packages drawn on 2026-11-18, after ruleset 2026.11.2: 100 npm and 1 PyPI dated 2026-08-01 or later (DataDog), 60 PyPI from pypi_malregistry; 2 archives do not unpack | 90/159 (57%, 49-64) |
| `fresh2-2026-11` | 200 packages drawn on 2026-11-18, before ruleset 2026.11.5: 150 npm dated 2026-01-01 or later (DataDog), 50 PyPI from pypi_malregistry; 4 archives do not unpack | 156/196 (80%, 73-85) |
| `late-2026-11` | the 26 npm names dated 2026-08-01 or later that were left in the dataset, drawn on 2026-11-18 | 13/26 (50%, 32-68) |
| `npmstudy-2026-11` | 200 npm packages from [the ASE 2026 npm study](https://doi.org/10.6084/m9.figshare.31869370) whose names the DataDog dataset does not have, drawn on 2026-11-19; mostly published 2021-2024 | 159/200 (80%, 73-85) |

**The holdout number is the one to quote, and the `recent` row is the one to worry about**: on the newest npm malware KalaScan catches about half (24 of 60 with ruleset 2026.11.1, before the tuning described below). The second sources say the rules are not fitted to one dataset's taste: PyPI 87% on pypi_malregistry against 37 of 48 (77%) on the original DataDog PyPI holdout samples; npm 80% on the study's samples against 148 of 193 (77%) on DataDog npm dated before August 2026. Both second sources are older malware, so they do not speak to the newest; the `recent` row does. By ecosystem the whole holdout is IDE extensions 32/48 (67%, 53-78), npm 395/587 (67%, 63-71; DataDog 236/387, the study 159/200), PyPI 212/248 (85%, 81-89).

### A second npm source, and registry metadata measured and not built (ruleset 2026.11.7)

**A second npm source.** Every npm sample came from the DataDog dataset. The replication package of "How Effective Are NPM Malicious Package Detectors? A Large-Scale Empirical Study" (ASE 2026, [the ASE 2026 npm study](https://doi.org/10.6084/m9.figshare.31869370)) holds 6,547 malicious npm tarballs from four academic collections and two advisory feeds, each reviewed by three people; 3,529 of its package names are not in the DataDog dataset. 200 of those were drawn into the holdout (`sample_malicious.py --npmstudy`, seed 20261117) and nobody read them. `eval/fetch_npmstudy.py` reads the 200 out of the 4.8 GB archive with HTTP range requests. **159 of 200 (80%, 73-85)**, against 148 of 193 (77%) on DataDog npm dated before August 2026: the npm rules are not fitted to one dataset. The study's samples are mostly from 2021 to 2024, so this says nothing about the newest malware; the 46% on samples dated August 2026 or later stands.

**Registry metadata, measured and not built.** The DataDog dataset stores the npm registry document of each package next to the sample (830 of 831 npm samples). Cut at the scanned version's publish time, so that later versions and takedowns do not leak in, it gives what a scan on the day would have seen. Eight signals were counted on the npm samples and on the 394 clean npm packages (their registry documents cut the same way):

| signal | holdout missed (151) | dev missed (97) | clean (394) |
|---|---|---|---|
| new package: first version at most 2 days before, at most 3 versions | 86 | 54 | 160 |
| no repository, homepage or description | 14 | 9 | 27 |
| at least 5 versions in 24 hours | 9 | 6 | 15 |
| published by an account no earlier version was published by, package at least 30 days old | 7 | 6 | 10 |
| first release after 180 days without one | 2 | 2 | 35 |
| install script added in this version (already a registry check) | 1 | 2 | 0 |
| version jump to 90 or more (already `Dependency Confusion Version`) | 1 | 0 | 0 |

No signal and no pair of signals separates the misses from clean packages: the best pair (a burst of versions and no repository) holds 3 holdout and 2 `dev` misses and 1 clean package. A new package with no repository is what most new npm packages look like. Nothing was built.

### Reading the newest misses (ruleset 2026.11.7)

**What was read.** The 44 `tune-recent-2026-11` samples (`dev`, npm, dated August to October 2026) that ruleset 2026.11.6 missed, sorted by why:

| why it is missed | samples |
|---|---|
| nothing malicious in the package's own files: a sibling of a campaign's package (`@toptal/picasso-*` at version 100.0.x, `@wizloft/harness-*`), a placeholder, a researcher's probe, a web page, a payload kept as data | 26 |
| a native binary and a manifest, nothing else | 4 |
| the behaviour is in plain code and the findings stay weak (a launcher that downloads a binary, a fork of a large library) | 11 |
| an obfuscator the rules did not know | 3 |

Thirty of 44 carry no code a reader could call malicious, which is most of the gap between the newest samples and the rest of the holdout.

**What was added.** Five rules and three chains, each for a technique, not a name: a packer's swap-shuffle string decoder (`Shuffled String Loader`), a string table behind kana identifiers, code written to the stdin of a detached interpreter started with no script, a base64 shell script inside `package.json`, a javascript-obfuscator line appended to a readable file (`Chain: Obfuscated Code Appended to Readable Source`) a program copied under the name of a Windows system process (`Chain: Executable Copied Under a System Process Name`), and a native executable kept in a dot-directory of the package next to a process started detached (`Chain: Hidden Bundled Binary Started Detached`, the compromised `@memtensor/memos-cloud-openclaw-plugin`).

Two of the 44 were read twice and stay unexplained by any code: `charclass` is a copy of someone else's library published by a stranger, `jimg` a release by its own author with nothing added. One more pattern got no rule: `module-relpath` carves bytes from the end of an image, but never calls the function that does it, and image parsers slice buffers from the end too.

**Result.** `tune-recent-2026-11` 36 → 44 of 80, `dev` 480 → 490 of 626. **The holdout moved by two: 478 → 480 of 683** (both in `recent-2026-11`, 31 → 33 of 60; dated August 2026 or later 87 → 89 of 195). None of the eight fires on a clean package (0 of 822). The appended-obfuscation chain fires on 11 holdout and 8 `dev` samples, nearly all of them caught already by another chain. A static scan of the newest npm malware is near its ceiling on this dataset; the dependency scan below and the registry checks work on what the files do not show.

### One hop into the dependencies, and a time slice (ruleset 2026.11.6)

**What was left.** After the npm round below, about a third of each npm batch had nothing malicious in the package's own files. The largest part of that third that a scanner can still reach is a payload kept in a dependency: `debug-fmt` is a copy of a known library plus one dependency, `debug-glitz`, published the same day; the hijacked `@mastra/*` releases add `easy-day-js`.

**Measured before it was built.** For every npm sample and every clean npm package the direct dependencies were looked up in the registry (npm keeps the publish times of a package it has replaced with a security placeholder). A dependency is *young* when its first version came out at most 30 days before the package that needs it:

| | packages | with a young dependency | whose young dependency scans at 50 or more |
|---|---|---|---|
| clean npm | 394 | 29 | 0 |
| `dev`, missed | 107 | 22 | 11 |
| holdout, missed | 153 | 26 | 12 |
| `dev` and holdout, already caught | 571 | 13 | 9 |

The dependency was scanned from the DataDog dataset when it is a sample there (the registry copy is gone), for clean packages from the registry. Young dependencies of clean packages are monorepo siblings and platform builds, published by the same release; none scans above 15. For 5 missed holdout packages and 3 `dev` ones the young dependency is in neither place, so the count is a lower bound.

**What was built.** A scan of `npm:name@version` now looks up the dependencies that this version added (all of them while the package has five versions or fewer), skips siblings (`@scope/…`, `name-<platform>`), reads the registry document of each up to 256 KB (an established package is cut off there and never read in full), and scans the ones that were young, three at most, one hop deep (`young_dependencies` in `src/registry.rs`, `malicious_dependencies` in `src/lib.rs`). A dependency at risk 50 or more gives the package `Chain: Malicious New Dependency`. Replayed on the registry documents the dataset keeps, the rule for which dependencies to look at keeps all 23 packages of the table. On the 393 clean npm packages, scanned live with it: 0 flagged, no package carries the chain, median scan time 1.9 s.

**What it does to the numbers: nothing in the table at the top, and that is deliberate.** The harness scans extracted archives; a registry lookup needs the name and the day. The replay says a live scan on the day would have caught 12 more holdout samples: **490 of 683 (72%, 68-75)**, 9 of the 12 in `fresh2-2026-11`. Of the samples dated August or later it adds 3 (90 of 195). This is a registry check like the others: it works on `kalascan scan npm:…`, `kalascan guard` and lockfile audits, not on a tarball handed over as a file.

**The time slice.** A holdout drawn from later months than every tuning batch was the plan, and the dataset does not allow it: 744 files are dated August to October, and only 26 package names among them were unused. Those 26 are `late-2026-11` (13 of 26 on first count). The slice in the table at the top is the substitute: every holdout sample dated August or later, whatever its set. Tuning batches from here on are drawn from before August (`sample_malicious.py --since 2026-01-01 --before 2026-08-01`), so that the slice stays ahead of what the rules were written from. One caveat: `tune-recent-2026-11` (80 samples, read for ruleset 2026.11.2) is from the same months.

### npm tuning with GuardDog as a second reader (ruleset 2026.11.5)

The round before this one tuned on IDE extensions and moved no holdout number, because the largest gap is npm. This round went at npm, and used GuardDog to point at what KalaScan misses.

**A new holdout first.** The `fresh-2026-11` count had been read three times, so before any rule changed a new set was drawn (`sample_malicious.py --since 2026-01-01 --ecosystem npm --size 150 --seed 20261121` and `--malregistry --size 50`; `"set": "fresh2-2026-11"`). With ruleset 2026.11.4 it scored **138 of 196 (70%)**; the whole holdout was 444 of 657.

**A tuning batch, read.** Separately, 200 npm packages dated 2026 went into `dev` (`--size 200 --seed 20261122`; `"set": "tune-npm-2026-11"`, no name shared with the holdout). Before any change: 139 of 200. Of its 61 misses:

- **A self-decoding `eval` wrapper** (8, compromised releases of `autotel-*`, `awaitly-postgres`, `executable-stories-playwright`, `node-env-resolver` and two `@redhat-cloud-services` packages, June 2026): a 4.5 MB `index.js` planted next to the real build, `eval(function(s,n){…fromCharCode…}([40,109,…]))`. Now `Code Decoded From a Number Array and Evaluated`, a verdict on its own.
- **A launcher for a binary under another name** (13 + 1 binary package): packages named after companies (`ycombinator`, `motherduck`, `sourcery-ai`, cities) with a `0.0.0-dev-…` version, each a copy of an open-source CLI's npm installer whose wrapper and platform packages are called `stardrop`. The package's own code is the installer; the payload is the binary. What a scan can see is the mismatch: the command, wrapper and `stardrop-<os>-<arch>` packages carry one name, the package another, and an install hook runs. Now `Chain: Platform Binary Under Another Name` (`foreign_binary` in `src/correlate.rs`; a real CLI shares its binary's name, `turbo` / `turbo-darwin-64`).
- **An SSH key planted by a logger** (4): `pino-pretty-logger` look-alikes that append a hard-coded public key to `~/.ssh/authorized_keys`, then walk the home directory for `.env` files and upload them. Now `Chain: SSH Key Planted`, which needs the public key in the code: Remote - SSH writes the user's own key there and was flagged by the first version (below). One of the four fetches its key and is not caught.
- **Smaller fixes**: remote code run through `new (Function.constructor)("require", …)` and through `axios_1.default.get` (2; the chain existed, the patterns missed these spellings), `require(Buffer.from('ZnM=','base64').toString())` (`Module Name Decoded From Base64`, a lead), an install script that runs `uname -a` through its own helper and posts it, a Node `lib.request({hostname: …})` call (`URL Fetch Command`).
- **Out of reach** (about 30): `@mastra/*` compromised versions with no payload in the package, helpers whose payload is in a dependency (`debug-fmt` → `debug-glitz`, `ts-big-number` → `npm-doc-builder`), research probes that write a file to `/tmp`, a proxy-node deployer, a WhatsApp library fork.

After the changes the batch scores 166 of 200.

**GuardDog as a second reader.** GuardDog 3.2.0 was run on every `dev` sample and every clean sample (not on the holdout). Of 182 `dev` samples KalaScan missed, GuardDog's threat rules caught 57. Ranked by how many of those misses a rule caught against how many of the 821 clean packages it flags, the one clean signal was `threat-runtime-obfuscation-dynamic-eval` (16 misses, 0 clean): the wrapper above, now covered. The rest flag clean packages too (`threat-process-spawn-silent` 20 misses and 11 clean, `threat-network-exfiltration` 14 and 16, `threat-filesystem-read` 23 and 56); the `dev` samples behind them were read and gave the smaller fixes above, plus one more:

- **Code behind padding** (`utils-mf`, 15 MB): 11 MB of `\u00a0\u200e\n` put the obfuscated payload at 4.1 MB, between the first 3 MiB and the last 1 MiB the scanner reads. An oversized file is now read with whitespace runs longer than 64 bytes collapsed, and a script with 1 MiB or more of them gets `Code Hidden Behind Whitespace Padding` (critical, not a verdict alone). Line numbers in such a file count from the collapsed text.

**The holdout, counted once after the changes: 444 → 465 of 657 (71%, 67-74).** `fresh2-2026-11` 138 → 156 of 196 (80%, 73-85), npm across the holdout 201 → 221 of 361. The 21 holdout samples that crossed 50 did so on `Code Decoded From a Number Array and Evaluated` (10), `Chain: Platform Binary Under Another Name` (9) and `Chain: SSH Key Planted` (2): the same campaigns as in the tuning batch, which is what a holdout drawn from the same months should show. The older sets barely moved (`fresh-2026-11` 89 → 90, original 103 → 105). No sample's score went down, the evasion suite catches the same pairs.

**The clean side, first contact.** The first run of the new rules flagged 3 clean holdout packages at 90: `ms-vscode-remote.remote-ssh` (its help text appends `${pubKey}` to `authorized_keys`), `saoudrizwan.claude-dev` (a minified `C("hostname")` read as a recon helper call) and `liangzimixin`, a random npm draw that hides `node:child_process` behind base64 from its plugin marketplace's scanner. The SSH chain now needs a key in the code, the helper-call pattern takes `whoami` and `uname -a` only, and the base64 module rule is a lead, not a verdict. The three were read, so they are in `dev` now; the clean corpus is 0 of 822 again.

Ruleset 2026.11.4 (next section) moved none of the holdout numbers.

### IDE extensions, and two ideas measured and not built (ruleset 2026.11.4)

**A tuning batch of extensions.** The extension rate on the holdout (32 of 48) had not moved since the first rules. `sample_malicious.py --ecosystem ide_extensions --seed 20261120` drew every extension name in the DataDog dataset that the corpus did not have yet: 24, in `dev` as `"set": "tune-ext-2026-11"`. One holds 11,859 files, over the scanner's 10,000-file limit, and counts as an error. Before any change the batch scored 9 of 23. It was read inside the throwaway VM. Its 14 misses:

- **An AI agent used as the payload** (`amazon-q-vscode` 1.84.0, the compromised release): a prompt that tells the agent to delete the user's files and cloud resources, run with `q --trust-all-tools --no-interactive`. Two things hid it. The code sits at the end of a 21 MB bundle and the scanner read the first 4 MiB of a file; it now reads the first 3 MiB and the last 1 MiB of a file over the limit. And nothing in it is a known API: now `Agent CLI Run With Permissions Disabled` (the approval-bypass flags of Amazon Q, Claude Code, Codex and Gemini CLI), which every agent harness also has and so is a lead, and `Chain: Weaponised AI Agent` when the text around it asks for deletion or for keys and wallets.
- **`child_process` cut in two** (1): a javascript-obfuscator string table holding `'child_proc'` and `'ess'`, and an ngrok TCP tunnel. Now `Split child_process Name`, which counts as process execution in the chains.
- **Commands over DNS** (1): TXT records of an attacker's domain, joined and handed to `eval`. Now `DNS TXT Query` and `Chain: DNS Tunnel Command Execution`.
- **Git hooks for every repository** (1): downloads, decrypts and starts a binary, then runs `git config --global core.hooksPath` towards a directory it fills. Now `Global Git Hooks Path Set` and `Chain: Git Hook Persistence`.
- **Nothing malicious in the code** (10): hello-world extensions, themes, forks of a legitimate extension, research probes. The listing was the offence.

After the changes the batch scores 13 of 23. The split-name rule catches one more `dev` sample (`tune-recent-2026-11` 35 → 36 of 80). **The holdout did not move: 306 of 461, extensions 32 of 48.** Four holdout scores changed and none crossed 50. The four behaviours are real and now have a name, and no unread sample needed them; what the 16 extension misses in the holdout are is not known, because they are not read. Treat this round as coverage of known incidents, not as a gain in the rate.

Reading the end of large files cost one false positive before it was merged: `github.copilot-chat` (clean, `dev`) went from 20 to 90. In the tail of its 20 MB bundle a command descriptor, `{command: "workbench.extensions.installExtension", arguments: [id]}`, matched `VS Code Extension Side-loading` next to a `fetch`. The rule now skips descriptors (the installed thing is not visible there). The clean corpus is back at 0 of 822; the highest clean score is 40 (Quokka). The same extension bundles an agent CLI and so carries `Agent CLI Run With Permissions Disabled` as a lead. The evasion suite catches the same pairs as before.

The `fresh-2026-11` count has now been read three times (78, 89, 89); the next round drew a new holdout first (above).

**Registry history as a signal: measured, not built.** Malicious samples are scanned as extracted archives, so the registry checks (install script added, provenance dropped, manifest confusion, version gap) never ran on them, and what they would add to recall was unknown. The DataDog dataset keeps the registry document of each npm sample from the day it was collected: found for 243 of 244 `dev` and all 211 holdout npm samples. The checks were replayed on those documents, with ruleset 2026.11.3:

- The npm misses are almost all packages that were malicious from their first version (`malicious_intent`: 78 `dev`, 108 holdout). Compromised versions of real packages, where a history exists to compare with, are 4 `dev` misses and 1 holdout miss.
- On the missed samples: an install script added in the malicious version, 0 `dev` and 1 holdout; provenance dropped together with a new publisher, 3 `dev` (the `@mastra/*` packages) and 0 holdout; manifest confusion, 0 of 454; the version gap fires only on samples already caught.
- On the full history of the 394 clean npm packages (23,756 steps from one version to the next, 49 packages that ever published with provenance), provenance dropped with a different publisher happened in 5 legitimate packages, axios, vue, node-gyp and mongoose among them. It cannot be a verdict.

So the registry checks stay what they are, context on a live scan, and recall on new npm malware will not come from them: one holdout sample at most.

**Install hooks that hand off to another package: measured, not built.** A hook that runs `npx other-package`: 1 `dev` miss, 0 in the holdout. A dependency aliased to another name (`"x": "npm:other@…"`, an ordinary npm feature): 3 `dev` misses; in the holdout 3 samples already caught and 2 missed. Too few, and too close to normal use, for a rule.

### Tuning on 2026 samples (ruleset 2026.11.3)

The `fresh` holdout below scored 78 of 159 with ruleset 2026.11.2, npm 37 of 100. To improve on that without reading it, a separate batch was drawn into `dev` and read instead (`"set": "tune-fresh-2026-11"`): 100 npm packages dated 2026-01-01 or later (`sample_malicious.py --since 2026-01-01 --seed 20261119`) and 50 PyPI packages from pypi_malregistry (`--malregistry --size 50 --seed 20261119`). It was read inside the throwaway VM; only text excerpts left it. Before any change it scored 96 of 150 (npm 63, PyPI 33). Its 54 misses:

- **Fernet-wrapped loaders** (7 PyPI): a `setup.py` install hook that runs `exec(Fernet(key).decrypt(blob))` on Windows, or writes the same line to a file and starts it. Now `Decrypted Code Executed`, a verdict on its own.
- **Builtin names spelled from other objects** (5 PyPI): `''.join(map(getattr(__builtins__, oct.__str__()[-3] + hex.__str__()[-4] + copyright.__str__()[4]), […]))` builds `chr` and then every string, with CJK variable names. Now `Builtin Name Built From Characters`, a verdict on its own.
- **Copies of aiohttp with a hidden zip** (2 PyPI): a file named `server.crt` or `_websocket.typed` is a zip of Python modules, loaded with `zipimport.zipimporter(…).load_module()` or put on `sys.path`. Now `Code Imported From Disguised Archive`.
- **A worm in a compromised scope** (5 npm, `@emilgroup/*`): one variant installs a Python payload as a systemd user service from `postinstall`; the other reads npm tokens from `.npmrc` and the environment, lists every package the account maintains (`/-/v1/search?text=maintainer:`) and republishes each with the payload. Now `Chain: Install-time Persistence` and `Chain: npm Worm`.
- **Smaller fixes**: javascript-obfuscator output whose only fixed shape is the decoder's `if(t['\x..']===undefined)` check (2), a `postinstall` that downloads and runs a binary from a pinggy tunnel (2), `npm publish` run through a script's own `run()` wrapper.
- **Out of reach or not malware** (about 30): compromised versions with no payload in the package (`@mastra/*`, the `stardrop` platform packages), proofs of concept that write to `/tmp`, a dependency-confusion probe whose payload is downloaded, an SSH key planted in `authorized_keys` by an otherwise ordinary logger, a hardcoded GitHub token that patches a gist, one-off Telegram bots.

After the changes the batch scores 120 of 150 (npm 72, PyPI 48). On the holdout, which was not read: **281 → 306 of 461**, `fresh` 78 → 89 of 159, `malregistry` 70 → 83 of 95, the original 147 from 101 to 103. Every gain on `fresh` is PyPI (41 → 52 of 59); npm stays at 37 of 100. No sample's score went down, the clean corpus stays at 0 of 822 (the highest clean score is 40, Quokka), and the evasion suite catches the same pairs as before.

### A fresh holdout and the sandbox (2026-11-18)

**A holdout drawn after the rules.** Every holdout count since November had been read after each rule change, so a new set was drawn once ruleset 2026.11.2 was released (`sample_malicious.py --since 2026-08-01 --seed 20261118`, npm and PyPI, plus `--malregistry --size 60`; `"set": "fresh-2026-11"`). Only one PyPI name dated August or later was left unused in the DataDog dataset, so the PyPI side comes from pypi_malregistry. Nobody has read these samples. Their count has been read twice: with ruleset 2026.11.2 and after the tuning above.

With ruleset 2026.11.2 they scored **78 of 159 (49%, 41-57)**: npm 37 of 100, PyPI 41 of 59. That is the number to expect on new malware; ruleset 2026.11.3 reaches 89 (56%, 48-63), all of the gain on PyPI. It is lower than the 31 of 60 on `recent-2026-11` and the 35 of 80 on the npm tuning batch: rules tuned on one batch of new npm malware carried over to the next only in part. 63 of the 100 npm samples score under 30.

**The sandbox, measured once.** The same corpus was scanned again with `--sandbox`, which runs a package's install hooks (npm lifecycle scripts, `setup.py install`, `.pth` files) under strace with bait credentials in `$HOME` and a fake network. The run was in a throwaway OrbStack machine (Ubuntu 24.04 arm64, `--isolated --isolate-network`: no host file sharing, no route to the host's services), with the 1.15.0 release binary.

- Every count was the same as the static run, at every threshold: 452 of 714 malicious, 0 of 822 clean. Bait credentials were opened by three malicious samples, all three already caught.
- Why, from the 71 `dev` misses with an archive: 58 have no install hook at all, the payload runs when the package is imported or the app is started. The 13 hooks were a `chmod` of a bundled binary, an "is Electron installed" check, a proof of concept that writes `/tmp/test.txt`, and hooks that fail at once because a dependency or `bun` is missing (no network, no `node_modules`).
- A prototype went one step further: load the entry point (`require()` the package, `import` its top-level modules) with every missing dependency replaced by a stub that accepts any call. It saw a DNS lookup on 3 of the 71 and a bait file opened on none, so it was not built into KalaScan.
- The VM is arm64. Bundled `x86_64` binaries (one `dev` miss ships one) are not executed there.

The sandbox catches install-time behaviour, and the samples that get past the static rules are mostly not that. It stays opt-in and outside the published numbers; its false-positive count on the clean corpus (0 of 822) is the one thing this run adds.

### Tuning on the newest npm samples (ruleset 2026.11.2)

The `recent` holdout set scored 24 of 60, and reading it would have ended it as a holdout. So a second batch was drawn the same way (`sample_malicious.py --since 2026-08-01 --seed 20261118`, 80 packages, `"set": "tune-recent-2026-11"`, split `dev`) and read instead. Before any change it scored 24 of 80 (30%), close to the holdout rate. Its 56 misses were of four kinds:

- **Web pages published as packages** (11): `"main": "index.html"` or `"index.svg"`, no module at all. The registry's CDNs (unpkg, jsDelivr) serve the page under a trusted host name: phishing pages, cloned sites, an SVG whose script builds the page. Now `Chain: Web Page Published as a Package`, for an entry point that is an HTML or SVG document with script written into it.
- **Nothing malicious in the artefact** (about 24): nine `@toptal/picasso-*` packages at version 100.x that hold the real component code and no payload, platform packages that are one native binary, research probes, and helper packages whose payload lives in a sibling package. Static rules have nothing to find there.
- **Hidden strings** (2): a payload host kept as a base64 literal and evaluated two lines later (`Base64-Encoded URL`, `Buffer Decode + eval`), and javascript-obfuscator output with mangled names instead of `_0x…` (the decoder's arithmetic is now part of `Obfuscator.io Output`).
- **One-offs** (about 19): forks of a WhatsApp library with a changed endpoint, an Electron exam-cheating tool, install scripts that fetch a binary like every native package does.

After the changes the batch scores 35 of 80 (44%), and the holdout moved once: **193 → 202 of 302**, `recent` 24 → 31 of 60, original 99 → 101 of 147. About a third of this batch is out of reach for a scan of the package's own files, so the newest-npm rate has a ceiling near two in three with the present approach.

The clean corpus did its job twice while this was written. A first version of the Node decode-and-eval pattern ran case-insensitively and matched `function (` after any base64 decode: 22 of 822 clean packages flagged, found before anything was merged. And the new chain flagged one clean holdout package, `responsive-embed@1.0.0`, a Polymer element whose entry point is its demo page; the chain now needs script written into the page and no HTML Imports, and that package is in `dev`. Quokka (a clean `dev` extension) ships a base64 blob of obfuscated code that it evals as licence protection, which is why `Buffer Decode + eval` is a lead (20 points) and not a verdict.

The two new sets were drawn with `eval/sample_malicious.py` (seed 20261117, one version per package name, names already in the corpus skipped) and have not been read. `--since` makes the same draw for a later date: the way to measure, at each release, on samples newer than the rules.

**The honest false-positive number moved.** A second random draw of clean packages (`sample_clean.py --seed 20261117`, 297 scanned) was flagged 4 times at 50 or more before any fix: a webpack dev bundle whose `eval` module held a link to a `.sh` file (`@crisog/sourcecred`), a `curl … .EXE` in `circle.yml` next to an npm install script (`sapnwrfc`), a curl command line kept in a variable and run (`cco`), and zc.buildout's old `bootstrap.py` (`xbob.paper.jmlr2013`). With the first draw that is 5 false positives in 595 random packages: **0.8% (0.4-2.0)**, not the 0.3% the first draw alone suggested. A fifth package, `diverse_fowl_z3n`, was a registry spam publisher like `democratic_trout_z3n` and is left out of the corpus. The four are fixed and stay in `dev` (`"set": "fit-2026-11"`): the clean half the v2 score weights are fitted on. The 0/456 on the holdout is what remains unseen.

**The harness scanned the wrong directory for some wheels.** A dataset archive of a PyPI wheel holds the wheel's files and, for some samples, a `sources/` checkout of the linked repository. `package_root` looked for `setup.py` / `pyproject.toml` / `PKG-INFO` and so picked `sources/` for those samples. It now takes a `*.dist-info` directory as a package root too, which is what pip installs. That, and reading name and version from a wheel's `METADATA`, moved the original holdout from 94 to 99 of 147 (ruleset 2026.11.1).

**The holdout number is still the one to quote.** Until November 2026 the holdout split held 27 malicious samples and scored 26/27 (96%). 120 fresh samples were then added with a fixed seed (40 npm and 40 PyPI packages first published to the dataset in 2026, 40 extensions, one version per package name), and none of them has been read. On those 120 alone KalaScan catches 56 (47%): the earlier figure was a small-sample artefact, and rules tuned on 2022-2025 samples generalise worse than it suggested.

Before the two new sets and the harness fix, holdout recall by ecosystem was IDE extensions 32/48 (67%), npm 29/51 (57%), PyPI 33/48 (69%); the current figures are above. The highest score among the picked clean packages is 23, among the random ones 38 (`tavallio-agent`, below). The 161 picked clean npm/PyPI targets also go through the registry checks (manifest confusion, install script added, provenance dropped, lapsed maintainer email domain) without a finding. Before this work the dev split scored 1/60, and marketplace-id scans failed outright.

### Tuning on fresh samples (November 2026)

PyPI was the weak spot (22 of 48 holdout samples). Rather than read the holdout misses, a separate tuning batch was drawn into `dev` (`"set": "tune-2026-11"`): every 2026 PyPI package in the dataset not used before (41), 19 PyPI packages from 2025 and 40 npm packages from 2026, one version each. Before any change it scored PyPI 27/60 and npm 23/40, close to the holdout rates, so it stood in for them. Reading its 50 misses showed what the rules did not know:

- npm install scripts that run `curl` / `nslookup` themselves next to `$(whoami)` or a dependency-confusion version, and dependencies given as an http tarball on the attacker's own server (PhantomRaven);
- `setup.py` hooks that read `whoami` / `hostname` (five samples of one template), and `setup.py` code that calls a capture service at module level;
- DNS exfiltration through `socket.getaddrinfo(f"{host}.{user}.domain")`, host recon through `os.popen('whoami')` and `os.uname().nodename`;
- `exec(resp.read())` after `urlopen`, `curl` run through `subprocess` and its output handed to `node -e`, `os.environ` collected into a dict and posted to a raw IP;
- `__import__('zlib').decompress(__import__('base64').b64decode(…))` loaders, and Telegram bot tokens used through a library rather than a URL.

After the changes: tuning batch PyPI 42/60, npm 28/40; holdout **82 → 94 of 147**, PyPI 22 → 33 of 48. No sample that was caught before was lost. The 12 holdout gains came from `Chain: Reconnaissance Beacon` (6), `Chain: Install-time Reconnaissance` (5), `Chain: Install-time Exfiltration` (2), data flow (2) and a remote URL dependency (1). Every new rule and chain fires on none of the 526 clean packages.

The data-flow pass was the risky part. Its first version ignored statement order and treated `.send()` as a network call, and flagged **53 of 526 clean packages**: `process.env` spread into a `fork()` option and an unrelated IPC `.send()`, a variable reused by two functions in a bundle, `eval(r.text)` used to parse a response. It now reads statements in order, counts only named network APIs, skips files over 64 KB or with minified lines, and needs a variable (not `curl` itself) to reach an interpreter. That cost two holdout detections (96 → 94) and brought the clean count back to 0. The ten clean packages looked at while fixing it are in `dev` now.

### Score model v2

`eval/fit_weights.py` fits a weight per finding on the `dev` split (`rules/weights.toml`), used by `kalascan scan --score-model v2`. [docs/scoring.md](../docs/scoring.md) has the model, how its two parameters were chosen by cross-validation, and the result of the one evaluation on the holdout.

### Compared with GuardDog

`python3 eval/run_eval.py --scanner guarddog --dataset ~/kalascan-corpus` runs [GuardDog](https://github.com/DataDog/guarddog) (3.2.0, Docker image) on the same samples. GuardDog reports rule hits rather than a score, so two readings are given: a `threat-*` or metadata rule fired, and any rule at all fired (`capability-*` rules describe what code can do, not that it is malicious).

| | malicious, holdout | malicious, all | clean, picked | clean, random |
|---|---|---|---|---|
| KalaScan (risk >= 50) | 306/461 (66%) | 598/864 (69%) | 0/227 | 0/595 |
| GuardDog, threat or metadata rule | 299/461 (65%) | 558/864 (65%) | 130/226 (58%) | 91/595 (15%) |
| GuardDog, any rule | 361/461 (78%) | 685/864 (79%) | 216/226 (96%) | 318/595 (53%) |

Run on 2026-11-18 on the corpus as it stood before the extension batch, KalaScan with ruleset 2026.11.4. GuardDog was not run on `fresh2-2026-11`, so the table stays on the 461 samples both tools were measured on; on them ruleset 2026.11.5 catches 307. At GuardDog's stricter reading the two tools catch the same share of the holdout and not the same samples: 242 are caught by both, 64 only by KalaScan, 57 only by GuardDog, 98 by neither. By ecosystem on the holdout, GuardDog then KalaScan: IDE extensions 32 and 32 of 48, npm 98 and 102 of 211, PyPI 169 and 172 of 202. By holdout set: `fresh-2026-11` 84 and 89 of 159, `recent-2026-11` 27 and 31 of 60, `malregistry-2026-11` 81 and 83 of 95.

The difference is on the clean side. GuardDog flags more than half of the popular packages and 15% of the random ones (48 of the 295 in the holdout). KalaScan's 0 is after its flagged clean samples were read and fixed; the number to set against GuardDog's 15% is KalaScan's first contact with the same random packages, 5 of 595 (0.8%).

Caveats. The malicious samples come from DataDog's own dataset, which GuardDog's rules were developed against. KalaScan's rules were tuned on `dev` samples of that dataset between the two runs: in the first run, before the November tuning, GuardDog was ahead on the 147 holdout samples of that time (107 against 94; 66 caught by both, 16 only by KalaScan, 41 only by GuardDog, 24 by neither). Samples GuardDog could not scan are outside its columns: the 7 broken archives, and 3 clean packages against KalaScan's 2.

The 60 extensions installed on the maintainer's machine (`kalascan installed`) also all score below 30. Ten of them were false positives during development and are now in the clean `dev` split.

**Honest false-positive number.** When the clean set grew from 66 to 227 samples (161 new ones in `holdout`, untouched by tuning), the first run flagged **9 of the 176 holdout clean samples (5%)**: greedy regexes (`powershell .* -enc` across a minified line, `bcdedit` inside base64), `~/.ethereum/geth.ipc` read as a wallet, a bidi character used as a regex range, official `curl … | sh` installers (gh.io, antigravity.google, nvm) and firebase-tools chmodding one file while spawning another. Those rules were fixed and the 12 samples looked at moved to `dev`; the remaining 165 holdout clean samples score below 50. Expect the real rate on unseen packages to sit somewhere between the two numbers.

**Packages nobody picked.** Popular packages are a soft test: they are well kept, and the list was partly chosen by hand. So 300 packages were drawn at random from the whole registries (`python3 eval/sample_clean.py`, seed 20261116): 150 by random rank in the [ecosyste.ms](https://packages.ecosyste.ms) npm index, 150 by random name from the PyPI simple index, each pinned to its newest version published before 2026-05-16. Registries take malicious versions down within days, so one that has survived six months is very likely benign. Rejected draws were npm 109 too new, 8 security placeholders, 7 gone, 4 over 30 MB, 2 index errors; PyPI 55 too new, 14 gone. Two scored 50 or more:

- `democratic_trout_z3n`: its publish script generates a random package name and runs `npm publish` in a loop, and this package is one of those names. `Chain: Registry Spam Publisher` exists for exactly this; it is left out of the corpus, not counted as clean.
- `tavallio-agent`, a legitimate connector for an AI agent: a device name from `os.hostname()` plus a Telegram bot integration made a `Chain: Reconnaissance Beacon`. The Telegram API host no longer counts as a beacon target, since agents and bots call it with the user's own token; a bot token written into the code still does. Malicious recall did not move (141/220, no sample's score changed), and the package now scores 38. It is in `dev`, the other 298 in `holdout`.

That is 1 false positive in 299 random packages (0.3%), PyPI 0 of 150. Nothing else reached 30.

What still got through in the original `dev` split before the November tuning (15 samples; the holdout misses are deliberately not read): forks of legitimate extensions republished with a changed API endpoint or compile server, so the user's code goes to a personal host (chatgpt-china, cppplayground, cortex-debug fork: 7 samples, nothing in the code is malicious on its own; the two that kept the original's `repository` are caught since the popular-extension list grew to 10,000); themes and hello-world extensions whose only offence is the listing (5); typo-squats with no code; an install script that patches a sibling package in `node_modules`; code that builds its C2 host at runtime.

What still gets through in the tuning batch (30 of 100): packages with no code at all (empty placeholders, a native `.node` binary, a typo-squat that copies the original), a proof-of-concept that only prints a warning, DNS exfiltration with every API name spelled as character codes, a javascript-obfuscator variant with mangled names instead of `_0x…`, environment variables stored by one function and sent by another, and a credential stealer for n8n that reads cloud metadata endpoints.
