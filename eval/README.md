# Detection eval

`corpus.json` lists labelled samples:

- **malicious**: real packages from the [DataDog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) (npm, PyPI, VS Code extensions), picked with a fixed seed, and 100 PyPI packages from a second, independent source, [pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry) (`"source": "malregistry"`).
- **clean**: popular npm / PyPI packages and VS Code extensions, fetched from the public registries. Several were chosen because they look suspicious on the surface: install scripts that download binaries, local dev servers, SSH tooling, telemetry. Entries with `"set": "random-2026-11"` were not picked but drawn at random from all of npm and PyPI (`eval/sample_clean.py`, see below).

Each sample has a `split`. Rules were tuned while looking at `dev`. `holdout` was added afterwards and never used for tuning, so its numbers are the honest estimate.

```bash
cargo build --release
eval/fetch_malicious.sh ~/kalascan-corpus ~/kalascan-malregistry   # ~480 files (about 1.5 GB), blobless clones
python3 eval/run_eval.py --dataset ~/kalascan-corpus --malregistry ~/kalascan-malregistry --out before.json
# ...change rules...
python3 eval/run_eval.py --dataset ~/kalascan-corpus --malregistry ~/kalascan-malregistry --compare before.json
```

Every rate is printed with its 95% Wilson interval. `--rule-stats` adds, for each finding, how many malicious and clean packages of a split it fired on and the likelihood ratio between the two. Without `--malregistry` the second source is left out.

**Holdout misses are counted, not listed.** A sample somebody has looked at stops being a holdout sample, so the miss list and the score changes show `dev` only (`--show-holdout` overrides this; move what you then read to `dev`). On 2026-11-17, before this was the default, one run printed the names and rule names of ten missed `malregistry` samples. No rule or weight was changed in response; they stay in the holdout.

The malicious samples are **live malware**. `run_eval.py` only scans them statically. It never passes `--sandbox`, and archives are extracted into a temp dir with the dataset password. Keep the corpus outside the repo.

CI (`.github/workflows/eval.yml`) runs only the clean half, as a false-positive gate: `--only clean --max-fpr 0`, on every pull request that touches `src/`, `rules/`, `eval/` or `Cargo.lock`.

Results at threshold 50 (measured 2026-11-17, ruleset 2026.11.2, score model v1; 95% interval in brackets; the aggregate is in [`results/2026.11.2.json`](results/2026.11.2.json)):

| split | malicious recall | clean false positives |
|---|---|---|
| dev | 171/253 (68%, 62-73) | 0/366 (0%, 0-1) |
| holdout | 202/302 (67%, 61-72) | 0/456 (0%, 0-1) |

The dev figure fell from 78% because 80 of the newest npm samples joined it as a tuning batch (below), not because anything was lost.

The holdout by sample set:

| holdout set | what it is | malicious recall |
|---|---|---|
| original | 147 samples: the 27 first ones and 120 added in November 2026 | 101/147 (69%, 61-76) |
| `recent-2026-11` | 60 npm packages dated 2026-08-01 or later, the newest in the dataset | 31/60 (52%, 39-64) |
| `malregistry-2026-11` | 100 PyPI packages from pypi_malregistry whose names the DataDog dataset does not have; 5 archives do not unpack | 70/95 (74%, 64-81) |

**The holdout number is the one to quote, and the `recent` row is the one to worry about**: on the newest npm malware KalaScan catches about half (24 of 60 with ruleset 2026.11.1, before the tuning described next). The second source says the PyPI rules are not fitted to one dataset's taste: 74% there, 36 of 48 (75%) on the DataDog PyPI holdout samples. By ecosystem the holdout is IDE extensions 32/48 (67%), npm 64/111 (58%), PyPI 106/143 (74%).

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

| | malicious, holdout | malicious, all | clean flagged |
|---|---|---|---|
| KalaScan (risk >= 50) | 94/147 (64%) | 153/220 (70%) | 0/227 (0%) |
| GuardDog, threat or metadata rule | 107/147 (73%) | 155/220 (70%) | 128/223 (57%) |
| GuardDog, any rule | 123/147 (84%) | 187/220 (85%) | 213/223 (96%) |

The two tools sit at different points: GuardDog finds more of the malware, most clearly on PyPI (41 of 48 holdout samples against KalaScan's 33), and flags more than half of the popular clean packages on the way; KalaScan flags none of the clean ones and misses more malware. GuardDog was run once, before the November tuning; at that time 66 holdout samples were caught by both, 16 only by KalaScan, 41 only by GuardDog and 24 by neither. The table is from that run: on the same 147 samples KalaScan is now at 101, and GuardDog has not been run on the two newer holdout sets. Read the comparison with two caveats: the malicious samples come from DataDog's own dataset, which GuardDog's rules were developed against, and four large clean PyPI packages timed out under GuardDog (300 s) and are left out of its column.

The 60 extensions installed on the maintainer's machine (`kalascan installed`) also all score below 30. Ten of them were false positives during development and are now in the clean `dev` split.

**Honest false-positive number.** When the clean set grew from 66 to 227 samples (161 new ones in `holdout`, untouched by tuning), the first run flagged **9 of the 176 holdout clean samples (5%)**: greedy regexes (`powershell .* -enc` across a minified line, `bcdedit` inside base64), `~/.ethereum/geth.ipc` read as a wallet, a bidi character used as a regex range, official `curl … | sh` installers (gh.io, antigravity.google, nvm) and firebase-tools chmodding one file while spawning another. Those rules were fixed and the 12 samples looked at moved to `dev`; the remaining 165 holdout clean samples score below 50. Expect the real rate on unseen packages to sit somewhere between the two numbers.

**Packages nobody picked.** Popular packages are a soft test: they are well kept, and the list was partly chosen by hand. So 300 packages were drawn at random from the whole registries (`python3 eval/sample_clean.py`, seed 20261116): 150 by random rank in the [ecosyste.ms](https://packages.ecosyste.ms) npm index, 150 by random name from the PyPI simple index, each pinned to its newest version published before 2026-05-16. Registries take malicious versions down within days, so one that has survived six months is very likely benign. Rejected draws were npm 109 too new, 8 security placeholders, 7 gone, 4 over 30 MB, 2 index errors; PyPI 55 too new, 14 gone. Two scored 50 or more:

- `democratic_trout_z3n`: its publish script generates a random package name and runs `npm publish` in a loop, and this package is one of those names. `Chain: Registry Spam Publisher` exists for exactly this; it is left out of the corpus, not counted as clean.
- `tavallio-agent`, a legitimate connector for an AI agent: a device name from `os.hostname()` plus a Telegram bot integration made a `Chain: Reconnaissance Beacon`. The Telegram API host no longer counts as a beacon target, since agents and bots call it with the user's own token; a bot token written into the code still does. Malicious recall did not move (141/220, no sample's score changed), and the package now scores 38. It is in `dev`, the other 298 in `holdout`.

That is 1 false positive in 299 random packages (0.3%), PyPI 0 of 150. Nothing else reached 30.

What still got through in the original `dev` split before the November tuning (15 samples; the holdout misses are deliberately not read): forks of legitimate extensions republished with a changed API endpoint or compile server, so the user's code goes to a personal host (chatgpt-china, cppplayground, cortex-debug fork: 7 samples, nothing in the code is malicious on its own; the two that kept the original's `repository` are caught since the popular-extension list grew to 10,000); themes and hello-world extensions whose only offence is the listing (5); typo-squats with no code; an install script that patches a sibling package in `node_modules`; code that builds its C2 host at runtime.

What still gets through in the tuning batch (30 of 100): packages with no code at all (empty placeholders, a native `.node` binary, a typo-squat that copies the original), a proof-of-concept that only prints a warning, DNS exfiltration with every API name spelled as character codes, a javascript-obfuscator variant with mangled names instead of `_0x…`, environment variables stored by one function and sent by another, and a credential stealer for n8n that reads cloud metadata endpoints.
