# Methodology

What KalaScan claims, how the claims are measured, and where they stop. Written for someone auditing the tool: every statement points at a file in the repository that holds the evidence.

Numbers on this page are for ruleset `2026.11.1`, score model v1, measured 2026-11-17, unless a line says otherwise. They are copies. The record is [`eval/results/2026.11.1.json`](https://github.com/wahidhendrawan/KalaScan/blob/main/eval/results/2026.11.1.json) and the [evaluation notes](https://github.com/wahidhendrawan/KalaScan/blob/main/eval/README.md); where this page and they disagree, they are right.

## What KalaScan claims and what it does not

**It claims** to read a package, an IDE extension or a repository before it is installed or merged, without running it, and to flag the ones whose code shows a known malicious behaviour. `kalascan scan` executes nothing from the target; `--sandbox` is the one pass that does, and it is opt-in ([architecture.md](architecture.md), phase 8).

**It claims a measured rate, not a guarantee.** At risk threshold 50, on malicious samples never used to write a rule:

| | flagged | 95% interval |
|---|---|---|
| malicious, all holdout samples | 193 of 302 (64%) | 58-69 |
| malicious, npm packages dated 2026-08-01 or later | 24 of 60 (40%) | 29-53 |
| clean, random npm and PyPI packages, before any fix | 5 of 595 (0.8%) | 0.4-2.0 |

**It does not claim that an unflagged package is safe.** 109 of the 302 malicious holdout samples score below 50. 108 of them score below 30, the band that reports label **safe** ([scoring.md](scoring.md), "What a score means": 71 + 37 in the v1 column). That label means that no combination of findings reached the warning band. It says nothing else.

**What "risk 50" means.** The score is a sum of parts, not a probability ([scoring.md](scoring.md)). 50 is the threshold the evaluation, the CI gate and `kalascan guard` use; the GitHub Action defaults to 60 (`action.yml`). Under v1, in a default scan, the three are the same gate:

- Without a second critical finding the findings add up to 45 at most: one critical 20, high findings 15, medium findings 5, known vulnerabilities 5 (`v1` in `src/score.rs`).
- Two critical findings, or one finding from the list with no benign reading (`decisive` in `src/score.rs`: every behaviour chain and ten named findings), give 70.
- Binary triage runs on every scan and can add up to 20 when a package ships a binary that is packed, has a section both writable and executable, or shows a suspicious capability (`risk_contribution` in `src/triage.rs`). 2 of the 1,297 scanned corpus packages carry such a part ([scoring.md](scoring.md)).

So a default v1 scan that reaches 50 has a chain, a decisive finding, or two critical findings (two rules, or one rule in two files); or, rarely, one critical finding next to a suspicious binary. On the holdout no package, malicious or clean, scores from 50 to 69. `--deobfuscate`, `--emulate`, `--sandbox` and `--ai` add parts that can fill that gap; they were not part of any measurement here.

A score is not the chance that a package is malicious. The holdout is 40% malicious and a registry is not ([scoring.md](scoring.md)). The v2 weights are stated for a base rate of 2%, which is a modelling choice, not a measurement of any registry.

## Threat model

**The adversary** is one of:

- a package author who publishes a new package or extension (vectors AV-100, AV-200 and below in [coverage.md](coverage.md));
- a pull-request author who adds code, a dependency or a workflow to a repository that scans pull requests (AV-301, AV-400);
- someone who has taken over a maintainer's account and publishes a new version of a package people already trust (AV-602, AV-500).

**The adversary controls** every byte of the scanned artefact, the names and paths of its files, its manifest, and the registry metadata an author can set: name, version, description, repository link, publisher name, declared scripts and dependencies. The scanner is built on that assumption. Anything cloned, downloaded or uploaded is scanned as someone else's code: build directories are scanned, inline `kalascan:ignore` markers are not honoured, and `.kalascanignore` and `kalascan.toml` from the checkout are not read ([architecture.md](architecture.md), phase 1; `untrusted` in `action.yml`, default `true`).

A local path scanned without `--untrusted` is treated as the operator's own tree. There, minified and vendored files (`*.min.js`, `vendor/`, `dist/`, `node_modules/`) get YARA only and ignore markers work (README, "File coverage"). A pull-request author controls file names and markers, so a pull-request scan without `--untrusted` can be switched off from inside the pull request.

**The adversary also knows the scanner.** The source, the rules and the corpus are public. A package can be changed and rescanned offline until it scores low. Every recall number on this page describes malware that was not written against KalaScan.

**What the scanner sees:**

- The files of the artefact as published, as text and bytes. Regex rules run on the file types their category names, YARA on every file except prose ([detection-rules.md](detection-rules.md)).
- For a registry name (`npm:`, `pypi:`), the registry's metadata and what changed against the previous version. For a marketplace id, the listing. A local directory or archive gets neither (`parse_package_target` and `parse_marketplace_id` in `src/lib.rs` look at the target string).
- Relations inside one package: two signals within 4 KB or in the same package (`src/correlate.rs`), and variables followed inside one file (`src/dataflow.rs`: one namespace per file, no control flow).

**What it reads only in part:**

- A file over 4 MiB is read up to the cap and reported as `Oversized File (partially scanned)` (`MAX_SCAN_BYTES` in `src/scanner.rs`).
- The data-flow pass skips files over 64 KB and files with minified lines (`src/dataflow.rs`).
- Compiled binaries get YARA and binary triage: file format, packer, section flags, imports (`src/triage.rs`). capa, FLOSS and DIE run only with `--deep-triage`.

**What it cannot see:**

- **How the code got in.** Six vectors are *payload only* in [coverage.md](coverage.md): a commit by a maintainer, a merged pull request, a tampered repository, protestware. The published package looks the same whichever happened. Only what the code does can be judged.
- **Anything outside the package.** Sixteen vectors are *out of scope*: a network path (MITM, DNS), a build host, a registry's own systems, a person who is bribed or phished.
- **What runs later.** A second stage fetched after install is not in the artefact. The static pass sees the fetch, not what is fetched. A host name assembled at run time is in no string.
- **Dependencies.** `scan` and `guard` read the named package, not what it pulls in (README, `kalascan guard`: "What it does not see"). `kalascan deps` scans a lockfile.
- **A package with no code.** A typo-squat that copies the original, an empty placeholder, a listing whose only offence is its name.

Five more vectors are *gaps*: visible in a package or its listing, and not checked yet (AV-201 combosquatting, AV-202 word order, AV-205 standard-library names, AV-208 namespace changes, AV-209 hallucinated package names).

## How a scan decides

[architecture.md](architecture.md), "Scan pipeline", has the ten phases with their modules. In order: acquire the target, changed-only filter, static pass, manifest and registry context, correlation into chains, git history, baseline and ignore filtering, deep passes, AI analysis, risk score and export.

[scoring.md](scoring.md) has the score: v1 (tiers set by hand, the default) and v2 (a weight per finding, fitted on the corpus, opt-in).

The evaluation runs `kalascan scan <target> --untrusted --format json` and no other flag (`scan` in `eval/run_eval.py`). What follows from that:

- The numbers describe the default scan: the static pass, manifest and registry context, chains, binary triage, the score. `--cve`, `--secrets`, `--git-history`, `--deobfuscate`, `--deep-triage`, `--emulate`, `--sandbox` and `--ai` have no measured rate.
- No lookup against a list of known-bad packages takes part. OSV `MAL-*` advisories need `--cve`. Recall is what the rules find in the code.
- URLhaus lookups run only when `URLHAUS_AUTH_KEY` is set in the environment, and `run_eval.py` passes its environment on. The published run does not record whether the key was set. Unset it to measure the rules alone.
- Malicious samples are scanned as extracted archives, so they get no registry or marketplace check. Clean samples are fetched by name and get all of them. Those checks are tested for false positives; what they add to recall is not measured.

## How detection quality is measured

### The corpus

`eval/corpus.json` lists every sample by reference: a path in a malware dataset, or a registry name and version. No sample is in the repository. Entries at this commit:

| label | split | `set` | entries | where from |
|---|---|---|---|---|
| malicious | dev | - | 73 | DataDog dataset; the samples the rules were first tuned on |
| malicious | dev | `tune-2026-11` | 100 | DataDog dataset: 60 PyPI, 40 npm, drawn for tuning and read |
| malicious | holdout | - | 147 | DataDog dataset: 27 early samples and 120 added in November 2026 |
| malicious | holdout | `recent-2026-11` | 60 | DataDog dataset: npm packages dated 2026-08-01 or later |
| malicious | holdout | `malregistry-2026-11` | 100 | pypi_malregistry: PyPI names the DataDog dataset does not have |
| clean | dev | - | 66 | picked: popular npm / PyPI packages and IDE extensions |
| clean | dev | `fit-2026-11` | 298 | random draw from npm and PyPI |
| clean | dev | `random-2026-11` | 3 | random draw; in dev (the evaluation notes name one, `tavallio-agent`, moved after it was read) |
| clean | holdout | - | 161 | picked, as above |
| clean | holdout | `random-2026-11` | 296 | random draw from npm and PyPI |

480 malicious and 824 clean entries. The sources are the [DataDog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) (380 entries: npm, PyPI, IDE extensions) and [pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry) (100 entries, PyPI only). The clean side comes from the public registries and marketplaces.

A sample that cannot be scanned (a broken archive, a package gone from the registry) is an error. It leaves the denominator; it is not a miss (`scan` in `eval/run_eval.py`). The published denominators are 173 and 302 malicious, 365 and 457 clean. Five `malregistry` archives do not unpack, which accounts for 307 entries against 302. The 367 clean dev entries against 365 are not accounted for in any document; the evaluation notes give 297 packages scanned for the second random draw, which has 298 entries, and that may be one of the two. A `--summary` file records the errors of each set.

### Dev and holdout

Each sample has a `split`. Rules are tuned while looking at `dev`. `holdout` is never used for tuning, so the holdout rate is the one to quote.

**A sample somebody has read leaves the holdout.** It moves to `dev`. `run_eval.py` enforces the first half of that: it lists misses and score changes for `dev` only and counts the holdout ones. `--show-holdout` overrides it; what is then read has to be moved. `eval/fit_weights.py` reads `dev` only.

Where the rule was bent, on record in the evaluation notes:

- On 2026-11-17, before counting was the default, one run printed the names and rule names of ten missed `malregistry` samples. No rule or weight was changed in response. They stay in the holdout.
- The holdout total has been read after each change (82, 96, 94 and 99 of 147). A count leaks less than a sample, but it leaks: a change that lowers the count can be dropped.
- Clean holdout samples that were flagged and then read were moved to `dev` and the rules fixed. The clean holdout is therefore what was never flagged. See "The clean side".

### The sample sets

A set drawn later or from another source is its own measurement and is reported on its own line.

| set | drawn with | seed |
|---|---|---|
| `random-2026-11` | `eval/sample_clean.py` | 20261116 |
| `fit-2026-11` | `eval/sample_clean.py --seed 20261117` | 20261117 |
| `recent-2026-11` | `eval/sample_malicious.py --since 2026-08-01 --ecosystem npm` | 20261117 |
| `malregistry-2026-11` | `eval/sample_malicious.py --malregistry` | 20261117 |

The malicious draws take one version per package name and skip names already in the corpus. The 120 holdout samples added in November 2026 and the `tune-2026-11` batch were also drawn with a fixed seed or by a stated rule (the evaluation notes describe both), but their seeds are not written down.

A seed records the procedure. It does not make the draw repeatable. `sample_clean.py` draws a random rank in a live npm index and random names from the live PyPI index, and both grow. `sample_malicious.py` draws from the dataset's current file list. The draw that counts is the one frozen in `eval/corpus.json`.

`sample_malicious.py --since DATE` makes the same draw for a later date. That is the intended measurement at each release: samples newer than the rules.

### The clean side

The clean side decides the false-positive rate, and it is easy to make it too kind.

**Picked packages are a soft test.** 227 entries are popular packages and extensions, some chosen because they look suspicious (install scripts that download binaries, SSH tooling, telemetry). Popular packages are well kept. When the picked set grew from 66 to 227, the first run flagged 9 of the 176 holdout samples (5%).

**Random draws are the harder test.** 150 npm packages by random rank and 150 PyPI packages by random name, twice. Each is pinned to its newest version published before 2026-05-16: registries remove malicious versions within days, so a version that has survived six months is very likely benign. First contact, before any rule was fixed:

- first draw: 1 of 299 flagged;
- second draw: 4 of 297 flagged;
- together 5 of 595: **0.8% (0.4-2.0)**. This is the false-positive rate to quote.

**0 of 457 is not the false-positive rate.** It is the clean holdout after every flagged sample was read, fixed and moved to `dev`. It shows that the fixes hold and that nothing regressed. The evaluation notes say the same: expect the real rate on unseen packages between the first-contact number and zero.

What the clean side does not cover:

- **Labels are assumed.** Nobody verified that a clean package is clean. Two of about 600 random draws were registry spam publishers and were removed from the corpus.
- **The draw is filtered.** Versions newer than the cutoff, packages over 30 MB, npm security placeholders and packages gone from the registry are rejected (the evaluation notes list the counts). New packages, where malware lives, are not in the clean set.
- **No random draw of IDE extensions.** The 66 clean extensions are picked.

### Intervals

Every rate is printed with its 95% Wilson score interval (`wilson` in `eval/run_eval.py`, z = 1.96). The Wilson interval stays honest at 0 of n: 0 of 457 has an upper bound of 0.8%, not zero.

The interval answers one question: how far could the rate on this kind of sample be from the rate measured on these samples. It assumes independent draws. Malware comes in campaigns (five samples of one `setup.py` template in the tuning batch), so the true uncertainty is wider than printed. It says nothing about samples of another kind: malware no dataset has collected, or packages newer than the clean cutoff.

### The CI gate

`.github/workflows/eval.yml` runs the clean half:

```bash
python3 eval/run_eval.py --only clean --threshold 50 --max-fpr 0 --allow-errors --jobs 4
```

It runs on a pull request that touches `src/`, `rules/`, `eval/` or `Cargo.lock`, on manual dispatch, and once a week. Any clean sample at risk 50 or more fails the job.

The weekly run exists because the corpus is fixed and the registries are not. The 66 extension entries are marketplace ids without a version, so each run scans whatever is published that day. Registry metadata changes under a pinned version too: `Maintainer Email Domain Unregistered` fires when a domain lapses. Without a schedule such a change shows up on somebody's unrelated pull request, or never. GitHub stops scheduled workflows in a repository with no activity for 60 days.

What the gate does not check:

- **Recall.** The malicious half never runs in CI. A change that loses detections merges with a green check.
- **Errors.** `--allow-errors` keeps a flaky registry from failing the job. A clean package that has been removed is an `ERR` line in the log and one sample fewer; the gate still passes.
- **Any threshold but 50, and any model but v1.** The range v2 adds between 30 and 70 is not gated.

**Why the malicious half is not run in CI.** The samples are live malware (the header of the workflow file gives that reason). Two things make a CI job the wrong place for them. A pull request changes the code the job builds and runs, the scanner and the harness included, so unreviewed code would run on a machine that holds the samples. And the handling rules below ask for a machine the operator controls and a deletion the operator can check; a hosted runner offers neither. The cost is the first bullet above: recall is measured by a person, at each release, and recorded in `eval/results/`. Nothing enforces that it was.

## Reproducing the numbers

Needed: git, a Rust toolchain, Python 3.12 or later (standard library only; `tarfile` extraction filters), network access to npm, PyPI and the extension marketplaces. Docker only for the GuardDog comparison.

**The clean half** needs no malware and is what CI runs:

```bash
git clone https://github.com/wahidhendrawan/KalaScan && cd KalaScan
cargo build --release --locked
python3 eval/run_eval.py --only clean --summary /tmp/clean.json
```

**The full corpus:**

```bash
eval/fetch_malicious.sh ~/kalascan-corpus ~/kalascan-malregistry   # about 480 files, 1.5 GB
python3 eval/run_eval.py --dataset ~/kalascan-corpus --malregistry ~/kalascan-malregistry \
  --out ~/kalascan-results.json --summary /tmp/summary.json
rm -rf ~/kalascan-corpus ~/kalascan-malregistry
```

Compare `/tmp/summary.json` with the file for the same ruleset version in `eval/results/`. Add `--flag=--score-model=v2` for the v2 columns of [scoring.md](scoring.md). `python3 eval/fit_weights.py ~/kalascan-results.json --cv` repeats the cross-validation table.

**Handling rules.** The malicious samples are live malware.

1. **Static scan only.** `run_eval.py` never passes `--sandbox`. Do not add it with `--flag`. Do not install, import or run anything from the checkouts.
2. **Outside the repository.** The checkouts go in a directory of their own, as above. Archives are unpacked one at a time into a temporary directory that is removed after the scan (`scan` in `eval/run_eval.py`; the dataset's zip password, `..` and absolute member names dropped).
3. **Deleted afterwards.** Remove both checkouts when the run is done.
4. **Do not read the holdout.** The `--out` file holds every sample's name, score and findings, holdout included. Give it to `fit_weights.py` and `--compare`, which read `dev` only. Do not open it. The `--summary` file has no sample names and is the one to share.

**What may differ on your run:**

- `fetch_malicious.sh` clones the current head of both datasets. No commit is pinned. A sample that has been renamed or removed upstream is an error, and the denominator shrinks.
- Clean packages are fetched live. A removed package is an error. An extension is scanned at its current version.
- Compare counts, then intervals. A count that moved by one or two with an error to match is drift. A count that moved without one is a finding: please report it.

**Run time.** The clean half takes about 3 minutes to scan after a 5 minute release build, on a GitHub-hosted runner with four jobs ([run 44063169983](https://github.com/wahidhendrawan/KalaScan/actions/runs/44063169983), 2026-11-17, this corpus). The run time of the malicious half is not recorded anywhere in the repository. It needs no downloads once fetched, and each sample is cut off at 300 seconds (`--timeout`).

## Known limits

From the measured results, not from principle.

1. **Newest npm malware: four in ten.** 24 of 60 (40%, 29-53) on npm packages dated 2026-08-01 or later. npm across the holdout is 55 of 111 (50%), PyPI 106 of 143 (74%), IDE extensions 32 of 48 (67%). Rules tuned on 2022-2025 samples generalise worse to newer ones: until November 2026 the holdout held 27 samples and scored 26.
2. **A third of known malware is missed outright.** 109 of 302 holdout samples score below 50, and 108 of those below 30.
3. **False positives on packages nobody picked: 0.8% (0.4-2.0).** 5 of 595 at first contact. At that rate a lockfile of 1,000 packages raises about 8 flags; that is arithmetic, not a measurement of `kalascan deps`. On popular packages the first-contact rate was 5% (9 of 176). On random IDE extensions it is not measured.
4. **What gets through**, from the misses that were read (evaluation notes, last two paragraphs):
   - packages with no code: empty placeholders, typo-squats that copy the original, a native `.node` binary;
   - forks of legitimate extensions republished with a changed API endpoint, where nothing in the code is malicious on its own;
   - themes and hello-world extensions whose only offence is the listing;
   - an install script that patches a sibling package in `node_modules`;
   - a C2 host built at run time; DNS exfiltration with every API name spelled as character codes;
   - a javascript-obfuscator variant with mangled names instead of `_0x…`;
   - environment variables stored by one function and sent by another (the data-flow pass does not follow calls);
   - a credential stealer that reads cloud metadata endpoints.
5. **What is not looked for**, from [coverage.md](coverage.md): 5 gaps, 6 payload-only vectors and 16 out-of-scope vectors of 50. 17 more are partial; several of those cover IDE extensions only (AV-206, AV-207) or GitHub Actions only (AV-400, AV-701).
6. **One malicious dataset dominates.** 380 of 480 malicious entries, all 173 the rules were tuned on, and every npm and extension sample come from the DataDog dataset. The second source is PyPI only: 70 of 95 there (74%, 64-81) against 36 of 48 (75%) on the DataDog PyPI holdout. Recall on npm and on extensions has no independent check.
7. **Both sources hold malware somebody already caught.** Malware no one has identified is in neither. No number here speaks about it.
8. **The rules are public.** See the threat model: an author who tests against KalaScan is not in the corpus.
9. **Score v2 treats findings as independent** given the class, and they are not: a chain and the two findings it is made of fire together. The halving in the accumulation dampens this and does not remove it ([scoring.md](scoring.md), "Limits"). The weights are fitted on 173 malicious packages from one dataset and 365 clean ones; a finding seen once or twice carries mostly its class prior. With no clean package flagged, v2 catches 193 of 302 and v1 194: v2 is a choice of operating point, not better detection.
10. **The holdout has been touched.** Ten sample names printed once, the total read after each change, flagged clean samples moved out. See "Dev and holdout".
11. **Recall is not gated.** See "The CI gate".
12. **Only the default scan is measured.** `--deobfuscate`, `--deep-triage`, `--emulate`, `--sandbox` and `--ai` have no measured detection or false-positive rate.
13. **The ruleset version is set by hand** (`RULESET_VERSION` in `src/scanner.rs`), and chains, data flow and scoring live in the binary, not in the rule files. A result file is named after the ruleset version; it identifies a result only if the version was raised with the change.
14. **The record for `2026.11.1` was transcribed** from the published tables, not written by a run. Its `source` field says so and lists what is missing.

## How to challenge a result

**A malicious package KalaScan scores low.** Open an [issue](https://github.com/wahidhendrawan/KalaScan/issues) with the package name, the exact version and where it was reported. Do not attach the sample; say where to get it. It goes into the corpus ([SECURITY.md](https://github.com/wahidhendrawan/KalaScan/blob/main/SECURITY.md), "Out of scope").

**A clean package KalaScan flags.** Open an issue with the name and exact version, `kalascan --version`, the first line of `kalascan rules`, the command, and the output of `--format json`. Its `score_breakdown` and `rule_matches` show which findings made the score.

**A number you cannot reproduce.** Open an issue with the commit you built, the `--summary` file of your run, and your Python and OS versions. Do not post the `--out` file or holdout sample names. If you have read a holdout sample, say so: it moves to `dev`.

**A flaw in the method.** A leak between dev and holdout, a biased draw, a wrong interval: an issue, with the file and line.

**A vulnerability in KalaScan itself.** Code execution or a file write outside the temp directory while scanning, an authentication bypass, a sandbox escape: report it privately through [GitHub security advisories](https://github.com/wahidhendrawan/KalaScan/security/advisories/new), not in an issue. A first reply comes within 7 days ([SECURITY.md](https://github.com/wahidhendrawan/KalaScan/blob/main/SECURITY.md)).
