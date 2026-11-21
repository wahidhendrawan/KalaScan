# Methodology

What KalaScan claims, how the claims are measured, and where they stop. Written for someone auditing the tool: every statement points at a file in the repository that holds the evidence.

Numbers on this page are for ruleset `2026.11.13`, score model v1, measured 2026-11-21, unless a line says otherwise. They are copies. The record is [`eval/results/2026.11.13.json`](https://github.com/wahidhendrawan/KalaScan/blob/main/eval/results/2026.11.13.json) and the [evaluation notes](https://github.com/wahidhendrawan/KalaScan/blob/main/eval/README.md); where this page and they disagree, they are right.

## What KalaScan claims and what it does not

**It claims** to read a package, an IDE extension or a repository before it is installed or merged, without running it, and to flag the ones whose code shows a known malicious behaviour. `kalascan scan` executes nothing from the target; `--sandbox` is the one pass that does, and it is opt-in ([architecture.md](architecture.md), phase 8).

**It claims a measured rate, not a guarantee.** At risk threshold 50, on malicious samples never used to write a rule:

| | flagged | 95% interval |
|---|---|---|
| malicious, all holdout samples | 725 of 1,109 (65%) | 63-68 |
| malicious, newer than the rules: drawn after ruleset 2026.11.12 (`rolling-2026-11`) | 62 of 131 (47%) | 39-56 |
| malicious, holdout packages and IDE extensions before the rolling draw | 644 of 876 (74%) | 70-76 |
| malicious, AI agent skills in the holdout (`skills-2026-11`) | 19 of 102 (19%) | 12-27 |
| the same skills with `--ai` (DeepSeek, measured once) | 49 of 102 (48%) | 39-58 |
| malicious, holdout samples dated 2026-08-01 or later (newer than most of what the rules were written from) | 103 of 210 (49%) | 42-56 |
| malicious, drawn after ruleset 2026.11.2 (`fresh-2026-11`) | 91 of 156 (58%) | 50-66 |
| malicious, drawn before ruleset 2026.11.5 (`fresh2-2026-11`; the tuning batch came from the same months) | 155 of 195 (79%) | 73-85 |
| malicious, npm samples in the holdout | 408 of 601 (68%) | 64-71 |
| malicious, npm from a second source, mostly 2021-2024 (`npmstudy-2026-11`) | 159 of 200 (80%) | 73-85 |
| malicious, npm packages dated 2026-08-01 or later (`recent-2026-11`) | 34 of 59 (58%) | 45-69 |
| clean, random npm and PyPI packages, before any fix | 19 of 2,584 (0.7%) | 0.5-1.1 |
| clean, random Open VSX extensions, before any fix (two draws) | 21 of 542 (3.9%) | 2.5-5.9 |
| clean, random AI agent skills from GitHub, before any fix | 6 of 487 (1.2%) | 0.6-2.7 |

**It does not claim that an unflagged package is safe.** 232 of the 876 malicious holdout packages and extensions score below 50, 69 of the 131 in the rolling draw, and 83 of the 102 AI agent skills. 231 of the 232, and all 69, score below 30, the band that reports label **safe** ([scoring.md](scoring.md), "What a score means"). That label means that no combination of findings reached the warning band. It says nothing else.

**What "risk 50" means.** The score is a sum of parts, not a probability ([scoring.md](scoring.md)). 50 is the threshold the evaluation, the CI gate and `kalascan guard` use; the GitHub Action defaults to 60 (`action.yml`). Under v1, in a default scan, the three are the same gate:

- Without a second critical finding the findings add up to 45 at most: one critical 20, high findings 15, medium findings 5, known vulnerabilities 5 (`v1` in `src/score.rs`).
- Two critical findings, or one finding from the list with no benign reading (`decisive` in `src/score.rs`: every behaviour chain and ten named findings), give 70.
- Binary triage runs on every scan and can add up to 20 when a package ships a binary that is packed, has a section both writable and executable, or shows a suspicious capability (`risk_contribution` in `src/triage.rs`). 2 of the 1,297 scanned corpus packages carry such a part ([scoring.md](scoring.md)).

So a default v1 scan that reaches 50 has a chain, a decisive finding, or two critical findings (two rules, or one rule in two files; credentials written into the package count as one finding together); or, rarely, one critical finding next to a suspicious binary. On the holdout no package, malicious or clean, scores from 50 to 69. `--deobfuscate`, `--emulate`, `--sandbox` and `--ai` add parts that can fill that gap. `--sandbox`, `--deobfuscate`, `--emulate` and `--deep-triage` were measured once each and changed no count at 50 (Known limits, 12); `--ai` was measured once, on AI agent skills only.

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

- A file over 4 MiB is read with whitespace runs longer than 64 bytes collapsed; of what remains the first 3 MiB and the last 1 MiB are scanned, and it is reported as `Oversized File (partially scanned)` (`read_capped` in `src/scanner.rs`). The middle of a large file that is not padding is not read.
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

- The numbers describe the default scan: the static pass, manifest and registry context, chains, binary triage, the score. `--cve`, `--secrets` and `--git-history` have no measured rate, `--ai` one on AI agent skills only; `--sandbox`, `--deobfuscate`, `--emulate` and `--deep-triage` have one run each, outside the published numbers.
- No lookup against a list of known-bad packages takes part. OSV `MAL-*` advisories need `--cve`. Recall is what the rules find in the code.
- URLhaus lookups run only when `URLHAUS_AUTH_KEY` is set in the environment, and `run_eval.py` passes its environment on. The published run does not record whether the key was set. Unset it to measure the rules alone.
- Malicious samples are scanned as extracted archives, so they get no registry or marketplace check. Clean samples are fetched by name and get all of them. Those checks are tested for false positives. What they would add to recall was measured by replay, twice: the history checks add one holdout sample at most (Known limits, 15); scanning the dependencies that were days old adds 12, which would have made 490 of the 683 holdout samples of the time (72%) and is not in the published rate (Known limits, 17).

## How detection quality is measured

### The corpus

`eval/corpus.json` lists every sample by reference: a path in a malware dataset, or a registry name and version. No sample is in the repository. Entries at this commit:

| label | split | `set` | entries | where from |
|---|---|---|---|---|
| malicious | dev | - | 73 | DataDog dataset; the samples the rules were first tuned on |
| malicious | dev | `tune-2026-11` | 100 | DataDog dataset: 60 PyPI, 40 npm, drawn for tuning and read |
| malicious | dev | `tune-recent-2026-11` | 80 | DataDog dataset: npm packages dated 2026-08-01 or later, drawn for tuning and read |
| malicious | dev | `tune-fresh-2026-11` | 150 | DataDog dataset: 100 npm packages dated 2026-01-01 or later; pypi_malregistry: 50 PyPI; drawn for tuning and read |
| malicious | dev | `tune-ext-2026-11` | 24 | DataDog dataset: every IDE extension name not in the corpus before, drawn for tuning and read |
| malicious | dev | `tune-npm-2026-11` | 200 | DataDog dataset: npm packages dated 2026-01-01 or later, drawn for tuning and read |
| malicious | holdout | - | 147 | DataDog dataset: 27 early samples and 120 added in November 2026 |
| malicious | holdout | `recent-2026-11` | 60 | DataDog dataset: npm packages dated 2026-08-01 or later |
| malicious | holdout | `malregistry-2026-11` | 100 | pypi_malregistry: PyPI names the DataDog dataset does not have |
| malicious | holdout | `fresh-2026-11` | 161 | drawn 2026-11-18, after the last rule change: DataDog 100 npm and 1 PyPI dated 2026-08-01 or later; pypi_malregistry 60 PyPI |
| malicious | holdout | `fresh2-2026-11` | 200 | drawn 2026-11-18, before ruleset 2026.11.5: DataDog 150 npm dated 2026-01-01 or later; pypi_malregistry 50 PyPI |
| malicious | holdout | `late-2026-11` | 26 | drawn 2026-11-18: every npm name dated 2026-08-01 or later that the corpus did not have |
| malicious | holdout | `npmstudy-2026-11` | 200 | drawn 2026-11-19 from the ASE 2026 npm study: names the DataDog dataset does not have |
| clean | dev | - | 68 | picked: popular npm / PyPI packages and IDE extensions |
| clean | dev | `fit-2026-11` | 298 | random draw from npm and PyPI |
| clean | dev | `random-2026-11` | 5 | random draw; in dev (the evaluation notes name three, `tavallio-agent`, `responsive-embed` and `liangzimixin`, moved after they were read) |
| clean | holdout | - | 159 | picked, as above |
| clean | holdout | `random-2026-11` | 294 | random draw from npm and PyPI |
| clean | dev | `random2-2026-11` | 16 | larger random draw; the packages that scored 30 or more, moved after they were read |
| clean | holdout | `random2-2026-11` | 1,977 | larger random draw from npm and PyPI |
| clean | dev | `openvsx-random-2026-11` | 3 | random draw from Open VSX; extensions that scored 50 or more and were fixed, moved after they were read |
| clean | holdout | `openvsx-random-2026-11` | 242 | random draw of IDE extensions from Open VSX |

1,521 malicious and 3,062 clean entries. The sources are the [DataDog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) (1,061 entries: npm, PyPI, IDE extensions), [pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry) (260 entries, PyPI only) and [the ASE 2026 npm study](https://doi.org/10.6084/m9.figshare.31869370) (200 entries, npm only). The clean side comes from the public registries and marketplaces.

A sample that cannot be scanned (a broken archive, a package gone from the registry) is an error. It leaves the denominator; it is not a miss (`scan` in `eval/run_eval.py`). The published denominators are 626 and 883 malicious, 388 and 2,665 clean. Eleven pypi_malregistry archives do not unpack (five in `malregistry-2026-11`, two in `fresh-2026-11`, four in `fresh2-2026-11`), which accounts for 894 holdout entries against 883. One extension in `tune-ext-2026-11` holds more files than the scanner accepts (11,859 against a limit of 10,000): 627 dev entries against 626. Two clean dev packages cannot be scanned (one fails to unpack, one has no downloadable file left on PyPI), which accounts for 390 entries against 388. Six `random2-2026-11` packages and one `openvsx-random-2026-11` extension cannot be scanned either: 2,672 clean holdout entries against 2,665. A `--summary` file records the errors of each set.

### Dev and holdout

Each sample has a `split`. Rules are tuned while looking at `dev`. `holdout` is never used for tuning, so the holdout rate is the one to quote.

**A sample somebody has read leaves the holdout.** It moves to `dev`. `run_eval.py` enforces the first half of that: it lists misses and score changes for `dev` only and counts the holdout ones. `--show-holdout` overrides it; what is then read has to be moved. `eval/fit_weights.py` reads `dev` only.

Where the rule was bent, on record in the evaluation notes:

- On 2026-11-17, before counting was the default, one run printed the names and rule names of ten missed `malregistry` samples. No rule or weight was changed in response. They stay in the holdout.
- The holdout total has been read after each change (82, 96, 94, 99 and 101 of 147; 193 and 202 of 302). The `fresh-2026-11` set was drawn after ruleset 2026.11.2 and has been counted three times: 78 of 159 then, 89 after the tuning on `tune-fresh-2026-11`, 89 again with ruleset 2026.11.4; 281, 306 and 306 of 461 for the whole holdout. `fresh2-2026-11` was drawn before ruleset 2026.11.5 and counted twice: 138 of 196 before, 156 after (444 and 465 of 657 for the whole holdout). `npmstudy-2026-11` has been counted once (159 of 200). `late-2026-11` has been counted twice (13 of 26 both times; 478 and 480 of 683 for the whole holdout, rulesets 2026.11.6 and 2026.11.7). A count leaks less than a sample, but it leaks: a change that lowers the count can be dropped.
- Ruleset 2026.11.8: a false-positive fix (the Telegram API host in install-time chains) lowered the holdout count by one; the change that lowered it was narrowed and the run repeated. Which sample it was was not printed, only the finding it lost.
- Ruleset 2026.11.9: the holdout count was read once, after the changes, and did not move (639 of 883). A harness fix changed one `dev` count ("Reproducing the numbers").
- Ruleset 2026.11.10: the two agent-file lures were tried as a regex on the samples before they were written, and that run counted the AI skills holdout (19 of 102 would be reached, 7 before); the count was not used to change the patterns. The package and extension holdout was read once, after the changes, and did not move (639 of 883).
- Ruleset 2026.11.11: the holdout was counted six times, in two rounds. Round one (data flow across calls, encoded literals): a first version gave 6 more and flagged 5 clean samples; narrowed for those five, 2 more (660 of 985). Round two (false positives read off new releases, below): the first version lost 3 of the 660. Two were lost to a scoring change, one critical rule in two files counted once, which was dropped because of them; which rule was left on each was counted, the samples were not read. The third had lost its only chain to the list of official installers; to see which host, it was read and moved to `dev` (`openclaw-droid` 1.0.1: NodeSource's installer in an install script), and the list was kept. The last count is 659 of 984: no holdout sample caught before is missed. A count that drops is the holdout steering a change, and here it did twice; both are on record (evaluation notes, "Encoded literals and calls in the data flow" and "Reading what the watch flagged").
- Ruleset 2026.11.12 (35 narrowings from a second reading of new releases): the whole holdout was counted twice. The first count was 645 of 984, 14 fewer. To find the change behind each loss, the 14 samples were scanned with 30 builds that held the changes one after another, and then with three candidates; they were counted by the finding they had lost and not read. Three changes were dropped and four narrowed for them; for an eighth, a narrower version was tried first, did not bring the sample back, and the change was dropped. The second count is 659 of 984, with no sample lost or gained. This is the holdout steering changes again, eight times in one round; what it protects is on record too: six of the 14 were caught by an install hook and a network call that share a package and nothing else (evaluation notes, "What was still flagged, read by class").
- Ruleset 2026.11.13: the rolling holdout (`rolling-2026-11`) was counted before any change, 38 of 131, and the whole holdout four times: before the changes, then with three builds (725 of 1,109 each time). Seven npm `0.0.0-stage` placeholders were taken out of the corpus first, six of them holdout samples, all missed: they hold no code. That the seven were all missed was seen from the count, and their names were read to find them. With `--ai`, the AI skills holdout was counted at four cuts of the model's risk (49 of 102 at 60 and 70, 45 at 80 and 85) and the cut set at 70: the holdout chose between two values. Two clean skills the model flagged were read and moved to `dev` (evaluation notes, "A rolling holdout" and "AI agent skills by meaning").
- Clean holdout samples that were flagged and then read were moved to `dev` and the rules fixed. The clean holdout is therefore what was never flagged. See "The clean side".

### The sample sets

A set drawn later or from another source is its own measurement and is reported on its own line.

| set | drawn with | seed |
|---|---|---|
| `random-2026-11` | `eval/sample_clean.py` | 20261116 |
| `fit-2026-11` | `eval/sample_clean.py --seed 20261117` | 20261117 |
| `recent-2026-11` | `eval/sample_malicious.py --since 2026-08-01 --ecosystem npm` | 20261117 |
| `malregistry-2026-11` | `eval/sample_malicious.py --malregistry` | 20261117 |
| `fresh-2026-11` | `eval/sample_malicious.py --since 2026-08-01 --ecosystem npm`, the same with `--ecosystem pypi`, and `--malregistry --size 60` | 20261118 |
| `tune-fresh-2026-11` (dev) | `eval/sample_malicious.py --since 2026-01-01 --ecosystem npm --size 100` and `--malregistry --size 50` | 20261119 |
| `tune-ext-2026-11` (dev) | `eval/sample_malicious.py --ecosystem ide_extensions` (all 24 names left) | 20261120 |
| `fresh2-2026-11` | `eval/sample_malicious.py --since 2026-01-01 --ecosystem npm --size 150` and `--malregistry --size 50` | 20261121 |
| `tune-npm-2026-11` (dev) | `eval/sample_malicious.py --since 2026-01-01 --ecosystem npm --size 200`, drawn after `fresh2-2026-11` | 20261122 |
| `late-2026-11` | `eval/sample_malicious.py --since 2026-08-01 --ecosystem npm` (all 26 names left) | 20261123 |
| `npmstudy-2026-11` | `eval/sample_malicious.py --npmstudy --size 200` | 20261117 |
| `random2-2026-11` | `eval/sample_clean.py --size 1000 --draws 2200` | 20261124 |
| `openvsx-random-2026-11` | `eval/sample_clean.py --openvsx --size 300 --draws 420` | 20261125 |

The malicious draws take one version per package name and skip names already in the corpus. The 120 holdout samples added in November 2026 and the `tune-2026-11` batch were also drawn with a fixed seed or by a stated rule (the evaluation notes describe both), but their seeds are not written down.

A seed records the procedure. It does not make the draw repeatable. `sample_clean.py` draws a random rank in a live npm index and random names from the live PyPI index, and both grow. `sample_malicious.py` draws from the dataset's current file list. The draw that counts is the one frozen in `eval/corpus.json`.

`sample_malicious.py --since DATE` makes the same draw for a later date. That is the intended measurement at each release: samples newer than the rules. For ruleset 2026.11.9 that is `sample_malicious.py --since 2026-11-20`; on 2026-11-19 the dataset holds no sample that new, so the draw waits until it does. Until the dataset has such samples, `run_eval.py --since 2026-08-01` reports the holdout samples dated August 2026 or later as their own line (`holdout/since-2026-08-01` in the results file), and tuning batches are drawn with `--before 2026-08-01`. `tune-recent-2026-11`, read for ruleset 2026.11.2, is from those months, so the slice is newer than most of the tuning data, not all of it.

### The clean side

The clean side decides the false-positive rate, and it is easy to make it too kind.

**Picked packages are a soft test.** 227 entries are popular packages and extensions, some chosen because they look suspicious (install scripts that download binaries, SSH tooling, telemetry). Popular packages are well kept. When the picked set grew from 66 to 227, the first run flagged 9 of the 176 holdout samples (5%).

**Random draws are the harder test.** 150 npm packages by random rank and 150 PyPI packages by random name, twice, then 1,000 of each. Each is pinned to its newest version published before 2026-05-16: registries remove malicious versions within days, so a version that has survived six months is very likely benign. First contact, before any rule was fixed:

- first draw: 1 of 299 flagged;
- second draw: 4 of 297 flagged;
- third draw: 18 of 1,993 flagged, 4 of them registry spam publishers (not clean), so 14 of 1,989;
- together 19 of 2,584: **0.7% (0.5-1.1)**. This is the false-positive rate to quote for packages.

IDE extensions were drawn the same way from Open VSX (`sample_clean.py --openvsx`, the 21,685 extensions of its sitemap; Open VSX search stops at offset 10,000): 300 drawn, 249 with a universal version published before 2026-05-16. First contact: **7 of 248 at risk 50 or more**, one of them not clean (below), so **6 of 247 (2.4%, 1.1-5.2)**. An extension bundles its dependencies, so a scan reads more code than for a package; the rate is about three times the package rate, and the intervals barely overlap. Three were fixed. Three are flagged by design (a republished copy of a Microsoft extension, an AI usage dashboard that reads five tools' tokens, an SDK that sends its own key) and were taken out of the corpus, as `debi` and `ocr4` were (evaluation notes, "Random IDE extensions").

A second draw of 297 extensions with ruleset 2026.11.9 flagged **15 of 295 (5.1%, 3.1-8.2)**; 9 were fixed and 6 flagged by design were taken out (evaluation notes, "Random IDE extensions, a second draw"). AI agent skills have no registry: 487 were drawn from GitHub code search or listed from nine vendor repositories, each pinned to a commit (`sample_clean.py --skills`). **6 of 487 (1.2%, 0.6-2.7)** were flagged at first contact, all whole repositories with a `SKILL.md` at the root; one was fixed and five taken out (evaluation notes, "AI agent skills"). Nobody vets a GitHub repository the way a registry removes malware, so these labels are weaker still than the packages'.

Of the 14 in the third draw, 12 were fixed and 2 were left as they are and taken out of the corpus: a tool that installs `.deb` files it downloads from a personal host, and one obfuscated file run through `eval`. Both are behaviours KalaScan flags by design (evaluation notes, "Packages nobody picked, a larger draw").

**0 of 3,424 is not the false-positive rate.** It is the clean holdout after every flagged sample was read, fixed and moved to `dev`. It shows that the fixes hold and that nothing regressed. The evaluation notes say the same: expect the real rate on unseen packages between the first-contact number and zero.

What the clean side does not cover:

- **Labels are assumed.** Nobody verified that a clean package is clean. Six of about 2,600 random draws were registry spam publishers and were removed from the corpus; one random extension hides a payload that reports the user's prompts to a company server.
- **The draw is filtered.** Versions newer than the cutoff, packages over 30 MB, npm security placeholders and packages gone from the registry are rejected (the evaluation notes list the counts). New packages, where malware lives, are not in the clean set.
- **No random draw of IDE extensions.** The 66 clean extensions are picked.

### Intervals

Every rate is printed with its 95% Wilson score interval (`wilson` in `eval/run_eval.py`, z = 1.96). The Wilson interval stays honest at 0 of n: 0 of 3,424 has an upper bound of 0.1%, not zero.

The interval answers one question: how far could the rate on this kind of sample be from the rate measured on these samples. It assumes independent draws. Malware comes in campaigns (five samples of one `setup.py` template in the tuning batch), so the true uncertainty is wider than printed. It says nothing about samples of another kind: malware no dataset has collected, or packages newer than the clean cutoff.

### The CI gate

`.github/workflows/eval.yml` runs the clean half:

```bash
python3 eval/run_eval.py --only clean --threshold 50 --max-fpr 0 --allow-errors --jobs 4
```

It runs on a pull request that touches `src/`, `rules/`, `eval/` or `Cargo.lock`, on manual dispatch, and once a week. Any clean sample at risk 50 or more fails the job. A pull request adds `--skip-set random2-2026-11` and scans the other 1,069 clean entries (824 took about 3 minutes; the 245 random extensions added since have not been timed on a runner); the weekly and manual runs scan all 3,062. A false positive that only the large draw holds therefore surfaces within a week of the merge, and before a release, whose ruleset measurement scans everything.

The weekly run exists because the corpus is fixed and the registries are not. The 66 extension entries are marketplace ids without a version, so each run scans whatever is published that day. Registry metadata changes under a pinned version too: `Maintainer Email Domain Unregistered` fires when a domain lapses. Without a schedule such a change shows up on somebody's unrelated pull request, or never. GitHub stops scheduled workflows in a repository with no activity for 60 days.

What the gate does not check:

- **Recall.** The malicious half never runs in CI. A change that loses detections merges with a green check.
- **Errors.** `--allow-errors` keeps a flaky registry from failing the job. A clean package that has been removed is an `ERR` line in the log and one sample fewer; the gate still passes.
- **Any threshold but 50, and any model but v1.** The range v2 adds between 30 and 70 is not gated.

**Why the malicious half is not run in CI.** The samples are live malware (the header of the workflow file gives that reason). Two things make a CI job the wrong place for them. A pull request changes the code the job builds and runs, the scanner and the harness included, so unreviewed code would run on a machine that holds the samples. And the handling rules below ask for a machine the operator controls and a deletion the operator can check; a hosted runner offers neither. The cost is the first bullet above: recall is measured by a person, at each release, and recorded in `eval/results/`. What is enforced is that it was recorded: a pull request that changes a rule file or a detection module must bump `RULESET_VERSION` (CI job `ruleset`), and `cargo test` fails while `eval/results/<version>.json` is missing or has no holdout. That the file came from an honest run is not enforced; the procedure is in CONTRIBUTING.md, "Ruleset versions".

## Reproducing the numbers

Needed: git, a Rust toolchain, Python 3.12 or later (standard library only; `tarfile` extraction filters), network access to npm, PyPI and the extension marketplaces. Docker only for the GuardDog comparison and the sandbox run.

**The clean half** needs no malware and is what CI runs:

```bash
git clone https://github.com/wahidhendrawan/KalaScan && cd KalaScan
cargo build --release --locked
python3 eval/run_eval.py --only clean --summary /tmp/clean.json
```

**The full corpus:**

```bash
eval/fetch_malicious.sh ~/kalascan-corpus ~/kalascan-malregistry
eval/fetch_npmstudy.py ~/kalascan-npmstudy
python3 eval/run_eval.py --dataset ~/kalascan-corpus --malregistry ~/kalascan-malregistry \
  --npmstudy ~/kalascan-npmstudy --out ~/kalascan-results.json --summary /tmp/summary.json
rm -rf ~/kalascan-corpus ~/kalascan-malregistry ~/kalascan-npmstudy
```

Compare `/tmp/summary.json` with the file for the same ruleset version in `eval/results/`. Add `--flag=--score-model=v2` for the v2 columns of [scoring.md](scoring.md). `python3 eval/fit_weights.py ~/kalascan-results.json --cv` repeats the cross-validation table.

**Handling rules.** The malicious samples are live malware.

1. **Static scan, unless the machine is thrown away.** Do not install, import or run anything from the checkouts. `--flag=--sandbox` executes the samples, and `run_eval.py` refuses it without `--disposable-vm`. Pass that only on a VM made for the run, with no host file sharing and nothing else on it, deleted or emptied afterwards. The one sandbox run used an OrbStack machine created with `--isolated --isolate-network`.
2. **Outside the repository.** The checkouts go in a directory of their own, as above. Archives are unpacked one at a time into a temporary directory that is removed after the scan (`scan` in `eval/run_eval.py`; the dataset's zip password, `..` and absolute member names dropped).
3. **Deleted afterwards.** Remove both checkouts when the run is done.
4. **Do not read the holdout.** The `--out` file holds every sample's name, score and findings, holdout included. Give it to `fit_weights.py` and `--compare`, which read `dev` only. Do not open it. The `--summary` file has no sample names and is the one to share.

**What may differ on your run:**

- `fetch_malicious.sh` clones the current head of both datasets. No commit is pinned. A sample that has been renamed or removed upstream is an error, and the denominator shrinks.
- Clean packages are fetched live. A removed package is an error. An extension is scanned at its current version.
- Compare counts, then intervals. A count that moved by one or two with an error to match is drift. A count that moved without one is a finding: please report it.

**Run time.** The clean half takes about 3 minutes to scan after a 5 minute release build, on a GitHub-hosted runner with four jobs ([run 44063169983](https://github.com/wahidhendrawan/KalaScan/actions/runs/44063169983), 2026-11-17, with 824 clean entries). The corpus now holds 3,062, so expect about three and a half times as long for a full run; that is arithmetic, not a measured run. The run time of the malicious half is not recorded anywhere in the repository. It needs no downloads once fetched, and each sample is cut off at 300 seconds (`--timeout`).

**Time per scan**, from the `seconds` each record carries (ruleset 2026.11.8, 2026-11-19, a 7-core VM running 7 scans at once, so a lone scan is faster; clean times include the registry download, malicious ones the unpacking):

| what | scans | median | 95th percentile | slowest |
|---|---|---|---|---|
| clean npm package | 1,385 | 1.9 s | 4.9 s | 13.9 s |
| clean PyPI package | 1,358 | 0.6 s | 1.6 s | 23.5 s |
| clean extension, picked (VS Code Marketplace, popular) | 66 | 3.1 s | 41.0 s | 50.6 s |
| clean extension, random (Open VSX) | 248 | 1.8 s | 12.9 s | 93.7 s |
| malicious npm (DataDog) | 831 | 0.4 s | 23.7 s | 222.5 s |
| malicious PyPI (DataDog) | 126 | 0.5 s | 29.9 s | 123.5 s |
| malicious IDE extension | 103 | 0.4 s | 3.1 s | 8.1 s |

The slow tail is size: compromised releases of large libraries, and extensions that ship tens of megabytes (Claude Code, Continue, the C++ and Java tools). The whole corpus took about 17 minutes.

**One harness bug, found with ruleset 2026.11.9.** When an archive held two directories with a manifest at the same depth, `package_root` scanned whichever `os.walk` returned first. One `dev` sample (`perfkitbenchmarker` 9.9.9) holds the malicious package next to a copy of the source it imitates; the source was scanned, and the sample was caught only because a hostname read and a test fixture's IP address in two unrelated files made a beacon. A tie now scans the common parent. In the full run it changed that one sample and nothing else.

## Known limits

From the measured results, not from principle.

1. **npm malware: two in three, the newest under half.** 394 of 586 npm samples in the holdout (67%, 63-71; DataDog 235 of 386, the ASE 2026 study 159 of 200); of the holdout samples dated August 2026 or later, 89 of 195 (46%, 39-53), against 147 of 192 (77%) for npm dated before. PyPI is at 214 of 248 (86%), IDE extensions 32 of 48 (67%). The 80% on `fresh2-2026-11` is high partly because it shares campaigns with the batch the last rules were written from (eval/README.md, "npm tuning with GuardDog as a second reader"); `fresh-2026-11`, drawn earlier from later months, is at 57%. About a third of each npm tuning batch has no malicious code in the package's own files (a payload in a dependency, a native binary, a real library published at a hijacked version), which caps what a static scan of the artefact can reach. Among the newest it is two thirds: of the 44 `tune-recent-2026-11` samples ruleset 2026.11.6 missed, 30 are of that kind (eval/README.md, "Reading the newest misses"). Rules tuned on 2022-2025 samples generalise worse to newer ones: until November 2026 the holdout held 27 samples and scored 26.
2. **A quarter of known malware is missed outright, half of the newest, and four in five AI agent skills.** 232 of 876 holdout packages and extensions score below 50, and 231 of those below 30; 69 of the 131 samples drawn after the rules were written; 83 of 102 malicious AI agent skills, 53 with `--ai` (eval/README.md, "AI agent skills" and "A rolling holdout").
3. **False positives on packages nobody picked: 0.7% (0.5-1.1).** 19 of 2,584 at first contact. At that rate a lockfile of 1,000 packages raises about 7 flags; that is arithmetic, not a measurement of `kalascan deps`. On popular packages the first-contact rate was 5% (9 of 176). On random IDE extensions it is 3.9% (2.5-5.9): 21 of 542 at first contact over two draws (6 of 247, then 15 of 295 with ruleset 2026.11.9). On random AI agent skills 1.2% (0.6-2.7): 6 of 487. On releases published that day it was 2.7% (2.5-2.9), 574 of 21,257, with ruleset 2026.11.10 and the first 2026.11.11, and about 1.7% after the changes made for them (360 of the same 574 still flagged; the rest of the 21,257 were not scanned again). A second round, ruleset 2026.11.12, took the 618 releases flagged by any build since then from 389 to 270; ruleset 2026.11.13 flags 272 of them, and none of 1,498 releases drawn at random from those the watch had scored under 50. New releases are agent CLIs, installers and large applications, not the long tail the random draws are made of, and this is the rate `kalascan watch` and `kalascan guard` meet.
4. **What gets through**, from the misses that were read (evaluation notes, last two paragraphs):
   - packages with no code: empty placeholders, typo-squats that copy the original, a native `.node` binary;
   - forks of legitimate extensions republished with a changed API endpoint, where nothing in the code is malicious on its own;
   - themes and hello-world extensions whose only offence is the listing;
   - an install script that patches a sibling package in `node_modules`;
   - a C2 host built at run time; DNS exfiltration with every API name spelled as character codes;
   - a javascript-obfuscator variant with mangled names instead of `_0x…`;
   - a secret kept in a global by one function and sent by another, or handed to a function in another file (the data-flow pass follows calls inside one file only);
   - a credential stealer that reads cloud metadata endpoints.
5. **What is not looked for**, from [coverage.md](coverage.md): 5 gaps, 6 payload-only vectors and 16 out-of-scope vectors of 50. 17 more are partial; several of those cover IDE extensions only (AV-206, AV-207) or GitHub Actions only (AV-400, AV-701).
6. **One malicious dataset dominates.** 1,061 of 1,521 malicious entries, 576 of the 626 the rules were tuned on, every extension sample and every npm sample dated 2025 or later come from the DataDog dataset. The second sources: PyPI 83 of 95 on pypi_malregistry (87%, 79-93) against 37 of 48 (77%) on the original DataDog PyPI holdout; npm 159 of 200 on the ASE 2026 study (80%, 73-85), mostly 2021-2024 malware. Recall on extensions and on the newest npm malware has no independent check.
7. **Both sources hold malware somebody already caught.** Malware no one has identified is in neither. No number here speaks about it. A prospective run was started on 2026-11-20: `kalascan watch --log` records the score of every new npm and PyPI release it scans, and `eval/watch_outcome.py` compares them with OSV's malicious-package records and the registries after 30 days. It has no outcome yet. In its first day 574 of 21,257 new releases scored 50 or more (2.7%); a sample of them was read, nearly all benign, and ruleset 2026.11.11 was changed for what they showed (360 of the 574 still reach 50). The clean corpus had not shown it: the first version of this ruleset flagged no clean sample there and 41 of these releases that ruleset 2026.11.10 had not (evaluation notes, "Reading what the watch flagged"). A second reading made ruleset 2026.11.12 (270 of 618 releases flagged since still reach 50, 389 before); its first build lost 14 holdout samples that the clean corpus could not have shown either ("What was still flagged, read by class"). One day in, OSV names 12 of the 26,721 scanned releases malicious and 1 of the 12 had been flagged (8%, 1-35); that is an early reading, not the outcome. The watch was stopped on 2026-11-21; the logs are kept for the 30-day reading.
8. **The rules are public.** See the threat model: an author who tests against KalaScan is not in the corpus.
9. **Score v2 treats findings as independent** given the class, and they are not: a chain and the two findings it is made of fire together. The halving in the accumulation dampens this and does not remove it ([scoring.md](scoring.md), "Limits"). The weights are fitted on 626 malicious packages, 576 of them from one dataset, and 369 clean ones; a finding seen once or twice carries mostly its class prior. With no clean package flagged, v1 catches 480 of 683 and v2 479: v2 is a choice of operating point, not better detection.
10. **The holdout has been touched.** Ten sample names printed once, the total read after each change, flagged clean samples moved out. See "Dev and holdout".
11. **Recall is not gated.** See "The CI gate".
12. **Only the default scan is measured, and the sandbox adds nothing to it.** One run with `--sandbox` (2026-11-18, in a throwaway VM) gave the same counts as the static scan at every threshold, 0 of 822 clean included: the payloads it missed run on import or at app start, not at install ([eval/README.md](https://github.com/wahidhendrawan/KalaScan/blob/main/eval/README.md), "A fresh holdout and the sandbox"). `--deobfuscate`, `--emulate` and `--deep-triage` were run once each on the whole corpus (ruleset 2026.11.8, 2026-11-19): no malicious or clean count changed at 50 or 70. At 30, `--deobfuscate` flagged 33 clean packages instead of 13 and one more malicious sample; `--emulate` 16 clean instead of 13; `--deep-triage` changed nothing. They help reading a result; they do not change the verdict. `--ai` was measured once, on the AI agent skills, with one model (DeepSeek): 49 of 102 holdout skills instead of 19, 0 of 478 clean (evaluation notes, "AI agent skills by meaning"); on packages it has no measured rate.
13. **The ruleset version is set by hand** (`RULESET_VERSION` in `src/scanner.rs`), and chains, data flow and scoring live in the binary, not in the rule files. A result file is named after the ruleset version; it identifies a result only if the version was raised with the change. Since ruleset 2026.11.11 a result file also records the detection fingerprint of the binary that produced it, a hash of the rule files and detection modules made at build time (`build.rs`, printed by `kalascan rules`); it is recorded, not enforced. CI asks for a new version when a rule file or a detection module changes (CONTRIBUTING.md lists them), unless the pull request carries the `ruleset-unchanged` label; the scan pipeline in `src/lib.rs` is not on the list, and the label is a person's word.
14. **The record for `2026.11.1` was transcribed** from the published tables, not written by a run. Its `source` field says so and lists what is missing. `2026.11.2` is the first record written by a run.
15. **Registry history will not close the npm gap.** The registry checks (install script added, provenance dropped, manifest confusion, version gap) were replayed on the registry documents of 454 npm samples. The npm misses are packages malicious from their first version (108 of the holdout misses; 1 is a compromised version of a real package), where there is no history to compare with. On the missed holdout samples the checks fire once. On the 394 clean npm packages, provenance dropped with a new publisher happened in 5 legitimate ones, so it cannot be a verdict ([eval/README.md](https://github.com/wahidhendrawan/KalaScan/blob/main/eval/README.md), "IDE extensions, and two ideas measured and not built").
16. **Not every tuning round moves the holdout.** Ruleset 2026.11.4 added rules for four behaviours read in a batch of malicious IDE extensions (9 → 13 of 23 on that batch); the holdout stayed at 306 of 461 and its extensions at 32 of 48. Ruleset 2026.11.5, from a batch of 2026 npm packages, moved it from 444 to 465 of 657, all 21 on three campaigns that were in both.
17. **The dependency scan is measured by replay, not by the harness.** `Chain: Malicious New Dependency` needs the registry on the day of the scan. Its 12 holdout samples come from scanning the dependency's copy in the DataDog dataset; for 5 more missed holdout packages the young dependency is in no dataset. On 393 clean npm packages scanned live it flags none. Only npm, only direct dependencies, three scans at most, and only dependencies added in the scanned version unless the package has five versions or fewer.

## How to challenge a result

**A malicious package KalaScan scores low.** Open an [issue](https://github.com/wahidhendrawan/KalaScan/issues) with the package name, the exact version and where it was reported. Do not attach the sample; say where to get it. It goes into the corpus ([SECURITY.md](https://github.com/wahidhendrawan/KalaScan/blob/main/SECURITY.md), "Out of scope").

**A clean package KalaScan flags.** Open an issue with the name and exact version, `kalascan --version`, the first line of `kalascan rules`, the command, and the output of `--format json`. Its `score_breakdown` and `rule_matches` show which findings made the score.

**A number you cannot reproduce.** Open an issue with the commit you built, the `--summary` file of your run, and your Python and OS versions. Do not post the `--out` file or holdout sample names. If you have read a holdout sample, say so: it moves to `dev`.

**A flaw in the method.** A leak between dev and holdout, a biased draw, a wrong interval: an issue, with the file and line.

**A vulnerability in KalaScan itself.** Code execution or a file write outside the temp directory while scanning, an authentication bypass, a sandbox escape: report it privately through [GitHub security advisories](https://github.com/wahidhendrawan/KalaScan/security/advisories/new), not in an issue. A first reply comes within 7 days ([SECURITY.md](https://github.com/wahidhendrawan/KalaScan/blob/main/SECURITY.md)).
