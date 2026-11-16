# Detection eval

`corpus.json` lists labelled samples:

- **malicious**: real packages from the [DataDog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) (npm, PyPI, VS Code extensions), picked with a fixed seed.
- **clean**: popular npm / PyPI packages and VS Code extensions, fetched from the public registries. Several were chosen because they look suspicious on the surface: install scripts that download binaries, local dev servers, SSH tooling, telemetry. Entries with `"set": "random-2026-11"` were not picked but drawn at random from all of npm and PyPI (`eval/sample_clean.py`, see below).

Each sample has a `split`. Rules were tuned while looking at `dev`. `holdout` was added afterwards and never used for tuning, so its numbers are the honest estimate.

```bash
cargo build --release
eval/fetch_malicious.sh ~/kalascan-corpus           # ~220 files (about 700 MB), blobless clone
python3 eval/run_eval.py --dataset ~/kalascan-corpus --out before.json
# ...change rules...
python3 eval/run_eval.py --dataset ~/kalascan-corpus --compare before.json
```

The malicious samples are **live malware**. `run_eval.py` only scans them statically. It never passes `--sandbox`, and archives are extracted into a temp dir with the dataset password. Keep the corpus outside the repo.

CI (`.github/workflows/eval.yml`) runs only the clean half, as a false-positive gate: `--only clean --max-fpr 0`, on every pull request that touches `src/`, `rules/`, `eval/` or `Cargo.lock`.

Results at threshold 50 (KalaScan 1.14, measured 2026-11-16):

| split | malicious recall | clean false positives |
|---|---|---|
| dev | 59/73 (81%) | 0/63 |
| holdout | 82/147 (56%) | 0/463 |

**The holdout number is the one to quote.** Until November 2026 the holdout split held 27 malicious samples and scored 26/27 (96%). 120 fresh samples were then added with a fixed seed (40 npm and 40 PyPI packages first published to the dataset in 2026, 40 extensions, one version per package name), and none of them has been read. On those 120 alone KalaScan catches 56 (47%): the earlier figure was a small-sample artefact, and rules tuned on 2022-2025 samples generalise worse than it suggested.

Holdout recall by ecosystem: IDE extensions 32/48 (67%), npm 28/51 (55%), PyPI 22/48 (46%). The highest score among the picked clean packages is 23, among the random ones 38 (`tavallio-agent`, below). The 161 picked clean npm/PyPI targets also go through the registry checks (manifest confusion, install script added, provenance dropped, lapsed maintainer email domain) without a finding. Before this work the dev split scored 1/60, and marketplace-id scans failed outright.

### Compared with GuardDog

`python3 eval/run_eval.py --scanner guarddog --dataset ~/kalascan-corpus` runs [GuardDog](https://github.com/DataDog/guarddog) (3.2.0, Docker image) on the same samples. GuardDog reports rule hits rather than a score, so two readings are given: a `threat-*` or metadata rule fired, and any rule at all fired (`capability-*` rules describe what code can do, not that it is malicious).

| | malicious, holdout | malicious, all | clean flagged |
|---|---|---|---|
| KalaScan (risk >= 50) | 82/147 (56%) | 141/220 (64%) | 0/227 (0%) |
| GuardDog, threat or metadata rule | 107/147 (73%) | 155/220 (70%) | 128/223 (57%) |
| GuardDog, any rule | 123/147 (84%) | 187/220 (85%) | 213/223 (96%) |

The two tools sit at different points: GuardDog finds more of the malware, most clearly on PyPI (41 of 48 holdout samples against 22), and flags more than half of the popular clean packages on the way; KalaScan flags none of the clean ones and misses more malware. On the holdout samples 66 are caught by both, 16 only by KalaScan, 41 only by GuardDog and 24 by neither. Read the comparison with two caveats: the malicious samples come from DataDog's own dataset, which GuardDog's rules were developed against, and four large clean PyPI packages timed out under GuardDog (300 s) and are left out of its column.

The 60 extensions installed on the maintainer's machine (`kalascan installed`) also all score below 30. Ten of them were false positives during development and are now in the clean `dev` split.

**Honest false-positive number.** When the clean set grew from 66 to 227 samples (161 new ones in `holdout`, untouched by tuning), the first run flagged **9 of the 176 holdout clean samples (5%)**: greedy regexes (`powershell .* -enc` across a minified line, `bcdedit` inside base64), `~/.ethereum/geth.ipc` read as a wallet, a bidi character used as a regex range, official `curl … | sh` installers (gh.io, antigravity.google, nvm) and firebase-tools chmodding one file while spawning another. Those rules were fixed and the 12 samples looked at moved to `dev`; the remaining 165 holdout clean samples score below 50. Expect the real rate on unseen packages to sit somewhere between the two numbers.

**Packages nobody picked.** Popular packages are a soft test: they are well kept, and the list was partly chosen by hand. So 300 packages were drawn at random from the whole registries (`python3 eval/sample_clean.py`, seed 20261116): 150 by random rank in the [ecosyste.ms](https://packages.ecosyste.ms) npm index, 150 by random name from the PyPI simple index, each pinned to its newest version published before 2026-05-16. Registries take malicious versions down within days, so one that has survived six months is very likely benign. Rejected draws were npm 109 too new, 8 security placeholders, 7 gone, 4 over 30 MB, 2 index errors; PyPI 55 too new, 14 gone. Two scored 50 or more:

- `democratic_trout_z3n`: its publish script generates a random package name and runs `npm publish` in a loop, and this package is one of those names. `Chain: Registry Spam Publisher` exists for exactly this; it is left out of the corpus, not counted as clean.
- `tavallio-agent`, a legitimate connector for an AI agent: a device name from `os.hostname()` plus a Telegram bot integration made a `Chain: Reconnaissance Beacon`. The Telegram API host no longer counts as a beacon target, since agents and bots call it with the user's own token; a bot token written into the code still does. Malicious recall did not move (141/220, no sample's score changed), and the package now scores 38. It is in `dev`, the other 298 in `holdout`.

That is 1 false positive in 299 random packages (0.3%), PyPI 0 of 150. Nothing else reached 30.

What still gets through in the `dev` split (15 samples; the holdout misses are deliberately not read): forks of legitimate extensions republished with a changed API endpoint or compile server, so the user's code goes to a personal host (chatgpt-china, cppplayground, cortex-debug fork: 7 samples, nothing in the code is malicious on its own; the two that kept the original's `repository` are caught since the popular-extension list grew to 10,000); themes and hello-world extensions whose only offence is the listing (5); typo-squats with no code; an install script that patches a sibling package in `node_modules`; code that builds its C2 host at runtime.
