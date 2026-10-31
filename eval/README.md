# Detection eval

`corpus.json` lists labelled samples:

- **malicious**: real packages from the [DataDog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) (npm, PyPI, VS Code extensions), picked with a fixed seed.
- **clean**: popular npm / PyPI packages and VS Code extensions, fetched from the public registries. Several were chosen because they look suspicious on the surface: install scripts that download binaries, local dev servers, SSH tooling, telemetry.

Each sample has a `split`. Rules were tuned while looking at `dev`. `holdout` was added afterwards and never used for tuning, so its numbers are the honest estimate.

```bash
cargo build --release
eval/fetch_malicious.sh ~/kalascan-corpus           # ~100 files, blobless clone
python3 eval/run_eval.py --dataset ~/kalascan-corpus --out before.json
# ...change rules...
python3 eval/run_eval.py --dataset ~/kalascan-corpus --compare before.json
```

The malicious samples are **live malware**. `run_eval.py` only scans them statically. It never passes `--sandbox`, and archives are extracted into a temp dir with the dataset password. Keep the corpus outside the repo.

CI (`.github/workflows/eval.yml`) runs only the clean half, as a false-positive gate: `--only clean --max-fpr 0`.

Results at threshold 50:

| split | malicious recall | clean false positives |
|---|---|---|
| dev | 48/60 (80%) | 0/62 |
| holdout | 26/40 (65%) | 0/165 |

By ecosystem: PyPI 84%, npm 83%, IDE extensions 60%. Before this work the dev split scored 1/60, and marketplace-id scans failed outright.

The 60 extensions installed on the maintainer's machine (`kalascan installed`) also all score below 30. Ten of them were false positives during development and are now in the clean `dev` split.

**Honest false-positive number.** When the clean set grew from 66 to 227 samples (161 new ones in `holdout`, untouched by tuning), the first run flagged **9 of the 176 holdout clean samples (5%)**: greedy regexes (`powershell .* -enc` across a minified line, `bcdedit` inside base64), `~/.ethereum/geth.ipc` read as a wallet, a bidi character used as a regex range, official `curl … | sh` installers (gh.io, antigravity.google, nvm) and firebase-tools chmodding one file while spawning another. Those rules were fixed and the 12 samples looked at moved to `dev`; the remaining 165 holdout clean samples score below 50. Expect the real rate on unseen packages to sit somewhere between the two numbers.

What still gets through: malicious themes with no code (impersonation only, unless the name uses invisible characters or a look-alike publisher), payloads inside native binaries, code that builds its C2 host at runtime (`(Object+'').split(' ')[0]+"."+…`), verbatim copies of extensions outside the top 2,000 (copies of popular ones are caught through their `repository` field), install scripts that patch another package in `node_modules`, and typo-squats with no code (the name match alone scores 5).
