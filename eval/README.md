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
| dev | 39/60 (65%) | 0/45 |
| holdout | 23/40 (58%) | 0/16 |

By ecosystem: PyPI 76%, npm 66%, IDE extensions 50%. Before this work the dev split scored 1/60, and marketplace-id scans failed outright.

The 60 extensions installed on the maintainer's machine (`kalascan installed`) also all score below 30. Ten of them were false positives during development and are now in the clean `dev` split.

What still gets through: malicious themes with no code (impersonation only, unless the name uses invisible characters or a look-alike publisher), payloads inside `.wasm` / native binaries, and code that builds its C2 host at runtime (`(Object+'').split(' ')[0]+"."+…`).
