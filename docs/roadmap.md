# Roadmap

What is planned, in order of priority, and where each item stands. An item is built when a measurement says it helps; several were measured and not built, and those stay on the list with the number that decided it. The evidence is in the [evaluation notes](https://github.com/wahidhendrawan/KalaScan/blob/main/eval/README.md).

Last updated 2026-11-21, ruleset 2026.11.13.

## P0: what everything else depends on

| # | Item | Status |
|---|---|---|
| 1 | **Prospective evaluation.** Score new npm and PyPI releases the day they are published (`kalascan watch --log`) and compare with takedowns later (`eval/watch_outcome.py`). | Logged from 2026-11-20 to 2026-11-21 (26,721 releases), then stopped; the outcome can be read from 2026-12-21. Early reading, one day in: OSV names 12 of them malicious, 1 was flagged (8%, 1-35). What the flagged releases are was read twice and drove the changes of rulesets 2026.11.11 and 2026.11.12: of 618 releases flagged since the start, 272 reach 50 with ruleset 2026.11.13. |
| 2 | **Encoded literals read as code**, and character-code arrays through a decoder of any name. | Done, ruleset 2026.11.11. Evasion suite 151 of 153 (147). |
| 3 | **Calls in the data-flow pass**: wrappers around a network call, functions that return a secret, compiled TypeScript, `.then()`. | Done, ruleset 2026.11.11. Small on the corpus: of 236 `dev` misses, 13 hold a secret read and a network call in one file. |

## P1: the measured weaknesses

| # | Item | Status |
|---|---|---|
| 4 | **Fingerprints of known libraries**, so that findings in an unmodified bundled dependency weigh less. | Measured, not built. Of 569 new releases flagged on 2026-11-20, 10 had their verdict findings only in bundled dependencies. The false positives were elsewhere (one setting read from the environment, official installers, install scripts next to unrelated code), and those were fixed instead. |
| 5 | **Dependencies as a tree.** | Measured, not built. A second hop reaches no more missed samples than the first, and exact-pinned siblings none that can be measured. The young-dependency check and `kalascan guard` (which scans the tree an install would add) stay as they are. |
| 6 | **Independent malware sources**, above all for IDE extensions and the newest npm malware. | Blocked on access. VSMEx (extensions) and MalwareBench (npm, PyPI) are both given out on request to their maintainers. |
| 16 | **Install-time chains only where the install hook reaches**: follow the hook's script through what it requires and imports. | Built and measured, not shipped (ruleset 2026.11.12). It would clear about 24 of the 270 new releases still flagged and loses 6 holdout and 4 `dev` samples, whose install-time chain is a hook and a network call that share a package and nothing else. It needs a finding that names what those samples do, or a score in which an unreached pair counts for less than a verdict (item 11). |
| 7 | **A rolling holdout**: at each release, a draw of samples newer than the rules, counted once. | Done, ruleset 2026.11.13. `sample_malicious.py --ref` draws from the DataDog sync bot's unmerged branch, `--added-after` from pypi_malregistry's newest batch. First draw: 38 of 131 before the tuning round on its `dev` half, 62 after. The next draw is due at the next release. |
| 17 | **The sdist beside the wheel**: scan a PyPI release's sdist as well, whose `setup.py` runs wherever the wheel does not fit. | Built and measured, not shipped (ruleset 2026.11.13). Flagged 3 of 3,821 clean samples (tests, Makefiles and READMEs the wheel leaves out) and 6 of 1,493 new releases, and can gain no malicious sample of the corpus, which holds archives, not releases. It needs a scan of the sdist's `setup.py` alone, measured on releases. |

## P2: foundations

| # | Item | Status |
|---|---|---|
| 8 | **Agent skills by meaning**: an instruction that asks for harm in plain words has no URL or command to match. | Done, ruleset 2026.11.13: `--ai` sends a skill's text to the model, and a confident malicious verdict counts as one. With DeepSeek: holdout skills 49 of 102 (19 without), 0 of 478 clean. Measured once, with one model; the default scan stays at 19. |
| 9 | **Rules and chains as data**, and a ruleset version that is not set by hand. | Partly. A result file now records the detection fingerprint of the binary that produced it (a hash of the rule files and detection modules, `build.rs`). Chains still live in the binary; moving them out is not started, and no result depends on it. |
| 10 | **A recall gate.** | Partly. `eval/evasion.py --stacked` measures every seed under two rewrites at once: 792 of 810 caught. A weekly run of the malicious corpus needs a throwaway runner that is not GitHub's; not set up. |
| 11 | **Score v2 calibrated** on the prospective data, so a score reads as a probability at a measured base rate. | Waits for item 1. |

## P3: after that

| # | Item | Status |
|---|---|---|
| 12 | **More ecosystems** (crates.io, RubyGems, Go, Maven). | Blocked on samples: none is claimed without malware to measure it on (item 6). |
| 13 | **Continuous monitoring.** | In pieces: the GitHub Action scans what a pull request adds to the lockfiles (`new_dependencies`) and, on a schedule, everything they pin (`all_dependencies`); `kalascan deps` keeps results per ruleset, so a new ruleset rescans. An organisation-wide app is not started. |
| 14 | **Reporting back** to registries and OSV. | Waits for item 1: `kalascan watch --osv-dir` writes the records, and none is sent before a finding is confirmed. |
| 15 | **Inventory and policy** (`kalascan installed`, `kalascan sbom`, policy as code). | The two commands exist. A policy file is not started; nothing measured asks for it yet. |

## Not planned

- **A black-box classifier as the verdict.** 576 of the 626 samples the rules were first tuned on come from one dataset; a model would learn its campaigns, and a verdict could no longer be traced to a line of code.
- **A rule per incident.** Two tuning rounds on single samples did not move the holdout.
- **An ecosystem without samples.**
