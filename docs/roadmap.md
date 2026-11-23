# Roadmap

What was built, and what was measured and not built, with the number that decided it. Nothing else is planned: the open items were removed on 2026-11-22. The evidence is in the [evaluation notes](https://github.com/wahidhendrawan/KalaScan/blob/main/eval/README.md).

Last updated 2026-11-23, ruleset 2026.11.16.

## Done

| # | Item | Status |
|---|---|---|
| 2 | **Encoded literals read as code**, and character-code arrays through a decoder of any name. | Done, ruleset 2026.11.11. Evasion suite 151 of 153 (147). |
| 3 | **Calls in the data-flow pass**: wrappers around a network call, functions that return a secret, compiled TypeScript, `.then()`. | Done, ruleset 2026.11.11. Small on the corpus: of 236 `dev` misses, 13 hold a secret read and a network call in one file. |
| 7 | **A rolling holdout**: a draw of samples newer than the rules, counted once. | Done, ruleset 2026.11.13. `sample_malicious.py --ref` draws from the DataDog sync bot's unmerged branch, `--added-after` from pypi_malregistry's newest batch. First draw: 38 of 131 before the tuning round on its `dev` half, 62 after. |
| 8 | **Agent skills by meaning**: an instruction that asks for harm in plain words has no URL or command to match. | Done, ruleset 2026.11.13: `--ai` sends a skill's text to the model, and a confident malicious verdict counts as one. With DeepSeek: holdout skills 49 of 102 (19 without), 0 of 478 clean. Measured once, with one model; the default scan stays at 19. |
| 17 | **The sdist beside the wheel**: scan a PyPI release's sdist as well, whose `setup.py` runs wherever the wheel does not fit. | Done, ruleset 2026.11.14, as the sdist's `setup.py` alone, scanned as a unit of its own (`.sdist/setup.py`). Same counts as ruleset 2026.11.13: 0 of 3,823 clean, 0 of 1,496 new releases the watch never flagged; 68 clean PyPI samples score higher, none above 20. The whole sdist had flagged 3 clean samples and 6 new releases (ruleset 2026.11.13). What it gains is not measured: the corpus holds archives, not releases. |

## Measured, not built

| # | Item | Status |
|---|---|---|
| 4 | **Fingerprints of known libraries**, so that findings in an unmodified bundled dependency weigh less. | Of 569 new releases flagged on 2026-11-20, 10 had their verdict findings only in bundled dependencies. The false positives were elsewhere (one setting read from the environment, official installers, install scripts next to unrelated code), and those were fixed instead. |
| 5 | **Dependencies as a tree.** | A second hop reaches no more missed samples than the first, and exact-pinned siblings none that can be measured. The young-dependency check and `kalascan guard` (which scans the tree an install would add) stay as they are. |
| 16 | **Install-time chains only where the install hook reaches**: follow the hook's script through what it requires and imports. | Built and measured twice. Ruleset 2026.11.12: it would clear about 24 of the 270 new releases still flagged and loses 6 holdout and 4 `dev` samples, whose install-time chain is a hook and a network call that share a package and nothing else. Ruleset 2026.11.13: 4 holdout and 6 `dev` samples lost, 23 of the 272 live releases cleared, every one of them by `Chain: Install-time Exfiltration`, so no narrowing by chain separates them. |

## Not planned

- **A black-box classifier as the verdict.** 576 of the 626 samples the rules were first tuned on come from one dataset; a model would learn its campaigns, and a verdict could no longer be traced to a line of code.
- **A rule per incident.** Two tuning rounds on single samples did not move the holdout.
- **An ecosystem without samples.**
