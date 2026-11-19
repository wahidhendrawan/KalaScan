# Risk score

Every scan ends in one number from 0 to 100. `--fail-on-risk N` exits 1 at `score >= N`; reports label 0-29 **safe**, 30-69 **warning** and 70-100 **danger**. The JSON result carries `score_breakdown`: the model used and the parts the score is the sum of, so a reader can see where a number came from. Text and Markdown reports print the same parts on one line.

There are two models. **v1 is the default.** v2 is opt-in (`kalascan scan --score-model v2`, `score_model = "v2"` in `kalascan.toml`, `"score_model": "v2"` in an API request) and is described here with the evidence for and against it.

## v1: tiers set by hand

`src/score.rs`, `v1`:

1. **Dedup.** Each `(file, finding name)` pair counts once; a regex firing 40 times in a minified bundle is one finding. History hits (`<commit>:<path>`) count as the file they belong to.
2. **Buckets.** `Known Vulnerability:` findings go to a CVE counter. A behaviour chain (`Chain: …`), an invisible-character or look-alike publisher listing, a repackaged popular extension, an AI-vendor repository spoof, npm manifest confusion, a URLhaus hit, text hidden in Unicode tags, code decoded straight into `exec`, an import-obfuscated loader or a remote URL dependency counts as **two** criticals: these have no benign reading. Everything else is counted by its severity.
3. **Critical findings**: none 0, one 20, two or more `min(n x 35, 70)`. One critical alone is a lead, not a verdict; a chain or a second critical makes it one.
4. **High findings** `min(n x 5, 15)`, **medium findings** `min(n, 5)`.
5. **Known vulnerabilities** `min(n, 5)`: hygiene, not malware evidence.
6. **Deep analysis** `min(triage + deobfuscation + emulation + sandbox, 20)`: the deep passes share one budget because they overlap.
7. **AI verdict** `min(ai.risk_score / 2, 25)` only when the model says malicious; a benign verdict adds 0.
8. **Total** = the parts added up, capped at 100.

The result is nearly two-valued: a package has a chain or two criticals and scores 70 or more, or it does not and stays under 30. On the holdout 480 of 683 malicious samples score 70 or more, two score 30-49, none 50-69.

## v2: weights fitted on the corpus

`src/score.rs`, `v2`; weights in `rules/weights.toml`, written by `eval/fit_weights.py`.

Every finding present in the package (once, however many files show it) has a **weight**: the probability, in percent, that a package showing it is malicious.

```
rate_mal(f) = (malicious packages with f + k * pooled_mal(class)) / (malicious packages + k)
rate_cln(f) = (clean packages with f     + k * pooled_cln(class)) / (clean packages + k)
LR(f)       = rate_mal(f) / rate_cln(f)
weight(f)   = 100 * LR * prior / (LR * prior + 1 - prior)
```

- `class` is the finding's severity, or "chain" for the findings v1 counts twice. `pooled_*` is the mean rate of the findings of that class. A finding seen on few packages is pulled towards what its class usually means (empirical Bayes with `k` pseudo-samples), and a finding the corpus never showed gets the class weight. This is where the analyst's judgement enters: as a prior the data can overrule.
- `prior` is the base rate the weights are stated for. It sets the scale.
- `k = 50` and `prior = 0.02` were picked by 5-fold cross-validation on `dev` (below).

Weights combine largest first, each later one counting half as much as the one before, the accumulation [THOR](https://thor-manual.nextron-systems.com/en/latest/usage/other-topics.html) uses for its sub-scores:

```
score = 100 * (1 - prod_i (1 - weight_i / 100 / 2^i))
```

so the strongest evidence sets the score and the rest corroborates, with less to add each time. Two more rules:

- **A verdict needs one strong finding.** Without a weight of 75 or more the score stops at 69, below "danger", whatever the number of weaker findings (THOR requires the same of an alert).
- **Known vulnerabilities are counted apart** (`score_breakdown.known_vulnerabilities`) and add nothing: the score is about malice.

The opt-in deep passes and the AI verdict were not part of the corpus scans (only the metadata triage every scan runs was), so there is nothing to fit them on. They enter as two more weights, their v1 budgets doubled (at most 40 and 50), and neither reaches "danger" by itself.

### How the weights were fitted

`python3 eval/fit_weights.py results.json > rules/weights.toml`, on the `dev` split only: 626 malicious and 369 clean packages (66 picked, 300 drawn at random, see [eval/README.md](../eval/README.md)). The `holdout` split was not read.

Cross-validation on `dev` (fit on four fifths, score the fifth; held-out folds summed; `--cv`), flagged at 50 or more:

| prior | k | malicious caught | clean flagged |
|---|---|---|---|
| 0.02 | 5 | 487/626 | 10/369 |
| 0.02 | 20 | 487/626 | 8/369 |
| **0.02** | **50** | **478/626** | **3/369** |
| 0.05 | 20 | 493/626 | 12/369 |
| 0.05 | 50 | 487/626 | 8/369 |
| 0.1 | 20 | 519/626 | 44/369 |
| 0.1 | 50 | 514/626 | 38/369 |

v1 on the same split: 480/626 and 0/369, with rules that were tuned while looking at it. The table was recomputed for ruleset 2026.11.5. With rulesets 2026.11.2 to 2026.11.4 (253, 403 and 426 malicious) it picked the same parameters, and they were left as they were. The clean packages v2 flags in cross-validation each show one strong finding the other four fifths had not seen on a clean package (a download cradle in an agent's installer, bidi characters in a UI example, a base64 blob evaluated as licence protection).

Two variants were tried on `dev` (with ruleset 2026.11.1: 173 malicious, 365 clean) and dropped:

- **Confidence bounds instead of shrinkage** (lower Wilson bound for the malicious rate, upper for the clean rate). It ranks worse at every false-positive budget (58-73 of 173 caught at zero clean flagged, against 125): a rare chain loses the weight its class should give it.
- **A cap on any single finding that is not a chain.** It removes the two cross-validation false positives at a cap of 35 and loses 11 malicious samples that two unchained critical findings catch.

### What the holdout says

Ruleset 2026.11.7, 683 malicious and 453 clean holdout packages, 95% Wilson interval in brackets. The v1 column is the binary's ([`eval/results/2026.11.7.json`](../eval/results/2026.11.7.json)). The v2 column is what the fitter computes from the findings that run recorded, with the weights refitted on `dev` (626 malicious, 369 clean); the samples were deleted after the run, so the binary was not run again with `--score-model v2`. In the first evaluation (ruleset 2026.11.1) the two agreed on 1,295 of 1,297 packages, the other two carrying a binary-triage part the fitter does not see.

| threshold | v1 malicious | v1 clean | v2 malicious | v2 clean |
|---|---|---|---|---|
| 30 | 482/683 (71%, 67-74) | 0/453 (0%, 0-1) | 494/683 (72%, 69-76) | 4/453 (0.9%, 0.3-2.2) |
| 50 | 480/683 (70%, 67-74) | 0/453 (0%, 0-1) | 481/683 (70%, 67-74) | 0/453 (0%, 0-1) |
| 70 | 480/683 (70%, 67-74) | 0/453 (0%, 0-1) | 475/683 (70%, 66-73) | 0/453 (0%, 0-1) |

Malicious samples caught at the best threshold that flags no more than a given number of clean packages:

| clean flagged at most | 0 | 1 | 4 | 9 |
|---|---|---|---|---|
| v1 | 482 | 482 | 482 | 482 |
| v2 | 481 | 481 | 503 | 523 |

**v2 does not beat v1 where KalaScan operates.** With no clean package flagged the two are level (482 and 481 of 683). What v2 adds is a range v1 does not have: v1's scores leave almost nothing between 30 and 70 to trade with, while v2 catches 21 more samples for 4 clean packages flagged in 453, and 41 more for 9. That is why v2 ships behind a flag and v1 stays the default: the gain is a choice of operating point, not better detection, and the ceiling is set by what the rules see. 189 of the 683 malicious holdout samples score under 30 in v2, 201 in v1.

This is the seventh evaluation of v2 on the holdout. The first six (rulesets 2026.11.1 and 2026.11.2, 193 and 201 of 302 at threshold 50; rulesets 2026.11.3 and 2026.11.4, 305 of 461; ruleset 2026.11.5, 466 of 657; ruleset 2026.11.6, 479 of 683) gave the same picture. The model and its two parameters were not changed between them; the weights were refitted because the rules changed.

### What a score means

Holdout packages by score band. The corpus is half malicious; a registry is not, so the shares say how well a band separates the two classes, not how likely a package from that band is malicious in the wild.

| band | v1 malicious | v1 clean | v2 malicious | v2 clean |
|---|---|---|---|---|
| 0-9 | 147 | 331 | 125 | 395 |
| 10-29 | 54 | 122 | 64 | 54 |
| 30-49 | 2 | 0 | 13 | 4 |
| 50-69 | 0 | 0 | 6 | 0 |
| 70-100 | 480 | 0 | 475 | 0 |

## Limits

- Weights are fitted on 626 malicious packages from two datasets (576 from one) and 369 clean ones. A finding seen once or twice has a weight that is mostly its class prior.
- Findings are treated as independent given the class, which they are not (a chain and the two findings it is made of fire together). The halving in the accumulation dampens this; it does not remove it.
- The clean side decides the false-positive rate, and popular or six-month-old packages are an easier clean set than everything a registry holds. [eval/README.md](../eval/README.md) has the measured rate on random packages.
- Refit after rule changes: `python3 eval/run_eval.py … --out results.json`, then `eval/fit_weights.py`. A weight refers to the finding as it fired when the corpus was scanned.
