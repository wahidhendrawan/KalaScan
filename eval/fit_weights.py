#!/usr/bin/env python3
"""Fit the v2 score weights (rules/weights.toml) from eval results.

  python3 eval/run_eval.py --dataset ~/kalascan-corpus --out results.json
  python3 eval/fit_weights.py results.json > rules/weights.toml
  python3 eval/fit_weights.py results.json --cv        # pick --prior / --strength

Only the `dev` split is read: `holdout` stays unseen, so the numbers it
gives for the fitted weights are honest.

The model, per finding f (present or absent in a package, once):

  rate_mal(f) = (hits on malicious + k * pooled_mal(class)) / (malicious + k)
  rate_cln(f) = (hits on clean     + k * pooled_cln(class)) / (clean + k)
  LR(f)       = rate_mal / rate_cln
  weight(f)   = 100 * LR * prior / (LR * prior + 1 - prior)

`class` is the finding's severity ("chain" for correlated findings), and
`pooled_*` the mean hit rate of the findings of that class: a finding seen
on few packages is pulled towards what its class usually means (empirical
Bayes, strength k), and one never seen gets the class weight. `prior` is
the base rate the weights are stated for; it sets the scale, so that a
score of 50 means the same on the next corpus.

A package's score combines its weights, largest first, each later one
counting half as much as the one before (the accumulation THOR uses):

  score = 100 * (1 - prod_i (1 - weight_i / 100 / 2**i))
"""

import argparse
import collections
import json
import random
import re
import sys

CLASSES = ("chain", "critical", "high", "medium", "low")
VALUED = re.compile(r"^(Known Vulnerability|Malicious Package|Typo-squat Suspect|High-Entropy Suspicious Blob)\b.*")
# Hygiene, not malware evidence: its own dimension, outside this score.
SKIP = ("Known Vulnerability",)
HARD = 75  # a verdict needs one finding at least this strong (see score.rs)


def key(name):
    """Finding name without its value: `Typo-squat Suspect: x` -> `Typo-squat Suspect`."""
    return VALUED.sub(r"\1", name)


def klass(name, severity):
    return "chain" if name.startswith("Chain: ") else severity if severity in CLASSES else "low"


def features(sample):
    return {key(n): klass(n, sev) for n, sev in sample.get("rules", []) if key(n) not in SKIP}


def fit(samples, prior, strength):
    """-> ({finding: weight}, {class: weight}) from labelled samples."""
    mal = [features(s) for s in samples if s["label"] == "malicious"]
    cln = [features(s) for s in samples if s["label"] == "clean"]
    hits = collections.defaultdict(lambda: [0, 0])
    classes = {}
    for group, col in ((mal, 0), (cln, 1)):
        for feats in group:
            for name, cls in feats.items():
                hits[name][col] += 1
                classes[name] = cls
    pooled = {}
    for cls in CLASSES:
        members = [n for n in hits if classes[n] == cls]
        # Jeffreys +0.5 keeps a class nobody on the clean side hit off zero.
        m = (sum(hits[n][0] for n in members) + 0.5) / (max(len(members), 1) * len(mal) + 1)
        c = (sum(hits[n][1] for n in members) + 0.5) / (max(len(members), 1) * len(cln) + 1)
        pooled[cls] = (m, c)

    def weight(m_hits, c_hits, cls):
        pm, pc = pooled[cls]
        lr = ((m_hits + strength * pm) / (len(mal) + strength)) / ((c_hits + strength * pc) / (len(cln) + strength))
        return 100 * lr * prior / (lr * prior + 1 - prior)

    # Whole numbers, as rules/weights.toml stores them and score.rs reads them.
    weights = {n: round(weight(m, c, classes[n])) for n, (m, c) in hits.items()}
    defaults = {cls: round(weight(0, 0, cls)) for cls in CLASSES}
    return weights, defaults, hits, classes


def score(feats, weights, defaults):
    subs = sorted((weights.get(n, defaults[cls]) for n, cls in feats.items()), reverse=True)
    rest = 1.0
    for i, s in enumerate(subs):
        rest *= 1 - s / 100 / 2**i
    total = 100 * (1 - rest)
    # No verdict from leads alone: without one strong finding, stay below "danger".
    capped = total if subs and subs[0] >= HARD else min(total, 69.0)
    return int(capped + 0.5)


def rates(samples, weights, defaults, threshold):
    mal = [s for s in samples if s["label"] == "malicious"]
    cln = [s for s in samples if s["label"] == "clean"]
    caught = sum(score(features(s), weights, defaults) >= threshold for s in mal)
    flagged = sum(score(features(s), weights, defaults) >= threshold for s in cln)
    return caught, len(mal), flagged, len(cln)


def cross_validate(samples, prior, strength, threshold, folds=5, seed=20261117):
    """Fit on four fifths of dev, score the fifth it has not seen; sum over folds."""
    order = list(samples)
    random.Random(seed).shuffle(order)
    total = [0, 0, 0, 0]
    for f in range(folds):
        held = order[f::folds]
        train = [s for i, s in enumerate(order) if i % folds != f]
        weights, defaults, _, _ = fit(train, prior, strength)
        total = [a + b for a, b in zip(total, rates(held, weights, defaults, threshold))]
    return total


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results", nargs="+", help="--out files of eval/run_eval.py")
    ap.add_argument("--prior", type=float, default=0.02, help="base rate the weights are stated for")
    ap.add_argument("--strength", type=float, default=50, help="pseudo-samples pulling a finding towards its class")
    ap.add_argument("--threshold", type=int, default=50)
    ap.add_argument("--cv", action="store_true", help="5-fold cross-validation on dev over a grid, instead of writing weights")
    args = ap.parse_args()

    samples = [s for path in args.results for s in json.load(open(path)) if "rules" in s]
    dev = [s for s in samples if s.get("split", "dev") == "dev"]
    n_mal = sum(s["label"] == "malicious" for s in dev)
    n_cln = len(dev) - n_mal

    if args.cv:
        print(f"dev: {n_mal} malicious, {n_cln} clean; threshold {args.threshold}; held-out folds summed")
        print(f"{'prior':>6} {'strength':>8}  {'recall':>12}  {'clean flagged':>13}")
        for prior in (0.02, 0.05, 0.1, 0.2):
            for strength in (5, 20, 50):
                caught, n, flagged, c = cross_validate(dev, prior, strength, args.threshold)
                print(f"{prior:>6} {strength:>8}  {caught:>4}/{n} {100 * caught / n:3.0f}%  {flagged:>6}/{c}")
        return

    weights, defaults, hits, classes = fit(dev, args.prior, args.strength)
    caught, n, flagged, c = rates(dev, weights, defaults, args.threshold)
    print("# Score weights for `--score-model v2`. Generated by eval/fit_weights.py; do not edit by hand.")
    print(f"# Fitted on the dev split: {n_mal} malicious, {n_cln} clean packages. prior {args.prior}, strength {args.strength}.")
    print(f"# On that split (seen while fitting): {caught}/{n} malicious and {flagged}/{c} clean at or above {args.threshold}.")
    print("# weight = P(malicious | finding) in percent at that prior; `m` / `c` = packages it fired on.\n")
    print("[default]")
    for cls in CLASSES:
        print(f"{cls} = {defaults[cls]}")
    for name in sorted(weights, key=lambda n: (-weights[n], n)):
        m, c = hits[name]
        print(f"\n[[finding]]\nname = {json.dumps(name)}\nweight = {weights[name]}\nm = {m}\nc = {c}")


if __name__ == "__main__":
    main()
