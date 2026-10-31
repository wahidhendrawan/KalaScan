#!/usr/bin/env python3
"""Measure KalaScan detection quality on a labelled corpus.

Scans every sample in eval/corpus.json with the kalascan CLI (static only:
no --sandbox, nothing is executed), then reports recall / false-positive rate
at several risk thresholds, per ecosystem, and per-sample score changes
against a previous run.

  eval/fetch_malicious.sh ~/kalascan-corpus
  cargo build --release
  python3 eval/run_eval.py --dataset ~/kalascan-corpus --out eval-results.json
  python3 eval/run_eval.py ... --compare eval-results.json   # after a change

Gate a change with --min-recall / --max-fpr (exit 1 when violated).
"""

import argparse
import concurrent.futures as cf
import json
import os
import subprocess
import sys
import tempfile
import time
import zipfile

THRESHOLDS = (30, 50, 70)
MANIFESTS = ("package.json", "setup.py", "pyproject.toml", "PKG-INFO")


def package_root(path):
    """Shallowest dir holding a manifest, so dependency checks see it."""
    best = None
    for root, _dirs, files in os.walk(path):
        if any(m in files for m in MANIFESTS):
            depth = root.count(os.sep)
            if best is None or depth < best[0]:
                best = (depth, root)
    return best[1] if best else path


def ecosystem(sample):
    t = sample["target"]
    if sample["source"] == "dataset":
        return t.split("/")[1]  # samples/<eco>/...
    if t.startswith("npm:"):
        return "npm"
    if t.startswith("pypi:"):
        return "pypi"
    return "ide_extensions"


def scan(sample, args):
    started = time.time()
    with tempfile.TemporaryDirectory(prefix="kalascan-eval-") as tmp:
        target = sample["target"]
        if sample["source"] == "dataset":
            path = os.path.join(args.dataset, target)
            if not os.path.exists(path):
                return {"error": "missing; run eval/fetch_malicious.sh"}
            if path.endswith(".zip"):
                # Dataset archives use ZipCrypto with the published password.
                # zipfile drops `..` and absolute member names on extract.
                with zipfile.ZipFile(path) as z:
                    z.extractall(os.path.join(tmp, "x"), pwd=b"infected")
                target = package_root(os.path.join(tmp, "x"))
            else:
                target = path
        out = os.path.join(tmp, "result.json")
        # --untrusted: extracted samples are someone else's code, not a checkout.
        cmd = [args.kalascan, "scan", target, "--untrusted", "--format", "json", "--output", out, *args.flag]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout)
        except subprocess.TimeoutExpired:
            return {"error": "timeout"}
        if not os.path.exists(out):
            return {"error": (proc.stderr.strip().splitlines() or ["no output"])[-1][:200]}
        result = json.load(open(out))
    strong = sorted(
        {m["matched_pattern"] for m in result["rule_matches"] if m["severity"] in ("critical", "high")}
    )
    return {
        "risk": result["risk_score"],
        "seconds": round(time.time() - started, 1),
        "strong": strong[:12],
    }


def rate(num, den):
    return f"{num}/{den} ({100 * num / den:.0f}%)" if den else "-"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default=os.path.join(os.path.dirname(__file__), "corpus.json"))
    ap.add_argument("--dataset", help="checkout of the DataDog dataset (for malicious samples)")
    ap.add_argument("--kalascan", default="target/release/kalascan")
    ap.add_argument("--only", choices=("clean", "malicious"))
    ap.add_argument("--flag", action="append", default=[], help="extra scan flag, repeatable (e.g. --flag=--deobfuscate)")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--out", help="write per-sample results JSON")
    ap.add_argument("--compare", help="previous --out file; print score changes")
    ap.add_argument("--threshold", type=int, default=50, help="threshold the gates apply to")
    ap.add_argument("--min-recall", type=float, help="fail if malicious recall is below this (0-1)")
    ap.add_argument("--max-fpr", type=float, help="fail if clean false-positive rate is above this (0-1)")
    ap.add_argument("--allow-errors", action="store_true", help="don't fail on download/scan errors (flaky registries in CI)")
    args = ap.parse_args()

    samples = [s for s in json.load(open(args.corpus))["samples"] if not args.only or s["label"] == args.only]
    if any(s["source"] == "dataset" for s in samples) and not args.dataset:
        ap.error("--dataset is required for malicious samples (or use --only clean)")

    with cf.ThreadPoolExecutor(args.jobs) as pool:
        futures = {pool.submit(scan, s, args): s for s in samples}
        for i, fut in enumerate(cf.as_completed(futures), 1):
            s = futures[fut]
            s.update(fut.result())
            print(f"[{i}/{len(samples)}] {s['label']:9} {str(s.get('risk', 'ERR')):>3} {s['target']}", file=sys.stderr)

    samples.sort(key=lambda s: (s["label"], s["target"]))
    done = [s for s in samples if "risk" in s]
    errors = [s for s in samples if "error" in s]

    print("\n== detection by threshold (risk >= T counts as flagged)")
    print(f"{'T':>4}  {'malicious recall':<22}{'clean false positives':<22}")
    for t in THRESHOLDS:
        mal = [s for s in done if s["label"] == "malicious"]
        cln = [s for s in done if s["label"] == "clean"]
        print(f"{t:>4}  {rate(sum(s['risk'] >= t for s in mal), len(mal)):<22}"
              f"{rate(sum(s['risk'] >= t for s in cln), len(cln)):<22}")

    splits = sorted({s.get("split", "dev") for s in done})
    if len(splits) > 1:
        print(f"\n== per split at T={args.threshold} (rules are tuned on 'dev'; 'holdout' is the honest number)")
        for split in splits:
            mal = [s for s in done if s["label"] == "malicious" and s.get("split", "dev") == split]
            cln = [s for s in done if s["label"] == "clean" and s.get("split", "dev") == split]
            print(f"  {split:8} recall {rate(sum(s['risk'] >= args.threshold for s in mal), len(mal)):<16}"
                  f"false positives {rate(sum(s['risk'] >= args.threshold for s in cln), len(cln))}")

    print(f"\n== per ecosystem at T={args.threshold}")
    for eco in sorted({ecosystem(s) for s in done}):
        for label in ("malicious", "clean"):
            group = [s for s in done if s["label"] == label and ecosystem(s) == eco]
            if group:
                hit = sum(s["risk"] >= args.threshold for s in group)
                print(f"  {eco:15} {label:9} flagged {rate(hit, len(group))}")

    print(f"\n== misses at T={args.threshold}")
    for s in done:
        missed = (s["label"] == "malicious") != (s["risk"] >= args.threshold)
        if missed:
            kind = "FN" if s["label"] == "malicious" else "FP"
            print(f"  {kind} {s['risk']:>3} {s['target']}  {', '.join(s['strong'][:4])}")
    for s in errors:
        print(f"  ERR {s['target']}: {s['error']}")

    if args.compare and os.path.exists(args.compare):
        before = {s["target"]: s.get("risk") for s in json.load(open(args.compare))}
        print("\n== score changes vs", args.compare)
        for s in done:
            old = before.get(s["target"])
            if old is not None and old != s["risk"]:
                print(f"  {s['label']:9} {old:>3} -> {s['risk']:>3}  {s['target']}")

    if args.out:
        json.dump(samples, open(args.out, "w"), indent=1)

    mal = [s for s in done if s["label"] == "malicious"]
    cln = [s for s in done if s["label"] == "clean"]
    recall = sum(s["risk"] >= args.threshold for s in mal) / len(mal) if mal else 1.0
    fpr = sum(s["risk"] >= args.threshold for s in cln) / len(cln) if cln else 0.0
    failed = (args.min_recall is not None and recall < args.min_recall) or (
        args.max_fpr is not None and fpr > args.max_fpr
    )
    sys.exit(1 if failed or (errors and not args.allow_errors) else 0)


if __name__ == "__main__":
    main()
