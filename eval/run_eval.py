#!/usr/bin/env python3
"""Measure KalaScan detection quality on a labelled corpus.

Scans every sample in eval/corpus.json with the kalascan CLI (static only:
nothing is executed unless --flag=--sandbox, which needs --disposable-vm),
then reports recall / false-positive rate
at several risk thresholds, per ecosystem, and per-sample score changes
against a previous run.

  eval/fetch_malicious.sh ~/kalascan-corpus
  cargo build --release
  python3 eval/run_eval.py --dataset ~/kalascan-corpus --out eval-results.json
  python3 eval/run_eval.py ... --compare eval-results.json   # after a change

Gate a change with --min-recall / --max-fpr (exit 1 when violated).
Rates are printed with their 95% Wilson interval. --rule-stats lists every
finding with how often it fires on malicious and on clean samples.
--summary FILE writes the aggregate counts of the run, without sample names:
the per-release record kept in eval/results/.

--scanner guarddog runs DataDog's GuardDog (Docker image) on the same
samples, for a like-for-like comparison:

  python3 eval/run_eval.py --scanner guarddog --dataset ~/kalascan-corpus
"""

import argparse
import collections
import concurrent.futures as cf
import json
import math
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

THRESHOLDS = (30, 50, 70)
# Sources kept on disk: corpus `source` -> (argument holding the checkout, how to fetch it).
LOCAL = {
    "dataset": ("dataset", "eval/fetch_malicious.sh"),
    "malregistry": ("malregistry", "eval/fetch_malicious.sh"),
    "npmstudy": ("npmstudy", "eval/fetch_npmstudy.py"),
    "skills": ("skills", "eval/fetch_skills.py"),
}
MANIFESTS = ("package.json", "setup.py", "pyproject.toml", "PKG-INFO")
# --allow-errors forgives a registry that is down for a few samples, not a
# scanner that crashed on all of them: past this share of the samples the
# gate has measured nothing and fails.
MAX_ERROR_RATE = 0.05


def package_root(path):
    """Shallowest dir holding a manifest, so dependency checks see it. Two at
    that depth (a package next to the `sources/` of the one it copies) means
    their common parent: picking one left the result to directory order."""
    found = []
    for root, dirs, files in os.walk(path):
        # A wheel's manifest is its `<name>.dist-info` directory.
        if any(m in files for m in MANIFESTS) or any(d.endswith(".dist-info") for d in dirs):
            found.append((root.count(os.sep), root))
    if not found:
        return path
    top = min(d for d, _ in found)
    return os.path.commonpath([r for d, r in found if d == top])


def ecosystem(sample):
    t = sample["target"]
    if sample["source"] == "dataset":
        return t.split("/")[1]  # samples/<eco>/...
    if sample["source"] == "malregistry":
        return "pypi"
    if sample["source"] == "npmstudy":
        return "npm"
    if sample["source"] == "skills":
        return "ai-skills"
    if t.startswith("npm:"):
        return "npm"
    if t.startswith("pypi:"):
        return "pypi"
    return "ide_extensions"


def guarddog(sample, target, args):
    """GuardDog on one sample. It reports rule hits, not a score, so two
    readings are kept apart: risk 100 when a `threat-*` or metadata rule
    fires, risk 40 when only `capability-*` rules do (what the code can do,
    not that it is malicious). Threshold 50 is the first reading, threshold
    30 is "any issue", which is what --exit-non-zero-on-finding gates on."""
    eco = {"ide_extensions": "extension"}.get(ecosystem(sample), ecosystem(sample))
    cmd = ["docker", "run", "--rm"]
    if os.path.exists(target):
        inside = "/sample" + (os.path.splitext(target)[1] if os.path.isfile(target) else "")
        cmd += ["-v", f"{os.path.abspath(target)}:{inside}:ro"]
        spec = [inside]
    else:
        # Registry targets: npm:name[@version], pypi:name[==version], publisher.extension
        name, version = target.split(":", 1)[-1], None
        if eco == "npm" and "@" in name[1:]:
            name, version = name.rsplit("@", 1)
        elif eco == "pypi" and "==" in name:
            name, version = name.split("==", 1)
        spec = [name] + (["--version", version] if version else [])
    # --no-sandbox: GuardDog's own kernel sandbox is unavailable inside the container.
    cmd += [args.guarddog_image, eco, "scan", *spec, "--no-sandbox", "--output-format", "json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    report = [line for line in proc.stdout.splitlines() if line.startswith("{")]
    if not report:
        return {"error": (proc.stderr.strip().splitlines() or ["no output"])[-1][:200]}
    result = json.loads(report[-1])
    hits = sorted(rule for rule, found in (result.get("results") or {}).items() if found)
    threats = [rule for rule in hits if not rule.startswith("capability-")]
    risk = 100 if threats else 40 if hits else 0
    return {"risk": risk, "strong": (threats + hits)[:12]}


def scan(sample, args):
    started = time.time()
    with tempfile.TemporaryDirectory(prefix="kalascan-eval-") as tmp:
        target = sample["target"]
        if sample["source"] in LOCAL:
            root = getattr(args, LOCAL[sample["source"]][0])
            path = os.path.join(root, target)
            if not os.path.exists(path):
                return {"error": f"missing; run {LOCAL[sample['source']][1]}"}
            dest = os.path.join(tmp, "x")
            try:
                if path.endswith((".zip", ".whl")):
                    # Dataset archives use ZipCrypto with the published password.
                    # zipfile drops `..` and absolute member names on extract.
                    with zipfile.ZipFile(path) as z:
                        z.extractall(dest, pwd=b"infected")
                    target = package_root(dest)
                elif path.endswith((".tar.gz", ".tgz")):
                    with tarfile.open(path) as t:
                        t.extractall(dest, filter="data")
                    target = package_root(dest)
            except (zipfile.BadZipFile, tarfile.TarError, OSError, RuntimeError) as e:
                # A broken archive is an error, not a miss: it leaves the denominators.
                return {"error": f"cannot extract: {str(e).splitlines()[0][:160]}"}
            if target == sample["target"]:
                target = path
        if args.scanner == "guarddog":
            found = guarddog(sample, target, args)
            found.setdefault("seconds", round(time.time() - started, 1))
            return found
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
        # Every finding once, for --rule-stats and eval/fit_weights.py.
        "rules": sorted({(m["matched_pattern"], m["severity"]) for m in result["rule_matches"]}),
    }


def wilson(num, den, z=1.96):
    """95% Wilson score interval: honest at 0/n and n/n, where the normal one collapses."""
    if not den:
        return 0.0, 1.0
    p = num / den
    mid = (p + z * z / (2 * den)) / (1 + z * z / den)
    half = z * math.sqrt(p * (1 - p) / den + z * z / (4 * den * den)) / (1 + z * z / den)
    return max(0.0, mid - half), min(1.0, mid + half)


def rate(num, den):
    if not den:
        return "-"
    lo, hi = wilson(num, den)
    return f"{num}/{den} ({100 * num / den:.0f}%, {100 * lo:.0f}-{100 * hi:.0f})"


def rule_stats(done, split):
    """How often each finding fires per class, and the likelihood ratio
    P(fires | malicious) / P(fires | clean) with Jeffreys smoothing (+0.5),
    so a finding never seen on clean samples gets a finite ratio that grows
    with the number of clean samples it was tested on."""
    group = [s for s in done if split == "all" or s.get("split", "dev") == split]
    mal = [s for s in group if s["label"] == "malicious"]
    cln = [s for s in group if s["label"] == "clean"]
    hits = collections.defaultdict(lambda: [0, 0, ""])
    for samples, col in ((mal, 0), (cln, 1)):
        for s in samples:
            for name, severity in s.get("rules", []):
                hits[name][col] += 1
                hits[name][2] = severity
    rows = []
    for name, (m, c, severity) in hits.items():
        lr = ((m + 0.5) / (len(mal) + 1)) / ((c + 0.5) / (len(cln) + 1)) if mal and cln else 0.0
        rows.append((lr, name, severity, m, c))
    print(f"\n== findings on split '{split}' ({len(mal)} malicious, {len(cln)} clean), by likelihood ratio")
    print(f"  {'LR':>7}  {'malicious':>9}  {'clean':>5}  {'severity':8}  finding")
    for lr, name, severity, m, c in sorted(rows, reverse=True):
        print(f"  {lr:>7.1f}  {m:>9}  {c:>5}  {severity:8}  {name}")


def summarize(samples):
    """--summary: per split and per set, flagged / scanned at every threshold
    with its Wilson bounds, and the samples that could not be scanned. No
    sample names, so a holdout result can be published (eval/results/)."""
    keys = sorted({(s.get("split", "dev"), "") for s in samples} | {(s.get("split", "dev"), s["set"]) for s in samples if s.get("set")})
    groups = {}
    for split, name in keys:
        inside = [s for s in samples if s.get("split", "dev") == split and (not name or s.get("set") == name)]
        group = groups[split + ("/" + name if name else "")] = {}
        for label in ("malicious", "clean"):
            scanned = [s for s in inside if s["label"] == label and "risk" in s]
            errors = sum(s["label"] == label and "error" in s for s in inside)
            if scanned or errors:
                # Errors are outside `total`, as in the printed rates.
                group[label] = {"total": len(scanned), "errors": errors}
                for t in THRESHOLDS:
                    hit = sum(s["risk"] >= t for s in scanned)
                    lo, hi = wilson(hit, len(scanned))
                    group[label][str(t)] = {"flagged": hit, "lo": round(lo, 4), "hi": round(hi, 4)}
    return groups


def dated(samples, since):
    """--since: holdout malware whose DataDog file name carries a date on or
    after `since`. A slice across sets: what is newer than the tuning batches."""
    day = re.compile(r"/(\d{4}-\d{2}-\d{2})-")
    return [s for s in samples if s["label"] == "malicious" and s.get("split") == "holdout"
            and (m := day.search(s["target"])) and m.group(1) >= since]


def gate(done, errors, threshold, min_recall, max_fpr, allow_errors):
    """Exit status of a run. A rate over no sample is not a pass: with every
    scan failing (a binary that does not start, a registry outage), `fpr` used
    to be 0 of 0 and `--max-fpr 0 --allow-errors` exited 0."""
    mal = [s for s in done if s["label"] == "malicious"]
    cln = [s for s in done if s["label"] == "clean"]
    recall = sum(s["risk"] >= threshold for s in mal) / len(mal) if mal else 1.0
    fpr = sum(s["risk"] >= threshold for s in cln) / len(cln) if cln else 0.0
    failed = (min_recall is not None and recall < min_recall) or (max_fpr is not None and fpr > max_fpr)
    unmeasured = (min_recall is not None and not mal) or (max_fpr is not None and not cln)
    too_many = len(errors) > MAX_ERROR_RATE * (len(done) + len(errors))
    if unmeasured or too_many:
        print(f"gate: {len(errors)} of {len(done) + len(errors)} samples could not be scanned; nothing was measured", file=sys.stderr)
    return 1 if failed or unmeasured or too_many or (errors and not allow_errors) else 0


def self_test():
    """--self-test: the arithmetic a published number goes through. A wrong
    `package_root` once changed a result (docs/methodology.md)."""
    assert wilson(0, 0) == (0.0, 1.0)
    lo, hi = wilson(0, 100)
    assert lo == 0.0 and 0.03 < hi < 0.04, (lo, hi)
    assert rate(1, 4) == "1/4 (25%, 5-70)", rate(1, 4)

    with tempfile.TemporaryDirectory() as d:
        assert package_root(d) == d
        for sub in ("pkg-1.0", "sources/pkg"):
            os.makedirs(os.path.join(d, sub))
        open(os.path.join(d, "pkg-1.0", "setup.py"), "w").close()
        assert package_root(d) == os.path.join(d, "pkg-1.0")
        # A second manifest at the same depth: their common parent, not one of them.
        os.makedirs(os.path.join(d, "other"))
        open(os.path.join(d, "other", "package.json"), "w").close()
        assert package_root(d) == d
        os.makedirs(os.path.join(d, "wheel", "x-1.0.dist-info"))
        assert package_root(os.path.join(d, "wheel")) == os.path.join(d, "wheel")

    def sample(label, risk=None, split="holdout", **more):
        return {"label": label, "split": split, **({"error": "x"} if risk is None else {"risk": risk}), **more}

    groups = summarize([sample("malicious", 90), sample("malicious", 20), sample("malicious"),
                        sample("clean", 0, set="random"), sample("clean", 50, split="dev")])
    mal = groups["holdout"]["malicious"]
    # The sample that could not be scanned is an error, outside the total.
    assert (mal["total"], mal["errors"], mal["30"]["flagged"], mal["50"]["flagged"]) == (2, 1, 1, 1), groups
    assert groups["holdout/random"]["clean"]["total"] == 1 and groups["dev"]["clean"]["50"]["flagged"] == 1, groups

    clean, flagged, broken = sample("clean", 0), sample("clean", 50), sample("clean")
    assert gate([clean] * 20, [], 50, None, 0, False) == 0
    assert gate([clean] * 19 + [flagged], [], 50, None, 0, True) == 1
    assert gate([clean] * 20, [broken], 50, None, 0, False) == 1  # an error, and errors are not allowed
    assert gate([clean] * 20, [broken], 50, None, 0, True) == 0  # 1 of 21, under the ceiling
    assert gate([clean] * 10, [broken] * 2, 50, None, 0, True) == 1  # too many to call it measured
    assert gate([], [broken] * 5, 50, None, 0, True) == 1  # nothing scanned is not 0 false positives
    assert gate([], [], 50, None, 0, True) == 1
    assert gate([sample("malicious", 90)], [], 50, 0.5, None, False) == 0
    assert gate([clean], [], 50, 0.5, None, False) == 1  # a recall gate with no malware scanned
    print("self-test ok")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default=os.path.join(os.path.dirname(__file__), "corpus.json"))
    ap.add_argument("--dataset", help="checkout of the DataDog dataset (for malicious samples)")
    ap.add_argument("--malregistry", help="checkout of pypi_malregistry (second, independent malicious source)")
    ap.add_argument("--npmstudy", help="directory eval/fetch_npmstudy.py extracted into (second npm source)")
    ap.add_argument("--skills", help="directory eval/fetch_skills.py fetched the clean AI agent skills into")
    ap.add_argument("--rule-stats", nargs="?", const="dev", metavar="SPLIT", help="per-finding hit counts and likelihood ratio on SPLIT (dev, holdout, all) [dev]")
    ap.add_argument("--kalascan", default="target/release/kalascan")
    ap.add_argument("--scanner", choices=("kalascan", "guarddog"), default="kalascan", help="tool to measure")
    ap.add_argument("--guarddog-image", default="ghcr.io/datadog/guarddog:latest")
    ap.add_argument("--only", choices=("clean", "malicious"))
    ap.add_argument("--skip-set", action="append", default=[], metavar="SET", help="leave out the samples of a set, repeatable (the PR gate skips the large random draw; the weekly run scans it)")
    ap.add_argument("--flag", action="append", default=[], help="extra scan flag, repeatable (e.g. --flag=--deobfuscate)")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--out", help="write per-sample results JSON")
    ap.add_argument("--compare", help="previous --out file; print score changes")
    ap.add_argument("--summary", help="write aggregate counts JSON (no sample names): one per ruleset version in eval/results/")
    ap.add_argument("--since", metavar="YYYY-MM-DD", help="also report the holdout malware dated on or after this day")
    ap.add_argument("--threshold", type=int, default=50, help="threshold the gates apply to")
    ap.add_argument("--min-recall", type=float, help="fail if malicious recall is below this (0-1)")
    ap.add_argument("--max-fpr", type=float, help="fail if clean false-positive rate is above this (0-1)")
    ap.add_argument("--allow-errors", action="store_true", help="don't fail on download/scan errors (flaky registries in CI)")
    ap.add_argument("--show-holdout", action="store_true", help="also list holdout misses and score changes (then move what you read to dev)")
    ap.add_argument("--disposable-vm", action="store_true", help="confirm this runs in a throwaway VM; required by --flag=--sandbox")
    ap.add_argument("--self-test", action="store_true", help="check the harness's own arithmetic and exit")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if args.summary and args.scanner != "kalascan":
        ap.error("--summary records a KalaScan ruleset version; not with --scanner guarddog")
    if "--sandbox" in args.flag:
        # --sandbox executes the samples: live malware, so only on a throwaway machine.
        if not args.disposable_vm:
            ap.error("--flag=--sandbox runs live malware; only in a disposable VM with no host file sharing, then pass --disposable-vm (eval/README.md)")
        if args.summary:
            ap.error("--summary records the default scan; a --sandbox run is a separate measurement")

    samples = [
        s
        for s in json.load(open(args.corpus))["samples"]
        if (not args.only or s["label"] == args.only) and s.get("set") not in args.skip_set
    ]
    if any(s["source"] == "dataset" for s in samples) and not args.dataset:
        ap.error("--dataset is required for malicious samples (or use --only clean)")
    # The second sources are optional: without their files those samples are left out.
    samples = [s for s in samples if s["source"] not in ("malregistry", "npmstudy") or getattr(args, s["source"])]

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
    print(f"{'T':>4}  {'malicious recall':<26}{'clean false positives':<26}")
    for t in THRESHOLDS:
        mal = [s for s in done if s["label"] == "malicious"]
        cln = [s for s in done if s["label"] == "clean"]
        print(f"{t:>4}  {rate(sum(s['risk'] >= t for s in mal), len(mal)):<26}"
              f"{rate(sum(s['risk'] >= t for s in cln), len(cln)):<26}")

    # Per split, and per sample set inside it: a set drawn later or from
    # another source is its own measurement (see eval/README.md).
    groups = sorted({(s.get("split", "dev"), "") for s in done} | {(s.get("split", "dev"), s["set"]) for s in done if s.get("set")})
    if len(groups) > 1:
        print(f"\n== per split and set at T={args.threshold} (rules are tuned on 'dev'; 'holdout' is the honest number)")
        for split, name in groups:
            inside = [s for s in done if s.get("split", "dev") == split and (not name or s.get("set") == name)]
            mal = [s for s in inside if s["label"] == "malicious"]
            cln = [s for s in inside if s["label"] == "clean"]
            print(f"  {split + ('/' + name if name else ''):28} recall {rate(sum(s['risk'] >= args.threshold for s in mal), len(mal)):<24}"
                  f"false positives {rate(sum(s['risk'] >= args.threshold for s in cln), len(cln))}")

    if args.since:
        late = dated(done, args.since)
        print(f"  {'holdout, dated ' + args.since + ' or later':28} recall {rate(sum(s['risk'] >= args.threshold for s in late), len(late))}")

    print(f"\n== per ecosystem at T={args.threshold}")
    for eco in sorted({ecosystem(s) for s in done}):
        for label in ("malicious", "clean"):
            group = [s for s in done if s["label"] == label and ecosystem(s) == eco]
            if group:
                hit = sum(s["risk"] >= args.threshold for s in group)
                print(f"  {eco:15} {label:9} flagged {rate(hit, len(group))}")

    # Holdout misses are counted, not listed: a sample somebody has looked at
    # is no longer a holdout sample (move it to dev before reading it).
    print(f"\n== misses at T={args.threshold}" + ("" if args.show_holdout else " (dev only; holdout misses are counted above, not listed)"))
    for s in done:
        missed = (s["label"] == "malicious") != (s["risk"] >= args.threshold)
        if missed and (args.show_holdout or s.get("split", "dev") == "dev"):
            kind = "FN" if s["label"] == "malicious" else "FP"
            print(f"  {kind} {s['risk']:>3} {s['target']}  {', '.join(s['strong'][:4])}")
    for s in errors:
        print(f"  ERR {s['target']}: {s['error']}")

    if args.rule_stats:
        rule_stats(done, args.rule_stats)

    if args.compare and os.path.exists(args.compare):
        before = {s["target"]: s.get("risk") for s in json.load(open(args.compare))}
        print("\n== score changes vs", args.compare)
        for s in done:
            old = before.get(s["target"])
            if old is not None and old != s["risk"] and (args.show_holdout or s.get("split", "dev") == "dev"):
                print(f"  {s['label']:9} {old:>3} -> {s['risk']:>3}  {s['target']}")

    if args.out:
        json.dump(samples, open(args.out, "w"), indent=1)

    if args.summary:
        rules = subprocess.run([args.kalascan, "rules"], capture_output=True, text=True, check=True).stdout
        summary = {"date": time.strftime("%Y-%m-%d"), "ruleset": rules.splitlines()[0].split(": ")[-1]}
        # What the binary was built from: the version is raised by hand, this is not.
        summary.update({"detection": line.split(": ")[-1] for line in rules.splitlines()[1:2] if line.startswith("Detection fingerprint")})
        words = " ".join(args.flag).replace("=", " ").split()
        if "--score-model" in words[:-1]:
            summary["score_model"] = words[words.index("--score-model") + 1]
        summary["groups"] = summarize(samples)
        if args.since:
            summary["groups"]["holdout/since-" + args.since] = summarize(dated(samples, args.since)).get("holdout", {})
        with open(args.summary, "w") as f:
            json.dump(summary, f, indent=1)
            f.write("\n")

    sys.exit(gate(done, errors, args.threshold, args.min_recall, args.max_fpr, args.allow_errors))


if __name__ == "__main__":
    main()
