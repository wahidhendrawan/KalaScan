#!/usr/bin/env python3
"""What became of the releases `kalascan watch --log` scanned.

The corpus holds malware somebody already caught. This is the other
measurement: releases scored on the day they were published, checked later
against what was found out about them. For every release in the logs it asks
OSV for a malicious-package record (`MAL-…`, from the OpenSSF
malicious-packages feed, which takes in the registries' own removals), and for
the flagged ones without a record whether the registry still serves them.

  kalascan watch --ecosystem npm --log npm.jsonl          # for days or weeks
  python3 eval/watch_outcome.py npm.jsonl pypi.jsonl --min-age 30

Reported: of the flagged releases, how many were later named malicious, are
gone, or are still up; of the releases later named malicious, how many were
flagged (with a 95% Wilson interval), and how long before the OSV record the
scan ran. A release nobody has named yet counts as not malicious, so the
flagged-and-still-up row is an upper bound on false positives and the recall
is on malware found within the wait, not on all of it. "Gone" is weaker than
a record: authors unpublish too.
"""

import argparse
import collections
import datetime
import json
import math
import statistics
import sys
import urllib.error
import urllib.parse
import urllib.request

OSV = "https://api.osv.dev/v1"


def wilson(num, den, z=1.96):
    """95% Wilson score interval, as in eval/run_eval.py."""
    if not den:
        return 0.0, 1.0
    p = num / den
    mid = (p + z * z / (2 * den)) / (1 + z * z / den)
    half = z * math.sqrt(p * (1 - p) / den + z * z / (4 * den * den)) / (1 + z * z / den)
    return max(0.0, mid - half), min(1.0, mid + half)


def call(url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "kalascan-eval", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.load(r)


def when(text):
    return datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))


def parse(target):
    """`npm:name@1.0.0` / `pypi:name==1.0.0` -> (OSV ecosystem, name, version)."""
    kind, _, spec = target.partition(":")
    name, _, version = spec.rpartition("@") if kind == "npm" else spec.partition("==")
    return {"npm": "npm", "pypi": "PyPI"}[kind], name, version


def read_logs(paths, min_age, now):
    """The first scan of each target, old enough to have an outcome; and how many scans failed."""
    first, errors = {}, 0
    for path in paths:
        for line in open(path):
            row = json.loads(line)
            if "risk" not in row:
                errors += 1
            elif (now - when(row["ts"])).days >= min_age and row["target"] not in first:
                first[row["target"]] = row
    return list(first.values()), errors


def osv_records(rows):
    """target -> the earliest `published` time among its MAL- records."""
    found, published = {}, {}
    for i in range(0, len(rows), 1000):
        batch = rows[i:i + 1000]
        queries = [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in (parse(r["target"]) for r in batch)]
        for row, result in zip(batch, call(f"{OSV}/querybatch", {"queries": queries})["results"]):
            ids = [v["id"] for v in result.get("vulns", []) if v["id"].startswith("MAL-")]
            for vid in ids:
                if vid not in published:
                    published[vid] = when(call(f"{OSV}/vulns/{vid}")["published"])
            if ids:
                found[row["target"]] = min(published[v] for v in ids)
    return found


def gone(target):
    """True when the registry no longer serves the release (npm: also a security placeholder)."""
    eco, name, version = parse(target)
    url = (f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}" if eco == "npm"
           else f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json")
    try:
        doc = call(url)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return True
        raise
    return eco == "npm" and (version not in doc.get("versions", {}) or doc.get("dist-tags", {}).get("latest", "").endswith("-security"))


def outcome(rows, named, is_gone, threshold):
    """Counts per fate, the flagged-and-still-up targets, the missed ones, and scan-to-record lead times in days."""
    counts, still_up, missed, lead = collections.Counter(), [], [], []
    for r in rows:
        flagged, target = r["risk"] >= threshold, r["target"]
        if target in named:
            counts["flagged, named malicious" if flagged else "not flagged, named malicious"] += 1
            if flagged:
                lead.append((named[target] - when(r["ts"])).total_seconds() / 86400)
            else:
                missed.append(target)
        elif flagged and is_gone(target):
            counts["flagged, gone from the registry"] += 1
        elif flagged:
            counts["flagged, still up"] += 1
            still_up.append((r["risk"], target, r.get("findings", [])))
        else:
            counts["not flagged"] += 1
    return counts, still_up, missed, lead


def self_test():
    t0 = "2026-01-01T00:00:00Z"
    rows = [{"ts": t0, "target": f"npm:{n}@1.0.0", "risk": risk} for n, risk in (("a", 90), ("b", 90), ("c", 90), ("d", 0), ("e", 5))]
    named = {"npm:a@1.0.0": when("2026-01-03T00:00:00Z"), "npm:d@1.0.0": when(t0)}
    counts, still_up, missed, lead = outcome(rows, named, lambda t: t == "npm:b@1.0.0", 50)
    assert counts == {"flagged, named malicious": 1, "flagged, gone from the registry": 1, "flagged, still up": 1,
                      "not flagged, named malicious": 1, "not flagged": 1}, counts
    assert [t for _, t, _ in still_up] == ["npm:c@1.0.0"] and missed == ["npm:d@1.0.0"] and lead == [2.0]
    assert parse("npm:@scope/x@1.2.3") == ("npm", "@scope/x", "1.2.3") and parse("pypi:x==1!2.0") == ("PyPI", "x", "1!2.0")
    print("ok")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs", nargs="*", help="files written by `kalascan watch --log`")
    ap.add_argument("--threshold", type=int, default=50)
    ap.add_argument("--min-age", type=int, default=30, metavar="DAYS", help="leave out releases scanned fewer days ago: a takedown takes time")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    rows, errors = read_logs(args.logs, args.min_age, datetime.datetime.now(datetime.timezone.utc))
    if not rows:
        sys.exit(f"no release scanned {args.min_age} or more days ago in {len(args.logs)} log(s)")
    counts, still_up, missed, lead = outcome(rows, osv_records(rows), gone, args.threshold)
    print(f"{len(rows)} releases scanned {args.min_age} or more days ago ({errors} scans in the logs failed), threshold {args.threshold}")
    for fate in ("flagged, named malicious", "flagged, gone from the registry", "flagged, still up", "not flagged, named malicious", "not flagged"):
        print(f"  {counts[fate]:>7}  {fate}")
    caught, known = counts["flagged, named malicious"], counts["flagged, named malicious"] + counts["not flagged, named malicious"]
    if known:
        lo, hi = wilson(caught, known)
        print(f"flagged {caught} of the {known} later named malicious ({100 * caught / known:.0f}%, {100 * lo:.0f}-{100 * hi:.0f})")
    if lead:
        print(f"scan to OSV record: median {statistics.median(lead):.1f} days, {sum(d > 0 for d in lead)} of {len(lead)} scanned before the record")
    for risk, target, findings in sorted(still_up, reverse=True):
        print(f"  still up  {risk:>3}  {target}  {', '.join(findings)}")
    for target in missed:
        print(f"  missed  {target}")


if __name__ == "__main__":
    main()
