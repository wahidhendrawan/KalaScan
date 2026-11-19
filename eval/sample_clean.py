#!/usr/bin/env python3
"""Draw a uniform random sample of npm and PyPI packages for the clean corpus.

Popular packages are a soft false-positive test: they are well kept and
were partly picked by hand. This draws from the whole registries instead.

npm: a random rank in the ecosyste.ms npm index (sort=id). PyPI: a random
name from the simple index. With --openvsx: a random extension from Open
VSX's sitemap, pinned the same way (a version page URL). Each package is pinned to its newest version
published before --cutoff: registries remove malicious versions within days,
so a version that has survived months is very likely benign. Rejected draws
are counted by reason, so the sample's bias can be read off the output.

  python3 eval/sample_clean.py > sample.json
"""

import argparse
import collections
import concurrent.futures as cf
import json
import random
import re
import sys
import urllib.parse
import urllib.request

MAX_BYTES = 30 * 1024 * 1024


def get(url, accept="application/json"):
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "kalascan-eval-sampler"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.load(r)


def npm_pick(rank, cutoff):
    try:
        rows = get(f"https://packages.ecosyste.ms/api/v1/registries/npmjs.org/packages?per_page=1&page={rank}&sort=id")
    except Exception:
        return None, "index error"
    if not rows:
        return None, "no index row"
    name = rows[0]["name"]
    try:
        doc = get("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"))
    except Exception:
        return None, "gone from registry"
    versions = doc.get("versions", {})
    old = [(t, v) for v, t in doc.get("time", {}).items() if v in versions and t[:10] < cutoff]
    if not old:
        return None, "no version before cutoff"
    version = max(old)[1]
    if "-security" in version:
        return None, "npm security placeholder"
    if versions[version].get("dist", {}).get("unpackedSize", 0) > MAX_BYTES:
        return None, "too large"
    return f"npm:{name}@{version}", "ok"


def pypi_pick(name, cutoff):
    try:
        doc = get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
    except Exception:
        return None, "gone from registry"
    best = None
    for version, files in doc.get("releases", {}).items():
        live = [f for f in files if not f.get("yanked") and f["upload_time_iso_8601"][:10] < cutoff]
        if live:
            when = max(f["upload_time_iso_8601"] for f in live)
            if best is None or when > best[0]:
                best = (when, version, min(f["size"] for f in live))
    if best is None:
        return None, "no version before cutoff"
    if best[2] > MAX_BYTES:
        return None, "too large"
    return f"pypi:{name}=={best[1]}", "ok"


def openvsx_pick(ext, cutoff):
    ns, name = ext.split("/")
    try:
        q = urllib.parse.urlencode({"namespaceName": ns, "extensionName": name, "includeAllVersions": "true"})
        versions = get(f"https://open-vsx.org/api/-/query?{q}")["extensions"]
    except Exception:
        return None, "gone from registry"
    # Platform builds are one release each; the universal package is the one to scan.
    old = [(v["timestamp"], v["version"]) for v in versions if v.get("targetPlatform", "universal") == "universal" and v["timestamp"][:10] < cutoff]
    if not old:
        return None, "no version before cutoff"
    return f"https://open-vsx.org/extension/{ns}/{name}/{max(old)[1]}", "ok"


def sample(pick, draws, cutoff, size):
    picked, why = [], collections.Counter()
    with cf.ThreadPoolExecutor(6) as pool:
        for target, reason in pool.map(lambda d: pick(d, cutoff), draws):
            why[reason] += 1
            if target and len(picked) < size:
                picked.append(target)
    return picked, dict(why)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", type=int, default=20261116)
    ap.add_argument("--cutoff", default="2026-05-16", help="newest version published before this date")
    ap.add_argument("--size", type=int, default=150, help="packages per ecosystem")
    ap.add_argument("--draws", type=int, default=330, help="draws per ecosystem")
    ap.add_argument("--openvsx", action="store_true", help="draw IDE extensions from Open VSX instead of npm and PyPI packages")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    if args.openvsx:
        # The sitemap lists every extension; search stops at offset 10,000.
        req = urllib.request.Request("https://open-vsx.org/sitemap.xml", headers={"User-Agent": "kalascan-eval-sampler"})
        with urllib.request.urlopen(req, timeout=90) as r:
            sitemap = r.read().decode()
        names = sorted(set(re.findall(r"<loc>https://open-vsx\.org/extension/([^/<]+/[^/<]+)</loc>", sitemap)))
        ext, ext_why = sample(openvsx_pick, rng.sample(names, args.draws), args.cutoff, args.size)
        json.dump({"openvsx": ext, "openvsx_draws": ext_why}, sys.stdout, indent=1)
        return
    npm_count = get("https://packages.ecosyste.ms/api/v1/registries/npmjs.org")["packages_count"]
    names = [p["name"] for p in get("https://pypi.org/simple/", "application/vnd.pypi.simple.v1+json")["projects"]]
    npm, npm_why = sample(npm_pick, [rng.randrange(1, npm_count + 1) for _ in range(args.draws)], args.cutoff, args.size)
    pypi, pypi_why = sample(pypi_pick, rng.sample(names, args.draws), args.cutoff, args.size)
    json.dump({"npm": npm, "pypi": pypi, "npm_draws": npm_why, "pypi_draws": pypi_why}, sys.stdout, indent=1)


main()
