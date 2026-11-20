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
With --skills: AI agent skills from GitHub code search, pinned to a commit
(no registry, no cutoff; eval/fetch_skills.py fetches them).

  python3 eval/sample_clean.py > sample.json
  GITHUB_TOKEN=$(gh auth token) python3 eval/sample_clean.py --skills --size 300 > skills.json
"""

import argparse
import collections
import concurrent.futures as cf
import json
import os
import random
import re
import sys
import time
import urllib.error
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


def github(path, token, **params):
    url = f"https://api.github.com/{path}?{urllib.parse.urlencode(params)}"
    headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}", "User-Agent": "kalascan-eval-sampler"}
    for wait in (60, 120, 0):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=90) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code not in (403, 429) or not wait:  # secondary rate limit
                raise
            time.sleep(wait)


def skill_target(repo, commit, skill_md):
    """`owner/repo/<commit>/<directory of SKILL.md>`, the form eval/fetch_skills.py reads."""
    return f"{repo}/{commit}/{skill_md.rpartition('/')[0] or '.'}"


def skills_draw(rng, size, token):
    """AI agent skills (a directory with a SKILL.md) from GitHub code search.
    Search returns at most 1,000 hits per query, best match first, so the draw
    goes by file-size bucket: a bucket in proportion to its hit count, a
    random page of it, five random hits of that page. Not uniform: the count
    of a large bucket is capped. One skill per repository."""
    search = lambda **p: (time.sleep(6.5), github("search/code", token, **p))[1]  # 10 searches a minute
    edges = [round(100 * 1.25**i) for i in range(30)]  # 100 B to 65 KB
    buckets = [(f"{lo}..{hi - 1}", search(q=f"filename:SKILL.md size:{lo}..{hi - 1}", per_page=1)["total_count"])
               for lo, hi in zip(edges, edges[1:])]
    picked, repos, why = [], set(), collections.Counter()
    while len(picked) < size and why["search"] < 400:
        sizes, = rng.choices([b for b, _ in buckets], weights=[n for _, n in buckets])
        total = dict(buckets)[sizes]
        page = rng.randint(1, max(1, min(10, -(-total // 100))))
        why["search"] += 1
        items = search(q=f"filename:SKILL.md size:{sizes}", per_page=100, page=page)["items"]
        for item in rng.sample(items, min(5, len(items))):
            repo = item["repository"]["full_name"]
            commit = urllib.parse.parse_qs(urllib.parse.urlparse(item["url"]).query).get("ref", [""])[0]
            if not commit:
                why["no commit in the hit"] += 1
            elif item["name"] != "SKILL.md":
                why["not SKILL.md"] += 1
            elif repo.lower() in repos:
                why["repository drawn already"] += 1
            elif len(picked) < size:
                repos.add(repo.lower())
                picked.append(skill_target(repo, commit, item["path"]))
                why["ok"] += 1
    return picked, dict(why)


def skills_in(repo, token):
    """Every skill of a hand-picked repository, at its default branch's head."""
    branch = github(f"repos/{repo}", token)["default_branch"]
    commit = github(f"repos/{repo}/commits/{branch}", token)["sha"]
    tree = github(f"repos/{repo}/git/trees/{commit}", token, recursive=1)["tree"]
    return [skill_target(repo, commit, t["path"]) for t in tree if t["path"].rpartition("/")[2] == "SKILL.md"]


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
    ap.add_argument("--skills", action="store_true", help="draw AI agent skills from GitHub code search instead (needs GITHUB_TOKEN)")
    ap.add_argument("--skills-repo", action="append", default=[], metavar="OWNER/REPO", help="list every skill of a repository instead, repeatable (needs GITHUB_TOKEN)")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    if args.skills or args.skills_repo:
        token = os.environ["GITHUB_TOKEN"]  # code search needs a token
        if args.skills_repo:
            json.dump({"skills": [t for r in args.skills_repo for t in skills_in(r, token)]}, sys.stdout, indent=1)
        else:
            skills, why = skills_draw(rng, args.size, token)
            json.dump({"skills": skills, "skills_draws": why}, sys.stdout, indent=1)
        return
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
