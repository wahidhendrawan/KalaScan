#!/usr/bin/env python3
"""Draw unseen malicious samples for a new holdout set.

Both sources are read from a blobless clone: only file names are listed,
nothing is checked out (eval/fetch_malicious.sh does that later).

  # DataDog dataset, samples dated on or after a day (the date is in the file name)
  python3 eval/sample_malicious.py --dataset ~/kalascan-corpus --since 2026-08-01 --ecosystem npm --set recent-2026-11

  # IDE extensions and AI agent skills have no date in the file name, so --since does not apply
  python3 eval/sample_malicious.py --dataset ~/kalascan-corpus --ecosystem ide_extensions --set tune-ext-2026-11
  python3 eval/sample_malicious.py --dataset ~/kalascan-corpus --ecosystem ai-skills --set skills-2026-11

  # pypi_malregistry, only package names the DataDog dataset does not have
  python3 eval/sample_malicious.py --dataset ~/kalascan-corpus --malregistry ~/kalascan-malregistry --set malregistry-2026-11

  # the ASE 2026 npm study (eval/fetch_npmstudy.py), same rule
  python3 eval/fetch_npmstudy.py --list npmstudy.txt
  python3 eval/sample_malicious.py --dataset ~/kalascan-corpus --npmstudy npmstudy.txt --set npmstudy-2026-11

One version per package name, names already in the corpus are skipped, and
the pick is seeded. Prints corpus entries (split "holdout") to paste into
eval/corpus.json. Nobody reads the picked samples: that is what makes the
set a holdout.
"""

import argparse
import json
import os
import random
import re
import subprocess
import sys


def tree(repo, prefix=""):
    out = subprocess.run(
        ["git", "-C", repo, "ls-tree", "-r", "--name-only", "HEAD", *([prefix] if prefix else [])],
        capture_output=True, text=True, check=True,
    ).stdout
    return [line for line in out.splitlines() if line]


def norm(name):
    """PyPI name normalisation (PEP 503), good enough for npm too."""
    return re.sub(r"[-_.]+", "-", name).lower()


def study_name(name):
    """The npm study writes `@scope/name` as `scope##name`, DataDog as `@scope@name`."""
    return "@" + name.replace("##", "@") if "##" in name else name


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default=os.path.join(os.path.dirname(__file__), "corpus.json"))
    ap.add_argument("--dataset", required=True, help="blobless clone of the DataDog dataset")
    ap.add_argument("--malregistry", help="blobless clone of pypi_malregistry; draw from it instead")
    ap.add_argument("--npmstudy", metavar="LIST", help="tarball list from eval/fetch_npmstudy.py --list; draw npm from it instead")
    ap.add_argument("--ecosystem", choices=("npm", "pypi", "ide_extensions", "ai-skills"), default="npm", help="DataDog ecosystem to draw from")
    ap.add_argument("--since", default="0000-00-00", help="DataDog only: samples dated on or after YYYY-MM-DD")
    ap.add_argument("--before", default="9999-99-99", help="DataDog only: samples dated before YYYY-MM-DD (a tuning batch stays behind the newest holdout)")
    ap.add_argument("--size", type=int, default=100)
    ap.add_argument("--seed", type=int, default=20261117)
    ap.add_argument("--set", required=True, help="name recorded on every entry, e.g. recent-2026-11")
    args = ap.parse_args()

    used = set()
    for s in json.load(open(args.corpus))["samples"]:
        parts = s["target"].split("/")
        used.add(norm(study_name(parts[3]) if s["source"] in ("dataset", "npmstudy") else parts[0]))

    by_name = {}
    if args.npmstudy:
        source = "npmstudy"
        known = {norm(p.split("/")[3]) for p in tree(args.dataset, "samples/npm") if p.count("/") >= 5}
        for path in open(args.npmstudy).read().split():
            name = norm(study_name(path.split("/")[3]))
            if name not in known | used:
                by_name.setdefault(name, []).append(path)
    elif args.malregistry:
        source = "malregistry"
        known = {norm(p.split("/")[3]) for p in tree(args.dataset, "samples/pypi") if p.count("/") >= 5}
        for path in tree(args.malregistry):
            parts = path.split("/")
            if len(parts) == 3 and path.endswith((".tar.gz", ".whl", ".zip")) and norm(parts[0]) not in known | used:
                by_name.setdefault(norm(parts[0]), []).append(path)
    else:
        source = "dataset"
        for path in tree(args.dataset, f"samples/{args.ecosystem}"):
            parts = path.split("/")
            dated = re.match(r"\d{4}-\d{2}-\d{2}", parts[-1])
            if args.ecosystem in ("ide_extensions", "ai-skills"):
                # samples/ide_extensions/<kind>/<id>/<version>.vsix, samples/ai-skills/<kind>/<id>/<id>.zip: no date in the name.
                wanted = len(parts) == 5 and path.endswith(".vsix" if args.ecosystem == "ide_extensions" else ".zip")
            else:
                wanted = len(parts) >= 6 and dated and args.since <= dated.group() < args.before
            if wanted and norm(parts[3]) not in used:
                by_name.setdefault(norm(parts[3]), []).append(path)

    rng = random.Random(args.seed)
    names = rng.sample(sorted(by_name), min(args.size, len(by_name)))
    entries = [
        {"target": rng.choice(sorted(by_name[n])), "label": "malicious", "source": source, "split": "holdout", "set": args.set}
        for n in names
    ]
    print(f"{len(by_name)} unseen package names, picked {len(entries)}", file=sys.stderr)
    json.dump(entries, sys.stdout, indent=1)


main()
