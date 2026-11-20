#!/usr/bin/env python3
"""Fetch the clean AI agent skills listed in eval/corpus.json (`"source": "skills"`).

A target is `owner/repo/<commit>/<directory>` (eval/sample_clean.py --skills):
the directory holding a SKILL.md, at a pinned commit. Each is fetched with
git into DEST/<target>: a shallow, blobless fetch of that one commit and a
sparse checkout of the directory, so a large repository is not downloaded
whole. Symlinks are written as plain files, so nothing points outside DEST.
No GitHub API call, no token.

  python3 eval/fetch_skills.py ~/kalascan-skills [corpus.json]
  python3 eval/run_eval.py --skills ~/kalascan-skills ...
"""

import concurrent.futures as cf
import json
import os
import shutil
import subprocess
import sys
import tempfile


def fetch(target, dest):
    try:
        return fetch_one(target, dest)
    except (OSError, subprocess.SubprocessError) as e:
        return f"failed: {e}"


def fetch_one(target, dest):
    out = os.path.normpath(os.path.join(dest, target))
    if os.path.isdir(out):
        return "had"
    owner, repo, commit, path = target.split("/", 3)
    git = ["git", "-c", "core.symlinks=false", "-c", "advice.detachedHead=false"]
    with tempfile.TemporaryDirectory(dir=dest) as tmp:
        steps = [
            ["init", "-q", tmp],
            ["-C", tmp, "remote", "add", "origin", f"https://github.com/{owner}/{repo}.git"],
            ["-C", tmp, "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", commit],
            *([] if path == "." else [["-C", tmp, "sparse-checkout", "set", "--no-cone", f"/{path}/"]]),
            ["-C", tmp, "checkout", "-q", "FETCH_HEAD"],
        ]
        for step in steps:
            proc = subprocess.run(git + step, capture_output=True, text=True, timeout=600)
            if proc.returncode:
                return f"failed: {(proc.stderr.strip().splitlines() or ['git ' + step[2]])[-1][:120]}"
        shutil.rmtree(os.path.join(tmp, ".git"))
        os.makedirs(os.path.dirname(out), exist_ok=True)
        os.rename(os.path.join(tmp, path) if path != "." else tmp, out)
        if path == ".":
            os.makedirs(tmp)  # TemporaryDirectory removes it on exit
    return "fetched"


def main():
    dest = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else sys.exit(__doc__))
    os.makedirs(dest, exist_ok=True)
    corpus = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus.json")
    targets = [s["target"] for s in json.load(open(corpus))["samples"] if s["source"] == "skills"]
    with cf.ThreadPoolExecutor(6) as pool:
        for target, result in zip(targets, pool.map(lambda t: fetch(t, dest), targets)):
            if result not in ("fetched", "had"):
                print(target, result, file=sys.stderr)
    print(f"{len(targets)} skills in {dest}")


main()
