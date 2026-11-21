#!/usr/bin/env python3
"""Fetch the npm samples listed in eval/corpus.json (source "npmstudy") from
the replication package of "How Effective Are NPM Malicious Package
Detectors? A Large-Scale Empirical Study" (ASE 2026, CC BY 4.0):
https://doi.org/10.6084/m9.figshare.31869370

The archive is 4.8 GB; only the listed tarballs are read out of it, through
HTTP range requests. Samples are LIVE MALWARE: extract them in a throwaway
VM only, never execute them. run_eval.py only scans them statically.

  python3 eval/fetch_npmstudy.py DEST          # the corpus entries, into DEST
  python3 eval/fetch_npmstudy.py --list FILE   # every malicious tarball's path, for sample_malicious.py
"""

import argparse
import io
import json
import os
import urllib.request
import zipfile

URL = "https://ndownloader.figshare.com/files/66774704"
PREFIX = "NPMStudy/Dataset/zip_malware/"
# The storage behind Figshare answers 403 to Python's default User-Agent.
UA = "kalascan-eval"


class Remote(io.RawIOBase):
    """A seekable view of a remote file, one range request per read."""

    def __init__(self, url):
        req = urllib.request.Request(url, headers={"Range": "bytes=0-0", "User-Agent": UA})
        with urllib.request.urlopen(req, timeout=60) as r:
            self.size = int(r.headers["Content-Range"].rsplit("/", 1)[1])
        # Every read goes through the redirect: the signed URL it gives does not take a second request.
        self.url, self.pos = url, 0

    def seekable(self):
        return True

    def readable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, off, whence=0):
        self.pos = {0: off, 1: self.pos + off, 2: self.size + off}[whence]
        return self.pos

    def readinto(self, b):
        if self.pos >= self.size or not len(b):
            return 0
        end = min(self.pos + len(b), self.size) - 1
        req = urllib.request.Request(self.url, headers={"Range": f"bytes={self.pos}-{end}", "User-Agent": UA})
        with urllib.request.urlopen(req, timeout=120) as r:
            data = r.read()
        b[: len(data)] = data
        self.pos += len(data)
        return len(data)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dest", nargs="?")
    ap.add_argument("--list", metavar="FILE", help="write the path of every malicious tarball in the archive")
    ap.add_argument("--corpus", default=os.path.join(os.path.dirname(__file__), "corpus.json"))
    args = ap.parse_args()
    if not args.dest and not args.list:
        ap.error("give DEST or --list FILE")

    z = zipfile.ZipFile(io.BufferedReader(Remote(URL), buffer_size=1 << 20))
    if args.list:
        names = [n for n in z.namelist() if n.startswith(PREFIX) and n.endswith(".tgz")]
        open(args.list, "w").write("\n".join(names) + "\n")
        print(len(names), "tarballs listed in", args.list)
        return
    want = [s["target"] for s in json.load(open(args.corpus))["samples"] if s["source"] == "npmstudy"]
    for name in want:
        out = os.path.join(args.dest, name)
        if not os.path.exists(out):
            # Aside first: a run killed half-way must not leave a truncated file that looks fetched.
            part = z.extract(name, os.path.join(args.dest, ".partial"))  # zipfile drops `..` and absolute member names
            os.makedirs(os.path.dirname(out), exist_ok=True)
            os.replace(part, out)
    print(f"{len(want)} samples in {args.dest}")


main()
