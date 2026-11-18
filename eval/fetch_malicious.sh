#!/usr/bin/env bash
# Fetch only the malicious samples listed in eval/corpus.json from the
# DataDog malicious-software-packages-dataset (blobless clone: ~60 files,
# not 30k). Samples are LIVE MALWARE: never extract them outside a scratch
# directory and never execute them. run_eval.py only scans them statically.
#
# With a second directory, also the samples listed from pypi_malregistry
# (source "malregistry": an independent second source, PyPI only).
#
# usage: eval/fetch_malicious.sh <dest-dir> [<malregistry-dir>]
set -euo pipefail

dest=${1:?usage: eval/fetch_malicious.sh <dest-dir> [<malregistry-dir>]}
here=$(cd "$(dirname "$0")" && pwd)

if [ ! -d "$dest/.git" ]; then
  git clone -q --filter=blob:none --no-checkout --depth 1 \
    https://github.com/DataDog/malicious-software-packages-dataset.git "$dest"
fi

python3 -I -c '
import json, sys
for s in json.load(open(sys.argv[1]))["samples"]:
    if s["source"] == "dataset":
        print(s["target"])
' "$here/corpus.json" | tr '\n' '\0' | xargs -0 git -C "$dest" checkout HEAD --

echo "fetched into $dest/samples"

if [ -n "${2:-}" ]; then
  if [ ! -d "$2/.git" ]; then
    git clone -q --filter=blob:none --no-checkout --depth 1 \
      https://github.com/lxyeternal/pypi_malregistry.git "$2"
  fi
  python3 -I -c '
import json, sys
for s in json.load(open(sys.argv[1]))["samples"]:
    if s["source"] == "malregistry":
        print(s["target"])
' "$here/corpus.json" | tr '\n' '\0' | xargs -0 -r git -C "$2" checkout HEAD --
  echo "fetched into $2"
fi
