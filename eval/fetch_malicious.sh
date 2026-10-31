#!/usr/bin/env bash
# Fetch only the malicious samples listed in eval/corpus.json from the
# DataDog malicious-software-packages-dataset (blobless clone: ~60 files,
# not 30k). Samples are LIVE MALWARE: never extract them outside a scratch
# directory and never execute them. run_eval.py only scans them statically.
#
# usage: eval/fetch_malicious.sh <dest-dir>
set -euo pipefail

dest=${1:?usage: eval/fetch_malicious.sh <dest-dir>}
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
' "$here/corpus.json" | xargs git -C "$dest" checkout HEAD --

echo "fetched into $dest/samples"
