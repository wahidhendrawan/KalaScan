#!/usr/bin/env python3
"""Regenerate rules/secrets.toml from gitleaks' default config (MIT).

Loaded only with `kalascan scan --secrets`: a hard-coded token in a package
is a leak, not malware, so these rules are medium and never join a chain.

  python3 rules/gen_secret_rules.py > rules/secrets.toml

Skipped, so the generated rules stand on their own:
  - rules keyed on a file path instead of a regex (KalaScan scans contents);
  - rules whose accuracy depends on a gitleaks allowlist, which this format
    does not carry (generic-api-key among them; KalaScan's own Generic API
    Key rule covers that ground).
"""

import json
import sys
import tomllib
import urllib.request

REF = "v8.30.1"
URL = f"https://raw.githubusercontent.com/gitleaks/gitleaks/{REF}/config/gitleaks.toml"

# Rules the Rust regex crate cannot compile within its default size limit
# (long counted repetitions such as {50,1000}). Found by compiling each
# generated rule on its own.
INCOMPATIBLE: set[str] = {"pypi-upload-token", "vault-batch-token"}


def toml_literal(s: str) -> str:
    if "'''" not in s and "\n" not in s:
        return f"'''{s}'''"
    return json.dumps(s)


def main() -> None:
    src = sys.argv[1] if len(sys.argv) > 1 else URL
    raw = open(src, "rb").read() if not src.startswith("http") else urllib.request.urlopen(src, timeout=60).read()
    config = tomllib.loads(raw.decode())
    kept, skipped = [], []
    for r in config["rules"]:
        reason = (
            "no regex" if "regex" not in r
            else "path rule" if "path" in r
            else "needs allowlist" if r.get("allowlists")
            else "regex too large for Rust" if r["id"] in INCOMPATIBLE
            else None
        )
        if reason:
            skipped.append((r["id"], reason))
            continue
        kept.append(r)

    out = [
        "# Secret patterns generated from gitleaks " + REF + " (config/gitleaks.toml)",
        "# by rules/gen_secret_rules.py. Do not edit by hand.",
        "#",
        "# Copyright (c) 2019 Zachary Rice",
        "#",
        "# Permission is hereby granted, free of charge, to any person obtaining a copy",
        "# of this software and associated documentation files (the \"Software\"), to deal",
        "# in the Software without restriction, including without limitation the rights",
        "# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell",
        "# copies of the Software, and to permit persons to whom the Software is",
        "# furnished to do so, subject to the following conditions:",
        "#",
        "# The above copyright notice and this permission notice shall be included in all",
        "# copies or substantial portions of the Software.",
        "#",
        "# THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR",
        "# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,",
        "# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE",
        "# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER",
        "# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,",
        "# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE",
        "# SOFTWARE.",
        "#",
        f"# {len(kept)} rules kept, {len(skipped)} skipped: "
        + ", ".join(f"{i} ({why})" for i, why in skipped),
        "",
    ]
    for r in kept:
        out += [
            "[[rule]]",
            f'id = "GL-{r["id"]}"',
            f'name = "Secret: {r["id"]}"',
            'severity = "medium"',
            'category = "secret"',
            f"description = {json.dumps(r['description'])}",
            f"pattern = {toml_literal(r['regex'])}",
        ]
        if "entropy" in r:
            out.append(f"entropy = {float(r['entropy'])}")
        if "secretGroup" in r:
            out.append(f"secret_group = {int(r['secretGroup'])}")
        if r.get("keywords"):
            out.append("keywords = " + json.dumps([k.lower() for k in r["keywords"]]))
        out.append("")
    sys.stdout.write("\n".join(out))
    print(f"{len(kept)} rules, {len(skipped)} skipped", file=sys.stderr)


if __name__ == "__main__":
    main()
