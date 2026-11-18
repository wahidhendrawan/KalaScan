use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
}

/// Names and tactics follow Enterprise ATT&CK v20.1 (2026-11): the Defense
/// Evasion tactic is split into Stealth and Defense Impairment, and the
/// T1562 family moved to T1685.
const TECHNIQUE_TABLE: &[(&str, &str, &str)] = &[
    ("T1001", "Data Obfuscation", "Command and Control"),
    ("T1005", "Data from Local System", "Collection"),
    ("T1008", "Fallback Channels", "Command and Control"),
    ("T1014", "Rootkit", "Stealth"),
    (
        "T1016",
        "System Network Configuration Discovery",
        "Discovery",
    ),
    ("T1021", "Remote Services", "Lateral Movement"),
    ("T1025", "Data from Removable Media", "Collection"),
    ("T1027", "Obfuscated Files or Information", "Stealth"),
    ("T1027.002", "Software Packing", "Stealth"),
    ("T1027.009", "Embedded Payloads", "Stealth"),
    ("T1027.010", "Command Obfuscation", "Stealth"),
    ("T1027.013", "Encrypted/Encoded File", "Stealth"),
    ("T1033", "System Owner/User Discovery", "Discovery"),
    ("T1036", "Masquerading", "Stealth"),
    (
        "T1036.005",
        "Match Legitimate Resource Name or Location",
        "Stealth",
    ),
    ("T1039", "Data from Network Shared Drive", "Collection"),
    ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    (
        "T1048",
        "Exfiltration Over Alternative Protocol",
        "Exfiltration",
    ),
    ("T1053.005", "Scheduled Task", "Persistence"),
    ("T1055", "Process Injection", "Stealth"),
    ("T1056.001", "Keylogging", "Collection"),
    ("T1059", "Command and Scripting Interpreter", "Execution"),
    ("T1059.001", "PowerShell", "Execution"),
    ("T1059.004", "Unix Shell", "Execution"),
    ("T1059.006", "Python", "Execution"),
    ("T1059.007", "JavaScript", "Execution"),
    (
        "T1068",
        "Exploitation for Privilege Escalation",
        "Privilege Escalation",
    ),
    ("T1070", "Indicator Removal", "Stealth"),
    ("T1070.003", "Clear Command History", "Stealth"),
    ("T1070.004", "File Deletion", "Stealth"),
    ("T1070.006", "Timestomp", "Stealth"),
    ("T1071", "Application Layer Protocol", "Command and Control"),
    ("T1071.001", "Web Protocols", "Command and Control"),
    ("T1071.004", "DNS", "Command and Control"),
    ("T1074", "Data Staged", "Collection"),
    ("T1082", "System Information Discovery", "Discovery"),
    ("T1083", "File and Directory Discovery", "Discovery"),
    ("T1087", "Account Discovery", "Discovery"),
    ("T1090", "Proxy", "Command and Control"),
    (
        "T1095",
        "Non-Application Layer Protocol",
        "Command and Control",
    ),
    ("T1102", "Web Service", "Command and Control"),
    ("T1104", "Multi-Stage Channels", "Command and Control"),
    ("T1105", "Ingress Tool Transfer", "Command and Control"),
    ("T1106", "Native API", "Execution"),
    ("T1112", "Modify Registry", "Defense Impairment"),
    ("T1113", "Screen Capture", "Collection"),
    ("T1115", "Clipboard Data", "Collection"),
    ("T1119", "Automated Collection", "Collection"),
    ("T1123", "Audio Capture", "Collection"),
    ("T1125", "Video Capture", "Collection"),
    ("T1129", "Shared Modules", "Execution"),
    ("T1132", "Data Encoding", "Command and Control"),
    (
        "T1140",
        "Deobfuscate/Decode Files or Information",
        "Stealth",
    ),
    ("T1176", "Software Extensions", "Persistence"),
    (
        "T1195.001",
        "Compromise Software Dependencies and Development Tools",
        "Initial Access",
    ),
    (
        "T1195.002",
        "Compromise Software Supply Chain",
        "Initial Access",
    ),
    ("T1203", "Exploitation for Client Execution", "Execution"),
    ("T1204", "User Execution", "Execution"),
    ("T1204.002", "Malicious File", "Execution"),
    ("T1205", "Traffic Signaling", "Command and Control"),
    ("T1218", "System Binary Proxy Execution", "Stealth"),
    ("T1218.011", "Rundll32", "Stealth"),
    (
        "T1222",
        "File and Directory Permissions Modification",
        "Defense Impairment",
    ),
    ("T1480", "Execution Guardrails", "Stealth"),
    ("T1485", "Data Destruction", "Impact"),
    ("T1486", "Data Encrypted for Impact", "Impact"),
    ("T1490", "Inhibit System Recovery", "Impact"),
    ("T1497", "Virtualization/Sandbox Evasion", "Stealth"),
    (
        "T1528",
        "Steal Application Access Token",
        "Credential Access",
    ),
    ("T1539", "Steal Web Session Cookie", "Credential Access"),
    ("T1542", "Pre-OS Boot", "Persistence"),
    ("T1542.001", "System Firmware", "Persistence"),
    ("T1543.002", "Systemd Service", "Persistence"),
    ("T1543.003", "Windows Service", "Persistence"),
    ("T1546", "Event Triggered Execution", "Persistence"),
    (
        "T1546.004",
        "Unix Shell Configuration Modification",
        "Persistence",
    ),
    (
        "T1547.001",
        "Registry Run Keys / Startup Folder",
        "Persistence",
    ),
    ("T1552", "Unsecured Credentials", "Credential Access"),
    ("T1552.001", "Credentials In Files", "Credential Access"),
    ("T1552.004", "Private Keys", "Credential Access"),
    (
        "T1555",
        "Credentials from Password Stores",
        "Credential Access",
    ),
    (
        "T1555.003",
        "Credentials from Web Browsers",
        "Credential Access",
    ),
    ("T1557", "Adversary-in-the-Middle", "Credential Access"),
    ("T1560", "Archive Collected Data", "Collection"),
    ("T1560.001", "Archive via Utility", "Collection"),
    ("T1564", "Hide Artifacts", "Stealth"),
    ("T1564.001", "Hidden Files and Directories", "Stealth"),
    ("T1566", "Phishing", "Initial Access"),
    ("T1566.001", "Spearphishing Attachment", "Initial Access"),
    ("T1567", "Exfiltration Over Web Service", "Exfiltration"),
    ("T1567.004", "Exfiltration Over Webhook", "Exfiltration"),
    ("T1568", "Dynamic Resolution", "Command and Control"),
    (
        "T1568.002",
        "Domain Generation Algorithms",
        "Command and Control",
    ),
    ("T1571", "Non-Standard Port", "Command and Control"),
    ("T1572", "Protocol Tunneling", "Command and Control"),
    ("T1573", "Encrypted Channel", "Command and Control"),
    ("T1620", "Reflective Code Loading", "Stealth"),
    ("T1622", "Debugger Evasion", "Stealth"),
    ("T1657", "Financial Theft", "Impact"),
    ("T1685", "Disable or Modify Tools", "Defense Impairment"),
    (
        "T1685.005",
        "Clear Windows Event Logs",
        "Defense Impairment",
    ),
    (
        "T1685.006",
        "Clear Linux or Mac System Logs",
        "Defense Impairment",
    ),
];

static TECHNIQUES: LazyLock<BTreeMap<&'static str, AttackTechnique>> = LazyLock::new(|| {
    TECHNIQUE_TABLE
        .iter()
        .map(|(id, name, tactic)| {
            (
                *id,
                AttackTechnique {
                    id: (*id).to_string(),
                    name: (*name).to_string(),
                    tactic: (*tactic).to_string(),
                },
            )
        })
        .collect()
});

pub fn lookup(id: &str) -> Option<AttackTechnique> {
    let id = id.trim();
    if let Some(found) = TECHNIQUES.get(id) {
        return Some(found.clone());
    }
    let base = id.split('.').next()?;
    TECHNIQUES.get(base).cloned().map(|mut found| {
        found.id = id.to_string();
        found
    })
}

pub fn merge(into: &mut Vec<AttackTechnique>, incoming: impl IntoIterator<Item = AttackTechnique>) {
    for technique in incoming {
        if !into.iter().any(|existing| existing.id == technique.id) {
            into.push(technique);
        }
    }
}

fn add(out: &mut Vec<AttackTechnique>, id: &str) {
    if out.iter().any(|existing| existing.id == id) {
        return;
    }
    if let Some(technique) = lookup(id) {
        out.push(technique);
    }
}

/// Short alphanumeric keywords must be whole words: as substrings, `etw`
/// matched "n*etw*ork" and mapped every network rule to Impair Defenses.
fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| {
        if needle.len() > 4 || !needle.chars().all(|c| c.is_ascii_alphanumeric()) {
            return haystack.contains(needle);
        }
        let bytes = haystack.as_bytes();
        haystack.match_indices(needle).any(|(i, _)| {
            let before = i.checked_sub(1).map(|j| bytes[j]);
            let after = bytes.get(i + needle.len()).copied();
            !before.is_some_and(|b| b.is_ascii_alphanumeric())
                && !after.is_some_and(|b| b.is_ascii_alphanumeric())
        })
    })
}

pub fn map_text(text: &str) -> Vec<AttackTechnique> {
    let text = text.to_ascii_lowercase();
    let mut out = Vec::new();

    if contains_any(
        &text,
        &[
            "discord",
            "telegram",
            "slack",
            "webhook",
            "hardcoded ip",
            "command and control",
            "c2 ",
            "raw socket",
            "reverse shell",
            "reverseshell",
            "malicious url",
        ],
    ) {
        add(&mut out, "T1071");
        add(&mut out, "T1041");
        if contains_any(&text, &["discord", "telegram", "slack", "webhook"]) {
            add(&mut out, "T1567");
        }
    }

    if contains_any(
        &text,
        &[
            "credential",
            "password",
            "api key",
            "secret",
            "token",
            "ssh key",
            "aws ",
            "github token",
            "environment variable",
            ".env",
            ".npmrc",
        ],
    ) {
        add(&mut out, "T1552");
        add(&mut out, "T1552.001");
    }

    if contains_any(
        &text,
        &[
            "browser", "cookie", "session", "wallet", "keystore", "metamask", "phantom",
        ],
    ) {
        add(&mut out, "T1555");
        add(&mut out, "T1539");
        add(&mut out, "T1528");
    }

    if contains_any(
        &text,
        &["wallet", "bitcoin", "financial", "crypto theft", "drainer"],
    ) {
        add(&mut out, "T1657");
    }

    if contains_any(
        &text,
        &[
            "eval",
            "exec",
            "dynamic import",
            "dynamic code",
            "classloading",
            "reflection",
            "scripting",
            "function constructor",
        ],
    ) {
        add(&mut out, "T1059");
        add(&mut out, "T1027");
        add(&mut out, "T1620");
    }

    if contains_any(
        &text,
        &[
            "base64",
            "b64",
            "hex encoding",
            "hex string",
            "hex-encoded",
            "xor decode",
            "encoded command",
            "long encoded",
            "obfuscat",
        ],
    ) {
        add(&mut out, "T1027");
        add(&mut out, "T1140");
    }

    if contains_any(&text, &["injection", "reflective dll"]) {
        add(&mut out, "T1055");
        add(&mut out, "T1620");
    }

    if contains_any(
        &text,
        &["ransom", "mass file encryption", "encrypted file extension"],
    ) {
        add(&mut out, "T1486");
        add(&mut out, "T1490");
    }

    if contains_any(&text, &["shadow copy"]) {
        add(&mut out, "T1490");
    }

    if contains_any(
        &text,
        &[
            "post-install",
            "typo-squat",
            "supply chain",
            "malicious package",
            "install hook",
            "install-time",
            "dependency confusion",
            "side-loading",
            "manifest confusion",
            "install script",
            "provenance",
            "email domain",
        ],
    ) {
        add(&mut out, "T1195.002");
        add(&mut out, "T1546");
    }

    // A poisoned skill, rule file or MCP server is a supply-chain component;
    // ATT&CK has no technique for the prompt injection itself.
    if contains_any(&text, &["agent instruction", "agent config"]) {
        add(&mut out, "T1195.002");
    }
    if contains_any(
        &text,
        &["hidden unicode", "invisible characters", "html comment"],
    ) {
        add(&mut out, "T1027");
    }
    if contains_any(&text, &["conceal"]) {
        add(&mut out, "T1564");
    }
    if contains_any(&text, &["runs remote code", "remote url dependency"]) {
        add(&mut out, "T1105");
        add(&mut out, "T1195.002");
    }
    if contains_any(&text, &["dns lookup"]) {
        add(&mut out, "T1071.004");
    }

    if contains_any(&text, &["zip slip", "remote file write"]) {
        add(&mut out, "T1203");
    }

    // A compromised CI job poisons every artifact it builds.
    if contains_any(&text, &["github actions"]) {
        add(&mut out, "T1195.002");
    }

    if contains_any(&text, &["remote script", "url fetch", "download"]) {
        add(&mut out, "T1105");
    }

    if contains_any(&text, &["exfiltration"]) {
        add(&mut out, "T1041");
        if contains_any(&text, &["exfiltration service"]) {
            add(&mut out, "T1567");
        }
    }

    if contains_any(&text, &["reconnaissance", "system discovery", "ip lookup"]) {
        add(&mut out, "T1082");
        add(&mut out, "T1016");
    }

    if contains_any(&text, &["account enumeration", "system discovery"]) {
        add(&mut out, "T1087");
        add(&mut out, "T1033");
    }

    if contains_any(&text, &["shell profile"]) {
        add(&mut out, "T1546.004");
    }

    if contains_any(&text, &["traffic hijack", "base url override"]) {
        add(&mut out, "T1557");
    }

    if contains_any(&text, &["clipboard"]) {
        add(&mut out, "T1115");
    }

    if contains_any(&text, &["workspace file", "file reading", "discovery"]) {
        add(&mut out, "T1005");
        add(&mut out, "T1083");
    }

    if contains_any(&text, &["wildcard activation"]) {
        add(&mut out, "T1204");
        add(&mut out, "T1546");
    }

    if contains_any(
        &text,
        &[
            "process execution",
            "execut",
            "process start",
            "process spawn",
            "subprocess",
            "os.system",
            "child_process",
            "os.popen",
            "powershell",
            "shell command",
        ],
    ) {
        add(&mut out, "T1059");
        if contains_any(&text, &["powershell"]) {
            add(&mut out, "T1059.001");
        }
        if contains_any(&text, &["python"]) {
            add(&mut out, "T1059.006");
        }
        if contains_any(&text, &["javascript", "node.js"]) {
            add(&mut out, "T1059.007");
        }
    }

    if contains_any(&text, &["keystroke", "keylog"]) {
        add(&mut out, "T1056.001");
    }

    if contains_any(&text, &["packer", "packed"]) {
        add(&mut out, "T1027.002");
    }

    if contains_any(&text, &["high entropy", "entropy"]) {
        add(&mut out, "T1027.013");
    }

    if contains_any(&text, &["anti-debug", "debugger"]) {
        add(&mut out, "T1622");
    }

    if contains_any(&text, &["virtual machine", "sandbox", "virtualization"]) {
        add(&mut out, "T1497");
    }

    if contains_any(&text, &["timestomp"]) {
        add(&mut out, "T1070.006");
    }

    if contains_any(&text, &["log clearing", "clear log", "event log"]) {
        add(&mut out, "T1070");
    }

    if contains_any(
        &text,
        &["amsi", "etw", "disable security", "impair defense"],
    ) {
        add(&mut out, "T1685");
    }

    // Not "registry" or "service": those named the npm registry and
    // exfiltration services, which became Windows Run Keys / Services.
    if contains_any(
        &text,
        &["startup", "scheduled task", "run key", "windows service"],
    ) {
        add(&mut out, "T1547.001");
        add(&mut out, "T1053.005");
        add(&mut out, "T1543.003");
    }

    if contains_any(&text, &["rootkit"]) {
        add(&mut out, "T1014");
    }

    if contains_any(&text, &["wiper", "data destruction"]) {
        add(&mut out, "T1485");
    }

    if contains_any(&text, &["phishing", "spearphish"]) {
        add(&mut out, "T1566");
    }

    if contains_any(
        &text,
        &[
            "impersonation",
            "name spoofing",
            "repackaged",
            "vendor repository",
        ],
    ) {
        add(&mut out, "T1036.005");
    }

    if contains_any(&text, &["masquerad"]) {
        add(&mut out, "T1036");
    }

    if contains_any(&text, &["hidden file", "hidden directory", "hide artifact"]) {
        add(&mut out, "T1564.001");
    }

    if contains_any(&text, &["file deletion", "delete file"]) {
        add(&mut out, "T1070.004");
    }

    // Not "archive": "Archive Extraction" is a zip-slip surface, not collection.
    if contains_any(&text, &["staging", "staged"]) {
        add(&mut out, "T1560");
        add(&mut out, "T1074");
    }

    if contains_any(&text, &["screen capture", "screenshot"]) {
        add(&mut out, "T1113");
    }

    if contains_any(&text, &["audio capture", "microphone"]) {
        add(&mut out, "T1123");
    }

    if contains_any(&text, &["video capture", "camera"]) {
        add(&mut out, "T1125");
    }

    if contains_any(&text, &["dns"]) {
        add(&mut out, "T1071.004");
    }

    if contains_any(&text, &["proxy"]) {
        add(&mut out, "T1090");
    }

    if contains_any(&text, &["dga", "domain generation"]) {
        add(&mut out, "T1568.002");
    }

    if contains_any(&text, &["non-standard port"]) {
        add(&mut out, "T1571");
    }

    if contains_any(&text, &["tunnel"]) {
        add(&mut out, "T1572");
    }

    if contains_any(&text, &["native api"]) {
        add(&mut out, "T1106");
    }

    if contains_any(&text, &["system binary", "rundll32"]) {
        add(&mut out, "T1218");
    }

    if contains_any(&text, &["permission modification"]) {
        add(&mut out, "T1222");
    }

    if contains_any(&text, &["execution guardrail"]) {
        add(&mut out, "T1480");
    }

    if contains_any(&text, &["firmware", "bootkit"]) {
        add(&mut out, "T1542");
    }

    if contains_any(&text, &["automated collection"]) {
        add(&mut out, "T1119");
    }

    if contains_any(&text, &["removable media", "usb"]) {
        add(&mut out, "T1025");
    }

    if contains_any(&text, &["network share", "smb"]) {
        add(&mut out, "T1039");
    }

    if contains_any(&text, &["remote service", "lateral movement"]) {
        add(&mut out, "T1021");
    }

    if contains_any(&text, &["web service"]) {
        add(&mut out, "T1102");
        add(&mut out, "T1567");
    }

    if contains_any(&text, &["fallback channel"]) {
        add(&mut out, "T1008");
    }

    if contains_any(&text, &["multi-stage"]) {
        add(&mut out, "T1104");
    }

    if contains_any(&text, &["traffic signaling"]) {
        add(&mut out, "T1205");
    }

    if contains_any(&text, &["data encoding"]) {
        add(&mut out, "T1132");
    }

    if contains_any(&text, &["privilege escalation", "exploit"]) {
        add(&mut out, "T1068");
    }

    out.truncate(6);
    out
}

/// Techniques of KalaScan's own findings, by name. Written out rather than
/// guessed from keywords (`map_text`), so each line can be checked against
/// attack.mitre.org. An empty list is deliberate: the finding is a
/// capability, a listing fact or a weakness, not an adversary technique.
#[rustfmt::skip]
const FINDING_TABLE: &[(&str, &[&str])] = &[
    // rules/builtin.toml
    ("Discord Webhook", &["T1567.004"]),
    ("Telegram Bot API Token", &["T1567", "T1102"]),
    ("Slack Webhook", &["T1567.004"]),
    ("Hardcoded IP Address", &["T1071"]),
    ("AWS Access Key", &["T1552.001"]),
    ("AWS Secret Key", &["T1552.001"]),
    ("GitHub Token", &["T1552.001"]),
    ("Generic API Key", &["T1552.001"]),
    ("Generic Webhook URL", &["T1567.004"]),
    ("Slack Bot Token", &["T1552.001"]),
    ("Browser Profile Access", &["T1555.003", "T1539"]),
    ("Crypto Wallet Access", &["T1005", "T1657"]),
    ("Password Manager Access", &["T1555", "T1552.001"]),
    ("Browser Database Access", &["T1539", "T1555.003"]),
    ("Discord Token Harvesting", &["T1528"]),
    ("SSH Key Access", &["T1552.004"]),
    ("Environment Variable Dump", &["T1552"]),
    ("eval() Usage", &["T1059"]),
    ("exec() Usage", &["T1059"]),
    ("b64decode + exec Chain", &["T1140", "T1059.006"]),
    ("nested b64decode", &["T1027", "T1140"]),
    ("child_process (Node.js)", &["T1059"]),
    ("subprocess (Python)", &["T1059"]),
    ("os.system", &["T1059"]),
    ("PowerShell Encoded Command", &["T1059.001", "T1027.010"]),
    ("Base64 Overuse", &["T1027"]),
    ("Dynamic Import/Load", &["T1620"]),
    ("Hex Encoding", &["T1027"]),
    ("XOR Decode Pattern", &["T1027", "T1140"]),
    ("Long Encoded String", &["T1027"]),
    ("os.popen", &["T1059"]),
    ("Process Injection", &["T1055"]),
    ("Reflective DLL Loading", &["T1620", "T1055"]),
    ("Mass File Encryption", &["T1486"]),
    ("Shadow Copy Deletion", &["T1490"]),
    ("Encrypted File Extension", &["T1486"]),
    ("Ransom Note", &["T1486"]),
    ("Bitcoin Payment Address", &["T1657"]),
    ("Post-Install Script", &["T1195.001"]),
    ("Local Network Server", &[]),
    ("HTTP File Upload Handler", &[]),
    ("Archive Extraction", &[]),
    ("Remote Script Download", &["T1105"]),
    ("URL Fetch Command", &["T1105"]),
    ("Hidden Directory Script", &["T1564.001"]),
    ("VS Code Session/Token Stealing", &["T1528"]),
    ("VS Code Clipboard Harvesting", &["T1115"]),
    ("VS Code Workspace File Reading", &["T1005"]),
    ("Installed Extension Tampering", &["T1176"]),
    ("VS Code Wildcard Activation", &["T1176"]),
    ("JetBrains Dynamic Classloading", &["T1620"]),
    ("JetBrains Process Execution", &["T1059"]),
    ("JetBrains Malicious Reflection", &["T1620"]),
    ("JetBrains Raw Socket Exfiltration", &["T1095"]),
    ("Browser Extension Dangerous Permissions", &["T1176"]),
    ("Browser Extension Dynamic Code Execution", &["T1059.007"]),
    ("Browser Extension Keystroke Logger", &["T1056.001"]),
    ("Browser Extension Cookie/Token Theft", &["T1539"]),
    ("Exfiltration Service Endpoint", &["T1567"]),
    ("Public IP URL", &["T1071.001"]),
    ("IP Lookup Service", &["T1016"]),
    ("Host Reconnaissance", &["T1082", "T1033"]),
    ("Remote Executable Download", &["T1105"]),
    ("Shell Process Start", &["T1059.004"]),
    ("Raw Socket Connection", &["T1095"]),
    ("Detached Process Spawn", &["T1059"]),
    ("Make File Executable", &["T1222"]),
    ("Obfuscator.io Output", &["T1027"]),
    ("Wallet Seed / Private Key Handling", &["T1552.004", "T1657"]),
    ("setup.py Install Hook Override", &["T1195.001"]),
    ("setup.py Install-time Execution", &["T1195.001", "T1059"]),
    ("setup.py Payload Decode/Fetch", &["T1195.001", "T1140", "T1105"]),
    ("Download Cradle (fetch piped to interpreter)", &["T1105", "T1059"]),
    ("Function Constructor with require", &["T1059.007", "T1027"]),
    ("Escaped eval Payload", &["T1027", "T1059"]),
    ("VS Code Extension Side-loading", &["T1176"]),
    ("Account Enumeration Command", &["T1087", "T1033"]),
    ("AI API Base URL Override", &["T1557"]),
    ("Shell Profile Modification", &["T1546.004"]),
    ("npm Publish from Code", &["T1195.001"]),
    ("Download Cradle (fetch then eval)", &["T1105", "T1059"]),
    ("Hex String Decoder", &["T1027", "T1140"]),
    ("GitLab Token", &["T1552.001"]),
    ("JWT Token", &["T1552.001"]),
    ("Azure Storage Connection String", &["T1552.001"]),
    ("GCP Service Account Key", &["T1552.001"]),
    ("Private Key Material", &["T1552.004"]),
    ("Database Connection String with Password", &["T1552.001"]),
    ("Hex-Encoded API Name", &["T1027"]),
    ("Char-Code Encoded API Name", &["T1027"]),
    ("Base64-Encoded URL", &["T1027"]),
    ("Buffer Decode + eval", &["T1140", "T1059.007"]),
    ("Install Script Network Command", &["T1195.001", "T1105"]),
    ("Install Script Host Reconnaissance", &["T1195.001", "T1082", "T1033"]),
    ("DNS Lookup of Built Hostname", &["T1071.004", "T1048"]),
    ("Python Import-Obfuscated Loader", &["T1027", "T1140"]),
    ("Decrypted Code Executed", &["T1140", "T1059.006"]),
    ("Builtin Name Built From Characters", &["T1027"]),
    ("Code Imported From Disguised Archive", &["T1027", "T1036"]),
    ("Systemd User Service Installed", &["T1543.002"]),
    ("npm Maintainer Package Enumeration", &["T1195.001"]),
    // Raised by code (taxonomy::CODE_FINDINGS). Instructions aimed at an AI
    // agent have no Enterprise technique (ATLAS AML.T0051 is theirs).
    ("Agent Instruction: Hidden Unicode Tag Text", &["T1027"]),
    ("Agent Instruction: Invisible Characters", &["T1027"]),
    ("Agent Instruction: Directive in HTML Comment", &["T1564"]),
    ("Agent Instruction: Conceal Action from User", &["T1564"]),
    ("Agent Instruction: Override Prior Instructions", &[]),
    ("Agent Instruction: Credential or Agent Config Path", &["T1552.001"]),
    ("Chain: Malicious Agent Instruction", &[]),
    ("Chain: Agent Config Runs Remote Code", &["T1105", "T1059"]),
    ("Zip Slip: Archive Extraction Without Path Validation", &[]),
    ("Chain: Credential Exfiltration", &["T1552", "T1041"]),
    ("Chain: Download and Execute", &["T1105", "T1059"]),
    ("Chain: Remote File Write via Local Server", &[]),
    ("Chain: Reverse Shell", &["T1059", "T1095"]),
    ("Chain: Drop and Execute Binary", &["T1105", "T1059"]),
    ("Chain: Install-time Exfiltration", &["T1195.001", "T1041"]),
    ("Chain: Reconnaissance Beacon", &["T1082", "T1041"]),
    ("Chain: Obfuscated Process Execution", &["T1027", "T1059"]),
    ("Chain: Install-time Payload Execution", &["T1195.001", "T1059"]),
    ("Chain: Install-time Reconnaissance", &["T1195.001", "T1082"]),
    ("Chain: Remote Code Execution", &["T1105", "T1059"]),
    ("Chain: Extension Side-loading", &["T1176"]),
    ("Chain: System Discovery", &["T1082", "T1087"]),
    ("Chain: AI API Traffic Hijack", &["T1557"]),
    ("Chain: Registry Spam Publisher", &["T1195.001"]),
    ("Chain: Obfuscated Reconnaissance", &["T1027", "T1082"]),
    ("Chain: Ransomware", &["T1486"]),
    ("Chain: Phishing Redirect Package", &["T1566"]),
    ("Chain: Dependency Confusion Install Hook", &["T1195.001"]),
    ("Chain: Install-time Persistence", &["T1195.001", "T1543.002"]),
    ("Chain: npm Worm", &["T1195.001", "T1552.001"]),
    ("Chain: Web Page Published as a Package", &["T1566", "T1036"]),
    ("Package Entry Point Is a Web Page", &[]),
    ("Chain: Obfuscated Credential Theft", &["T1027", "T1552"]),
    ("Chain: Obfuscated Download and Execute", &["T1027", "T1105", "T1059"]),
    ("Chain: Install-time Credential Access (sandbox)", &["T1195.001", "T1552"]),
    ("Dependency Confusion Version", &["T1195.001"]),
    ("Remote URL Dependency", &["T1195.001", "T1105"]),
    ("Known Malicious URL (URLhaus)", &["T1071.001"]),
    ("Extension Name Spoofing (invisible characters)", &["T1036"]),
    ("Publisher Impersonation (look-alike name)", &["T1036.005"]),
    ("Possible Brand Impersonation", &["T1036.005"]),
    ("Unverified Publisher", &[]),
    ("Low Install Count", &[]),
    ("Recently Published Extension", &[]),
    ("Repackaged Copy of Popular Extension", &["T1036.005"]),
    ("AI Vendor Repository Under Another Publisher", &["T1036.005"]),
    ("npm Manifest Confusion", &["T1195.001", "T1036"]),
    ("Install Script Added in This Version", &["T1195.001"]),
    ("New Dependencies in This Version", &["T1195.001"]),
    ("npm Provenance Dropped", &["T1195.001"]),
    ("Maintainer Email Domain Unregistered", &["T1195.001"]),
    ("GitHub Actions Pwn Request (pull_request_target + PR checkout)", &["T1195.002"]),
    ("GitHub Actions Script Injection", &["T1195.002", "T1059"]),
    ("GitHub Actions Unpinned Third-Party Action", &["T1195.001"]),
    ("GitHub Actions Spoofable Bot Check (github.actor)", &["T1195.002"]),
    ("Typo-squat Suspect", &["T1195.001", "T1036.005"]),
    ("Trojan Source Bi-Directional Character (CVE-2021-42574)", &["T1027"]),
    ("Confusable Homoglyph Character (Supply Chain Spoofing)", &["T1036"]),
    ("High-Entropy Suspicious Blob", &["T1027.013"]),
    ("Invisible Zero-Width Character (Steganography/Obfuscation)", &["T1027"]),
    ("Malicious Package", &["T1195.001"]),
    ("Known Vulnerability", &[]),
];

/// The table entry for a finding name; names that carry a value
/// (`Typo-squat Suspect: x`, `… Blob (Entropy: 7.9)`) match on their prefix.
fn finding_entry(name: &str) -> Option<&'static [&'static str]> {
    FINDING_TABLE
        .iter()
        .find(|(key, _)| {
            name.strip_prefix(key).is_some_and(|rest| {
                rest.is_empty() || rest.starts_with(':') || rest.starts_with(" (")
            })
        })
        .map(|(_, ids)| *ids)
}

/// True when the finding has a written-out mapping (possibly an empty one).
#[cfg(test)]
pub fn is_mapped(name: &str) -> bool {
    finding_entry(name).is_some()
}

/// Techniques of a finding: the written-out mapping for KalaScan's own
/// findings, keywords for anything else (custom rules, YARA rule names).
pub fn for_finding(name: &str) -> Vec<AttackTechnique> {
    match finding_entry(name) {
        Some(ids) => ids.iter().filter_map(|id| lookup(id)).collect(),
        None => map_text(name),
    }
}

pub fn from_capa_meta(meta: &serde_json::Value) -> Vec<AttackTechnique> {
    let mut out = Vec::new();

    if let Some(ids) = meta.get("attack").and_then(|value| value.as_array()) {
        for value in ids {
            if let Some(raw) = value.as_str() {
                let id = raw.split_whitespace().next().unwrap_or(raw);
                add(&mut out, id);
            }
        }
    }

    if out.is_empty() {
        let name = meta
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let namespace = meta
            .get("namespace")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let description = meta
            .get("description")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        out = map_text(&format!("{} {} {}", name, namespace, description));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_out_mappings_name_real_techniques() {
        for (finding, ids) in FINDING_TABLE {
            for id in *ids {
                assert!(
                    TECHNIQUE_TABLE.iter().any(|(known, _, _)| known == id),
                    "{finding}: {id} is not in TECHNIQUE_TABLE"
                );
            }
        }
        let id = |name: &str| {
            for_finding(name)
                .into_iter()
                .map(|t| t.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            id("Typo-squat Suspect: expresss (looks like express)")[0],
            "T1195.001"
        );
        assert_eq!(
            id("High-Entropy Suspicious Blob (Entropy: 7.91)"),
            ["T1027.013"]
        );
        // A capability, not a technique; and not a prefix match for "exec() Usage".
        assert!(id("Local Network Server").is_empty());
        // Unknown names (custom rules, YARA) still go through the keywords.
        assert!(!id("YARA Rule: discord_webhook_stealer").is_empty());
    }

    #[test]
    fn table_follows_attack_v20() {
        // v19 split Defense Evasion; v20 retired T1562 and two T1070 log-clearing sub-techniques.
        const TACTICS: [&str; 15] = [
            "Reconnaissance",
            "Resource Development",
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Stealth",
            "Defense Impairment",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact",
        ];
        for (id, _, tactic) in TECHNIQUE_TABLE {
            assert!(
                TACTICS.contains(tactic),
                "{} has retired tactic {}",
                id,
                tactic
            );
            assert!(
                !id.starts_with("T1562") && *id != "T1070.001" && *id != "T1070.002",
                "{} was revoked",
                id
            );
        }
        let tools = lookup("T1685").unwrap();
        assert_eq!(
            (tools.name.as_str(), tools.tactic.as_str()),
            ("Disable or Modify Tools", "Defense Impairment")
        );
        assert_eq!(lookup("T1027").unwrap().tactic, "Stealth");
        assert_eq!(lookup("T1176").unwrap().name, "Software Extensions");
    }

    #[test]
    fn lookup_known_and_parent_technique() {
        assert_eq!(lookup("T1055").unwrap().name, "Process Injection");
        assert_eq!(
            lookup("T1059.999").unwrap().name,
            "Command and Scripting Interpreter"
        );
    }

    #[test]
    fn maps_webhook_and_credential_rules() {
        let ids: Vec<String> = map_text("Discord Webhook data exfiltration")
            .into_iter()
            .map(|t| t.id)
            .collect();
        assert!(ids.contains(&"T1071".to_string()));
        assert!(ids.contains(&"T1041".to_string()));

        let ids: Vec<String> = map_text("SSH Key Access credential file access")
            .into_iter()
            .map(|t| t.id)
            .collect();
        assert!(ids.contains(&"T1552".to_string()));
    }

    #[test]
    fn short_keywords_match_whole_words_only() {
        let ids =
            |name: &str| -> Vec<String> { map_text(name).into_iter().map(|t| t.id).collect() };
        assert!(!ids("local network server").contains(&"T1685".to_string()));
        assert!(ids("patches etw and amsi").contains(&"T1685".to_string()));
    }

    #[test]
    fn maps_new_supply_chain_findings() {
        let ids =
            |name: &str| -> Vec<String> { map_text(name).into_iter().map(|t| t.id).collect() };
        assert!(ids("Typo-squat Suspect: crossenv (looks like cross-env)")
            .contains(&"T1195.002".to_string()));
        assert!(ids("Malicious Package: MAL-2024-1 in evil@1.0").contains(&"T1195.002".to_string()));
        assert!(ids("Chain: Remote File Write via Local Server").contains(&"T1203".to_string()));
        assert_eq!(lookup("T1203").unwrap().tactic, "Execution");
    }

    #[test]
    fn every_chain_and_critical_yara_rule_maps_to_a_technique() {
        let ids =
            |name: &str| -> Vec<String> { map_text(name).into_iter().map(|t| t.id).collect() };
        for (name, expected) in [
            ("Chain: Drop and Execute Binary", "T1059"),
            ("Chain: Download and Execute", "T1105"),
            ("Chain: Remote Code Execution", "T1059"),
            ("Chain: Install-time Exfiltration", "T1041"),
            ("Chain: Install-time Payload Execution", "T1195.002"),
            ("Chain: Reconnaissance Beacon", "T1082"),
            ("Chain: System Discovery", "T1087"),
            ("Chain: Extension Side-loading", "T1195.002"),
            ("Chain: AI API Traffic Hijack", "T1557"),
            ("YARA Rule: ReverseShellGeneric", "T1071"),
            ("YARA Rule: CryptoDrainerGeneric", "T1657"),
            ("Exfiltration Service Endpoint", "T1567"),
            ("Shell Process Start", "T1059"),
            ("Repackaged Copy of Popular Extension", "T1036.005"),
            ("Shell Profile Modification", "T1546.004"),
            ("Download Cradle (fetch then eval)", "T1105"),
            ("Chain: Obfuscated Reconnaissance", "T1082"),
            ("Chain: Obfuscated Credential Theft", "T1552"),
            ("Chain: Obfuscated Download and Execute", "T1105"),
            ("Chain: Install-time Credential Access (sandbox)", "T1552"),
            ("Chain: Malicious Agent Instruction", "T1195.002"),
            ("Chain: Agent Config Runs Remote Code", "T1105"),
            ("Agent Instruction: Hidden Unicode Tag Text", "T1027"),
            ("Agent Instruction: Conceal Action from User", "T1564"),
            ("Chain: Install-time Reconnaissance", "T1082"),
            ("Install Script Network Command", "T1195.002"),
            ("DNS Lookup of Built Hostname", "T1071.004"),
            ("Remote URL Dependency", "T1105"),
            ("Python Import-Obfuscated Loader", "T1027"),
        ] {
            assert!(
                ids(name).contains(&expected.to_string()),
                "{} -> {:?}",
                name,
                ids(name)
            );
        }
        // npm registry spam, IP lookups and exfil services are not Windows persistence.
        for name in [
            "Chain: Registry Spam Publisher",
            "IP Lookup Service",
            "Exfiltration Service Endpoint",
        ] {
            assert!(!ids(name).contains(&"T1543.003".to_string()), "{}", name);
        }
        assert!(!ids("Archive Extraction").contains(&"T1560".to_string()));
    }

    #[test]
    fn maps_capa_attack_metadata() {
        let meta = serde_json::json!({
            "attack": ["T1055", "T1620"],
            "name": "inject payload"
        });
        let ids: Vec<String> = from_capa_meta(&meta).into_iter().map(|t| t.id).collect();
        assert_eq!(ids, vec!["T1055", "T1620"]);
    }
}
