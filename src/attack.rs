use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
}

const TECHNIQUE_TABLE: &[(&str, &str, &str)] = &[
    ("T1001", "Data Obfuscation", "Command and Control"),
    ("T1005", "Data from Local System", "Collection"),
    ("T1008", "Fallback Channels", "Command and Control"),
    ("T1014", "Rootkit", "Defense Evasion"),
    ("T1021", "Remote Services", "Lateral Movement"),
    ("T1025", "Data from Removable Media", "Collection"),
    (
        "T1027",
        "Obfuscated Files or Information",
        "Defense Evasion",
    ),
    ("T1027.002", "Software Packing", "Defense Evasion"),
    ("T1027.009", "Embedded Payloads", "Defense Evasion"),
    ("T1027.010", "Command Obfuscation", "Defense Evasion"),
    ("T1027.013", "Encrypted/Encoded File", "Defense Evasion"),
    ("T1036", "Masquerading", "Defense Evasion"),
    (
        "T1036.005",
        "Match Legitimate Name or Location",
        "Defense Evasion",
    ),
    ("T1039", "Data from Network Shared Drive", "Collection"),
    ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    ("T1053.005", "Scheduled Task", "Persistence"),
    ("T1055", "Process Injection", "Defense Evasion"),
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
    ("T1070", "Indicator Removal", "Defense Evasion"),
    ("T1070.001", "Clear Windows Event Logs", "Defense Evasion"),
    (
        "T1070.002",
        "Clear Linux or Mac System Logs",
        "Defense Evasion",
    ),
    ("T1070.003", "Clear Command History", "Defense Evasion"),
    ("T1070.004", "File Deletion", "Defense Evasion"),
    ("T1070.006", "Timestomp", "Defense Evasion"),
    ("T1071", "Application Layer Protocol", "Command and Control"),
    ("T1071.001", "Web Protocols", "Command and Control"),
    ("T1071.004", "DNS", "Command and Control"),
    ("T1074", "Data Staged", "Collection"),
    ("T1083", "File and Directory Discovery", "Discovery"),
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
    ("T1112", "Modify Registry", "Defense Evasion"),
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
        "Defense Evasion",
    ),
    ("T1176", "Browser Extensions", "Persistence"),
    (
        "T1195.002",
        "Compromise Software Supply Chain",
        "Initial Access",
    ),
    ("T1203", "Exploitation for Client Execution", "Execution"),
    ("T1204", "User Execution", "Execution"),
    ("T1204.002", "Malicious File", "Execution"),
    ("T1205", "Traffic Signaling", "Command and Control"),
    ("T1218", "System Binary Proxy Execution", "Defense Evasion"),
    ("T1218.011", "Rundll32", "Defense Evasion"),
    (
        "T1222",
        "File and Directory Permissions Modification",
        "Defense Evasion",
    ),
    ("T1480", "Execution Guardrails", "Defense Evasion"),
    ("T1485", "Data Destruction", "Impact"),
    ("T1486", "Data Encrypted for Impact", "Impact"),
    ("T1490", "Inhibit System Recovery", "Impact"),
    ("T1497", "Virtualization/Sandbox Evasion", "Defense Evasion"),
    (
        "T1528",
        "Steal Application Access Token",
        "Credential Access",
    ),
    ("T1539", "Steal Web Session Cookie", "Credential Access"),
    ("T1542", "Pre-OS Boot", "Persistence"),
    ("T1542.001", "System Firmware", "Persistence"),
    ("T1543.003", "Windows Service", "Persistence"),
    ("T1546", "Event Triggered Execution", "Persistence"),
    (
        "T1547.001",
        "Registry Run Keys / Startup Folder",
        "Persistence",
    ),
    ("T1552", "Unsecured Credentials", "Credential Access"),
    ("T1552.001", "Credentials In Files", "Credential Access"),
    (
        "T1555",
        "Credentials from Password Stores",
        "Credential Access",
    ),
    ("T1560", "Archive Collected Data", "Collection"),
    ("T1560.001", "Archive via Utility", "Collection"),
    ("T1562", "Impair Defenses", "Defense Evasion"),
    ("T1562.001", "Disable or Modify Tools", "Defense Evasion"),
    ("T1562.006", "Indicator Blocking", "Defense Evasion"),
    ("T1564", "Hide Artifacts", "Defense Evasion"),
    (
        "T1564.001",
        "Hidden Files and Directories",
        "Defense Evasion",
    ),
    ("T1566", "Phishing", "Initial Access"),
    ("T1566.001", "Spearphishing Attachment", "Initial Access"),
    ("T1567", "Exfiltration Over Web Service", "Exfiltration"),
    ("T1568", "Dynamic Resolution", "Command and Control"),
    (
        "T1568.002",
        "Domain Generation Algorithms",
        "Command and Control",
    ),
    ("T1571", "Non-Standard Port", "Command and Control"),
    ("T1572", "Protocol Tunneling", "Command and Control"),
    ("T1573", "Encrypted Channel", "Command and Control"),
    ("T1620", "Reflective Code Loading", "Defense Evasion"),
    ("T1622", "Debugger Evasion", "Defense Evasion"),
    ("T1657", "Financial Theft", "Impact"),
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

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
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

    if contains_any(&text, &["wallet", "bitcoin", "financial", "crypto theft"]) {
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
        ],
    ) {
        add(&mut out, "T1195.002");
        add(&mut out, "T1546");
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
        add(&mut out, "T1562");
        add(&mut out, "T1562.001");
    }

    if contains_any(&text, &["registry", "startup", "scheduled task", "service"]) {
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

    if contains_any(&text, &["masquerad"]) {
        add(&mut out, "T1036");
    }

    if contains_any(&text, &["hidden file", "hidden directory", "hide artifact"]) {
        add(&mut out, "T1564.001");
    }

    if contains_any(&text, &["file deletion", "delete file"]) {
        add(&mut out, "T1070.004");
    }

    if contains_any(&text, &["archive", "staging", "staged"]) {
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

pub fn map_rule(name: &str, description: &str) -> Vec<AttackTechnique> {
    map_text(&format!("{} {}", name, description))
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
    fn lookup_known_and_parent_technique() {
        assert_eq!(lookup("T1055").unwrap().name, "Process Injection");
        assert_eq!(
            lookup("T1059.999").unwrap().name,
            "Command and Scripting Interpreter"
        );
    }

    #[test]
    fn maps_webhook_and_credential_rules() {
        let ids: Vec<String> = map_rule("Discord Webhook", "data exfiltration")
            .into_iter()
            .map(|t| t.id)
            .collect();
        assert!(ids.contains(&"T1071".to_string()));
        assert!(ids.contains(&"T1041".to_string()));

        let ids: Vec<String> = map_rule("SSH Key Access", "credential file access")
            .into_iter()
            .map(|t| t.id)
            .collect();
        assert!(ids.contains(&"T1552".to_string()));
    }

    #[test]
    fn maps_new_supply_chain_findings() {
        let ids =
            |name: &str| -> Vec<String> { map_rule(name, "").into_iter().map(|t| t.id).collect() };
        assert!(ids("Typo-squat Suspect: crossenv (looks like cross-env)")
            .contains(&"T1195.002".to_string()));
        assert!(ids("Malicious Package: MAL-2024-1 in evil@1.0").contains(&"T1195.002".to_string()));
        assert!(ids("Chain: Remote File Write via Local Server").contains(&"T1203".to_string()));
        assert_eq!(lookup("T1203").unwrap().tactic, "Execution");
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
