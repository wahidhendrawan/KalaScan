use crate::attack::{self, AttackTechnique};
use crate::entropy::calculate_entropy;
use crate::RuleMatch;
use anyhow::{Context, Result};
use goblin::mach::{Mach, SingleArch};
use goblin::Object;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use walkdir::WalkDir;

const ENGINE: &str = concat!("kalascan-static-triage/", env!("CARGO_PKG_VERSION"));
const MAX_FILES: usize = 10_000;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_BINARIES: usize = 64;
const MAX_TOOL_BINARIES: usize = 8;
const MAX_TOOL_BYTES: u64 = 50 * 1024 * 1024;
const MAX_SECTIONS: usize = 32;
const MAX_IMPORTS: usize = 80;
const MAX_STRINGS: usize = 40;
const MAX_CAPABILITIES: usize = 200;
const TOOL_TIMEOUT: Duration = Duration::from_secs(180);

const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "__pycache__",
    ".tox",
    ".eggs",
    "target",
    "venv",
    ".venv",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TriageReport {
    pub engine: String,
    pub deep: bool,
    pub files_scanned: usize,
    pub file_types: Vec<FileTypeCount>,
    pub binaries: Vec<BinaryArtifact>,
    pub capabilities: Vec<CapabilityFinding>,
    pub attack_techniques: Vec<AttackTechnique>,
    pub tools: Vec<ToolStatus>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTypeCount {
    pub kind: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryArtifact {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub file_type: String,
    pub architecture: Option<String>,
    pub bits: Option<u8>,
    pub entrypoint: Option<String>,
    pub entropy: f64,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<String>,
    pub packer: Option<PackerFinding>,
    pub indicators: Vec<String>,
    pub decoded_strings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub size: u64,
    pub entropy: f64,
    pub executable: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerFinding {
    pub name: String,
    pub confidence: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityFinding {
    pub name: String,
    pub namespace: String,
    pub description: String,
    pub severity: String,
    pub source: String,
    pub file_path: String,
    pub attack: Vec<AttackTechnique>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolStatus {
    pub name: String,
    pub available: bool,
    pub status: String,
    pub version: Option<String>,
}

pub async fn analyze_directory(dir: &Path, rule_matches: &[RuleMatch], deep: bool) -> TriageReport {
    let mut report = TriageReport {
        engine: ENGINE.to_string(),
        deep,
        ..Default::default()
    };
    let mut type_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut candidates: Vec<(String, PathBuf, String, Vec<u8>)> = Vec::new();
    let mut candidate_bytes = 0u64;

    for entry in WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            let name = entry.file_name().to_string_lossy();
            !entry.path().is_dir() || !SKIP_DIRS.contains(&name.as_ref())
        })
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        if !entry.file_type().is_file() {
            continue;
        }
        if report.files_scanned >= MAX_FILES {
            report.notes.push(format!(
                "Stopped after {} files to bound triage cost.",
                MAX_FILES
            ));
            break;
        }

        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.len() > MAX_FILE_BYTES {
            report.notes.push(format!(
                "Skipped oversized file {} ({} bytes).",
                entry.path().display(),
                metadata.len()
            ));
            continue;
        }

        let mut head = [0u8; 512];
        let read = File::open(entry.path())
            .and_then(|mut file| file.read(&mut head))
            .unwrap_or(0);
        let kind = detect_kind(entry.path(), &head[..read]);

        *type_counts.entry(kind.clone()).or_default() += 1;
        report.files_scanned += 1;

        if is_binary_kind(&kind) {
            if candidates.len() >= MAX_BINARIES {
                continue;
            }
            if candidate_bytes.saturating_add(metadata.len()) > MAX_TOTAL_BYTES {
                report.notes.push(format!(
                    "Skipped {} because the binary triage memory budget was reached.",
                    entry.path().display()
                ));
                continue;
            }
            let data = match std::fs::read(entry.path()) {
                Ok(data) => data,
                Err(_) => continue,
            };
            candidate_bytes = candidate_bytes.saturating_add(data.len() as u64);
            let rel_path = entry
                .path()
                .strip_prefix(dir)
                .unwrap_or(entry.path())
                .to_string_lossy()
                .to_string();
            candidates.push((rel_path, entry.path().to_path_buf(), kind, data));
        }
    }

    report.file_types = type_counts
        .into_iter()
        .map(|(kind, count)| FileTypeCount { kind, count })
        .collect();
    report
        .file_types
        .sort_by(|a, b| b.count.cmp(&a.count).then(a.kind.cmp(&b.kind)));

    if candidates.len() >= MAX_BINARIES {
        report.notes.push(format!(
            "Binary triage capped at {} artifacts.",
            MAX_BINARIES
        ));
    }

    for (rel_path, _absolute, kind, data) in &candidates {
        let artifact = analyze_binary(rel_path, kind, data);
        if let Some(packer) = &artifact.packer {
            let attack = attack::map_text(&format!("{} packer", packer.name));
            push_capability(
                &mut report.capabilities,
                CapabilityFinding {
                    name: format!("{} packer", packer.name),
                    namespace: "packer".to_string(),
                    description: packer.evidence.clone(),
                    severity: if packer.confidence == "high" {
                        "high".to_string()
                    } else {
                        "medium".to_string()
                    },
                    source: "heuristic".to_string(),
                    file_path: rel_path.clone(),
                    attack,
                },
            );
        }
        report.binaries.push(artifact);
    }

    for matched in rule_matches {
        // Rule name only: the context is surrounding source code (see ttp.rs).
        let techniques = attack::map_rule(&matched.matched_pattern, "");
        if techniques.is_empty() && matched.severity != "critical" {
            continue;
        }
        push_capability(
            &mut report.capabilities,
            CapabilityFinding {
                name: matched.matched_pattern.clone(),
                namespace: "static-rule".to_string(),
                description: format!(
                    "Rule matched at {}:{}",
                    matched.file_path, matched.line_number
                ),
                severity: matched.severity.clone(),
                source: "rule".to_string(),
                file_path: matched.file_path.clone(),
                attack: techniques,
            },
        );
    }

    if deep {
        run_deep_tools(dir, &mut report).await;
    }

    report.capabilities.sort_by(|a, b| {
        severity_rank(&a.severity)
            .cmp(&severity_rank(&b.severity))
            .then(a.name.cmp(&b.name))
    });
    report.capabilities.truncate(MAX_CAPABILITIES);

    for capability in &report.capabilities {
        attack::merge(&mut report.attack_techniques, capability.attack.clone());
    }
    report.attack_techniques.sort_by(|a, b| a.id.cmp(&b.id));

    report
}

fn push_capability(capabilities: &mut Vec<CapabilityFinding>, capability: CapabilityFinding) {
    if capabilities.iter().any(|existing| {
        existing.source == capability.source
            && existing.name == capability.name
            && existing.file_path == capability.file_path
    }) {
        return;
    }
    capabilities.push(capability);
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        _ => 3,
    }
}

pub fn risk_contribution(report: &TriageReport) -> u8 {
    let mut score = 0u16;
    for binary in &report.binaries {
        if binary.packer.is_some() {
            score += 8;
        }
        if binary.entropy >= 7.2 {
            score += 3;
        }
        if binary
            .sections
            .iter()
            .any(|section| section.executable && section.writable)
        {
            score += 4;
        }
    }

    for capability in report
        .capabilities
        .iter()
        .filter(|capability| capability.source != "rule")
    {
        score += match capability.severity.as_str() {
            "critical" => 10,
            "high" => 6,
            "medium" => 3,
            _ => 1,
        };
    }

    score.min(30) as u8
}

fn analyze_binary(rel_path: &str, kind: &str, data: &[u8]) -> BinaryArtifact {
    let mut artifact = BinaryArtifact {
        path: rel_path.to_string(),
        sha256: sha256(data),
        size: data.len() as u64,
        file_type: kind.to_string(),
        architecture: None,
        bits: None,
        entrypoint: None,
        entropy: calculate_entropy(data),
        sections: Vec::new(),
        imports: Vec::new(),
        packer: None,
        indicators: Vec::new(),
        decoded_strings: Vec::new(),
    };

    match Object::parse(data) {
        Ok(Object::PE(pe)) => {
            artifact.architecture = Some(pe_arch(pe.header.coff_header.machine));
            artifact.bits = Some(if pe.is_64 { 64 } else { 32 });
            artifact.entrypoint = Some(format!("0x{:x}", pe.entry));
            artifact.sections = pe
                .sections
                .iter()
                .take(MAX_SECTIONS)
                .map(|section| {
                    let bytes = slice_at(
                        data,
                        section.pointer_to_raw_data as usize,
                        section.size_of_raw_data as usize,
                    );
                    SectionInfo {
                        name: section.name().unwrap_or("").to_string(),
                        size: section.size_of_raw_data as u64,
                        entropy: calculate_entropy(bytes),
                        executable: section.characteristics & 0x2000_0000 != 0,
                        writable: section.characteristics & 0x8000_0000 != 0,
                    }
                })
                .collect();
            artifact.imports = pe
                .imports
                .iter()
                .take(MAX_IMPORTS)
                .map(|import| format!("{}!{}", import.dll, import.name))
                .collect();
        }
        Ok(Object::Elf(elf)) => {
            artifact.architecture = Some(elf_arch(elf.header.e_machine));
            artifact.bits = Some(if elf.is_64 { 64 } else { 32 });
            artifact.entrypoint = Some(format!("0x{:x}", elf.entry));
            artifact.sections = elf
                .section_headers
                .iter()
                .take(MAX_SECTIONS)
                .map(|section| {
                    let bytes =
                        slice_at(data, section.sh_offset as usize, section.sh_size as usize);
                    SectionInfo {
                        name: elf
                            .shdr_strtab
                            .get_at(section.sh_name)
                            .unwrap_or("")
                            .to_string(),
                        size: section.sh_size,
                        entropy: calculate_entropy(bytes),
                        executable: section.sh_flags & 0x4 != 0,
                        writable: section.sh_flags & 0x1 != 0,
                    }
                })
                .collect();
            artifact.imports = elf
                .dynsyms
                .iter()
                .filter(|symbol| symbol.st_shndx == 0)
                .take(MAX_IMPORTS)
                .filter_map(|symbol| elf.dynstrtab.get_at(symbol.st_name))
                .map(|name| name.to_string())
                .collect();
        }
        Ok(Object::Mach(mach)) => match mach {
            Mach::Binary(macho) => fill_macho(&mut artifact, &macho),
            Mach::Fat(fat) => {
                if let Ok(SingleArch::MachO(macho)) = fat.get(0) {
                    fill_macho(&mut artifact, &macho);
                }
            }
        },
        Ok(_) => {}
        Err(_) => artifact
            .indicators
            .push("Binary header could not be parsed".to_string()),
    }

    if kind == "Java class" && data.len() >= 8 {
        let major = u16::from_be_bytes([data[6], data[7]]);
        artifact.architecture = Some("JVM".to_string());
        artifact
            .indicators
            .push(format!("Java class major version {}", major));
    }

    artifact.packer = detect_packer(&artifact, data);
    artifact
        .indicators
        .extend(detect_indicators(&artifact, data));
    artifact.indicators.sort();
    artifact.indicators.dedup();
    artifact.indicators.truncate(20);
    artifact
}

fn fill_macho(artifact: &mut BinaryArtifact, macho: &goblin::mach::MachO) {
    artifact.architecture = Some(macho_arch(macho.header.cputype));
    artifact.bits = Some(if macho.is_64 { 64 } else { 32 });
    artifact.entrypoint = Some(format!("0x{:x}", macho.entry));

    for segment in macho.segments.iter() {
        if let Ok(sections) = segment.sections() {
            for (section, data) in sections.into_iter().take(MAX_SECTIONS) {
                artifact.sections.push(SectionInfo {
                    name: section.name().unwrap_or("").to_string(),
                    size: section.size,
                    entropy: calculate_entropy(data),
                    executable: section.flags & 0x8000_0000 != 0
                        || section.flags & 0x0000_0400 != 0,
                    writable: false,
                });
            }
        }
    }

    if let Ok(imports) = macho.imports() {
        artifact.imports = imports
            .iter()
            .take(MAX_IMPORTS)
            .map(|import| format!("{}!{}", import.dylib, import.name))
            .collect();
    }
}

fn slice_at(data: &[u8], offset: usize, size: usize) -> &[u8] {
    if offset >= data.len() {
        return &[];
    }
    let end = offset.saturating_add(size).min(data.len());
    &data[offset..end]
}

fn sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn pe_arch(machine: u16) -> String {
    match machine {
        0x014c => "x86".to_string(),
        0x8664 => "x86_64".to_string(),
        0x01c0 => "arm".to_string(),
        0xaa64 => "arm64".to_string(),
        0x0200 => "ia64".to_string(),
        0x5064 => "riscv64".to_string(),
        other => format!("machine-0x{:04x}", other),
    }
}

fn elf_arch(machine: u16) -> String {
    match machine {
        3 => "x86".to_string(),
        62 => "x86_64".to_string(),
        40 => "arm".to_string(),
        183 => "arm64".to_string(),
        8 => "mips".to_string(),
        20 => "powerpc".to_string(),
        21 => "powerpc64".to_string(),
        243 => "riscv".to_string(),
        other => format!("machine-{}", other),
    }
}

fn macho_arch(cputype: u32) -> String {
    match cputype {
        7 => "x86".to_string(),
        0x0100_0007 => "x86_64".to_string(),
        12 => "arm".to_string(),
        0x0100_000c => "arm64".to_string(),
        18 => "powerpc".to_string(),
        0x0100_0012 => "powerpc64".to_string(),
        other => format!("cputype-0x{:x}", other),
    }
}

fn detect_kind(path: &Path, head: &[u8]) -> String {
    if head.is_empty() {
        return "Empty".to_string();
    }
    if head.starts_with(b"MZ") {
        return "PE".to_string();
    }
    if head.starts_with(b"\x7fELF") {
        return "ELF".to_string();
    }
    if is_macho_magic(head) {
        return "Mach-O".to_string();
    }
    if head.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) {
        if path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("class"))
        {
            return "Java class".to_string();
        }
        return "Mach-O".to_string();
    }
    if head.starts_with(b"PK\x03\x04") {
        return "ZIP archive".to_string();
    }
    if head.starts_with(b"Cr24") {
        return "Chrome CRX".to_string();
    }
    if head.starts_with(b"Rar!") {
        return "RAR archive".to_string();
    }
    if head.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return "7z archive".to_string();
    }
    if head.starts_with(b"\x1f\x8b") {
        return "GZIP archive".to_string();
    }
    if head.starts_with(b"%PDF") {
        return "PDF".to_string();
    }
    if head.starts_with(b"\xd0\xcf\x11\xe0") {
        return "OLE document".to_string();
    }
    if head.starts_with(b"\0asm") {
        return "WebAssembly".to_string();
    }
    if head.starts_with(b"#!/") {
        return "Script".to_string();
    }
    if is_probably_text(head) {
        return text_kind(path);
    }
    "Binary data".to_string()
}

fn is_macho_magic(head: &[u8]) -> bool {
    matches!(
        head.get(..4),
        Some([0xfe, 0xed, 0xfa, 0xce])
            | Some([0xfe, 0xed, 0xfa, 0xcf])
            | Some([0xce, 0xfa, 0xed, 0xfe])
            | Some([0xcf, 0xfa, 0xed, 0xfe])
    )
}

fn is_probably_text(head: &[u8]) -> bool {
    if head.contains(&0) {
        return false;
    }
    let printable = head
        .iter()
        .filter(|byte| {
            **byte == b'\n' || **byte == b'\r' || **byte == b'\t' || (0x20..=0x7e).contains(&**byte)
        })
        .count();
    printable * 100 / head.len() >= 85
}

fn text_kind(path: &Path) -> String {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match extension.as_str() {
        "rs" => "Rust source",
        "py" => "Python source",
        "js" | "mjs" | "cjs" => "JavaScript source",
        "ts" | "tsx" => "TypeScript source",
        "jsx" => "JavaScript source",
        "sh" | "bash" | "zsh" => "Shell script",
        "ps1" => "PowerShell script",
        "bat" | "cmd" => "Batch script",
        "html" | "htm" => "HTML",
        "css" => "CSS",
        "json" => "JSON",
        "md" | "markdown" => "Markdown",
        "toml" => "TOML",
        "yaml" | "yml" => "YAML",
        "xml" => "XML",
        "java" => "Java source",
        "kt" | "kts" => "Kotlin source",
        "go" => "Go source",
        "c" | "h" => "C source",
        "cc" | "cpp" | "cxx" | "hpp" => "C++ source",
        "rb" => "Ruby source",
        "php" => "PHP source",
        "sql" => "SQL",
        "csv" => "CSV",
        "txt" => "Text",
        _ => "Text",
    }
    .to_string()
}

fn is_binary_kind(kind: &str) -> bool {
    matches!(kind, "PE" | "ELF" | "Mach-O" | "Java class" | "WebAssembly")
}

fn detect_packer(artifact: &BinaryArtifact, data: &[u8]) -> Option<PackerFinding> {
    let signatures: &[(&str, &str)] = &[
        ("upx", "UPX"),
        ("aspack", "ASPack"),
        ("mpress", "MPRESS"),
        ("themida", "Themida"),
        ("vmprotect", "VMProtect"),
        ("enigma", "Enigma Protector"),
        ("petite", "Petite"),
        ("fsg", "FSG"),
        ("mew", "MEW"),
        ("nspack", "NsPack"),
        (".vmp0", "VMProtect"),
        (".vmp1", "VMProtect"),
        (".packed", "Packed section"),
    ];

    for section in &artifact.sections {
        let name = section.name.to_ascii_lowercase();
        for (signature, label) in signatures {
            if name.contains(signature) {
                return Some(PackerFinding {
                    name: (*label).to_string(),
                    confidence: "high".to_string(),
                    evidence: format!("Section '{}' matches {} signature.", section.name, label),
                });
            }
        }
    }

    if contains_bytes(data, b"UPX!") {
        return Some(PackerFinding {
            name: "UPX".to_string(),
            confidence: "high".to_string(),
            evidence: "UPX marker found in binary data.".to_string(),
        });
    }

    if artifact.entropy >= 7.2 && artifact.imports.len() < 15 {
        return Some(PackerFinding {
            name: "Possible packing or encryption".to_string(),
            confidence: "medium".to_string(),
            evidence: format!(
                "High file entropy ({:.2}/8.0) with only {} imports.",
                artifact.entropy,
                artifact.imports.len()
            ),
        });
    }

    if artifact
        .sections
        .iter()
        .any(|section| section.executable && section.entropy >= 7.5)
    {
        return Some(PackerFinding {
            name: "High-entropy executable section".to_string(),
            confidence: "medium".to_string(),
            evidence: "An executable section has entropy >= 7.5/8.0.".to_string(),
        });
    }

    None
}

fn detect_indicators(artifact: &BinaryArtifact, data: &[u8]) -> Vec<String> {
    let mut indicators = Vec::new();
    let imports = artifact.imports.join(" ").to_ascii_lowercase();

    let suspicious_imports: &[(&str, &str)] = &[
        ("virtualallocex", "Suspicious import: VirtualAllocEx"),
        (
            "writeprocessmemory",
            "Suspicious import: WriteProcessMemory",
        ),
        (
            "createremotethread",
            "Suspicious import: CreateRemoteThread",
        ),
        (
            "ntmapviewofsection",
            "Suspicious import: NtMapViewOfSection",
        ),
        ("setwindowshookex", "Suspicious import: SetWindowsHookEx"),
        ("getasynckeystate", "Suspicious import: GetAsyncKeyState"),
        ("urldownloadtofile", "Suspicious import: URLDownloadToFile"),
        ("internetopen", "Suspicious import: InternetOpen"),
        ("winexec", "Suspicious import: WinExec"),
        ("shellexecute", "Suspicious import: ShellExecute"),
        ("isdebuggerpresent", "Anti-debug import: IsDebuggerPresent"),
        (
            "checkremotedebuggerpresent",
            "Anti-debug import: CheckRemoteDebuggerPresent",
        ),
        (
            "ntqueryinformationprocess",
            "Anti-debug import: NtQueryInformationProcess",
        ),
        ("amsiscanbuffer", "Defense evasion import: AmsiScanBuffer"),
        ("etweventwrite", "Defense evasion import: EtwEventWrite"),
        ("cryptencrypt", "Cryptographic import: CryptEncrypt"),
        ("regsetvalue", "Persistence import: RegSetValue"),
    ];

    for (needle, label) in suspicious_imports {
        if imports.contains(needle) {
            indicators.push((*label).to_string());
        }
    }

    let suspicious_strings: &[(&[u8], &str)] = &[
        (b"http://", "Contains HTTP URL"),
        (b"https://", "Contains HTTPS URL"),
        (b"powershell", "References PowerShell"),
        (b"cmd.exe", "References cmd.exe"),
        (b"discord", "References Discord"),
        (b"telegram", "References Telegram"),
        (b"bitcoin", "References Bitcoin"),
        (b"wallet", "References crypto wallet"),
        (b"amsi.dll", "References AMSI"),
        (b"isdebuggerpresent", "References anti-debug API"),
        (b"virtualalloc", "References memory allocation API"),
        (b"writeprocessmemory", "References process memory writing"),
        (b"createremotethread", "References remote thread creation"),
        (b"shellcode", "Contains shellcode marker"),
    ];

    for (needle, label) in suspicious_strings {
        if contains_bytes(data, needle) {
            indicators.push((*label).to_string());
        }
    }

    indicators
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

async fn run_deep_tools(dir: &Path, report: &mut TriageReport) {
    let tools = check_tools().await;
    let capa_available = tool_available(&tools, "capa");
    let floss_available = tool_available(&tools, "floss");
    let diec_available = tool_available(&tools, "diec");
    report.tools = tools;

    if !capa_available && !floss_available && !diec_available {
        report.notes.push(
            "Deep triage requested, but capa, FLOSS, and DIE are not installed. Install them for richer capabilities and decoded strings."
                .to_string(),
        );
        return;
    }

    let count = report.binaries.len().min(MAX_TOOL_BINARIES);
    for index in 0..count {
        let rel_path = report.binaries[index].path.clone();
        let file_type = report.binaries[index].file_type.clone();
        if !matches!(file_type.as_str(), "PE" | "ELF" | "Mach-O") {
            continue;
        }
        let absolute = dir.join(&rel_path);
        let metadata = match std::fs::metadata(&absolute) {
            Ok(metadata) => metadata,
            Err(error) => {
                report
                    .notes
                    .push(format!("Cannot inspect {}: {}", rel_path, error));
                continue;
            }
        };
        if metadata.len() > MAX_TOOL_BYTES {
            report.notes.push(format!(
                "Skipped external tools for {} ({} bytes).",
                rel_path,
                metadata.len()
            ));
            continue;
        }

        if capa_available {
            match run_capa(&absolute, &rel_path).await {
                Ok(capabilities) => {
                    for capability in capabilities {
                        push_capability(&mut report.capabilities, capability);
                    }
                }
                Err(error) => report
                    .notes
                    .push(format!("capa failed for {}: {}", rel_path, error)),
            }
        }

        if floss_available {
            match run_floss(&absolute).await {
                Ok(strings) => {
                    report.binaries[index].decoded_strings = strings.clone();
                    for string in strings {
                        let techniques = attack::map_text(&string);
                        if techniques.is_empty() {
                            continue;
                        }
                        push_capability(
                            &mut report.capabilities,
                            CapabilityFinding {
                                name: format!(
                                    "Decoded string: {}",
                                    string.chars().take(80).collect::<String>()
                                ),
                                namespace: "floss".to_string(),
                                description: "Recovered by FLOSS from the binary.".to_string(),
                                severity: "medium".to_string(),
                                source: "floss".to_string(),
                                file_path: rel_path.clone(),
                                attack: techniques,
                            },
                        );
                    }
                }
                Err(error) => report
                    .notes
                    .push(format!("FLOSS failed for {}: {}", rel_path, error)),
            }
        }

        if diec_available {
            match run_diec(&absolute, &rel_path).await {
                Ok(capabilities) => {
                    for capability in capabilities {
                        push_capability(&mut report.capabilities, capability);
                    }
                }
                Err(error) => report
                    .notes
                    .push(format!("DIE failed for {}: {}", rel_path, error)),
            }
        }
    }
}

fn tool_available(tools: &[ToolStatus], name: &str) -> bool {
    tools
        .iter()
        .find(|tool| tool.name == name)
        .is_some_and(|tool| tool.available)
}

async fn check_tools() -> Vec<ToolStatus> {
    vec![
        check_tool("capa").await,
        check_tool("floss").await,
        check_tool("diec").await,
    ]
}

async fn check_tool(name: &str) -> ToolStatus {
    match timeout(
        Duration::from_secs(5),
        Command::new(name).arg("--version").output(),
    )
    .await
    {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let version = stdout
                .lines()
                .chain(stderr.lines())
                .map(str::trim)
                .find(|line| !line.is_empty())
                .map(|line| line.chars().take(120).collect::<String>());
            ToolStatus {
                name: name.to_string(),
                available: true,
                status: "available".to_string(),
                version,
            }
        }
        Ok(Err(error)) => ToolStatus {
            name: name.to_string(),
            available: false,
            status: if error.kind() == std::io::ErrorKind::NotFound {
                "not found".to_string()
            } else {
                error.to_string()
            },
            version: None,
        },
        Err(_) => ToolStatus {
            name: name.to_string(),
            available: false,
            status: "version check timed out".to_string(),
            version: None,
        },
    }
}

async fn run_capa(path: &Path, rel_path: &str) -> Result<Vec<CapabilityFinding>> {
    let output = timeout(
        TOOL_TIMEOUT,
        Command::new("capa").arg("-j").arg(path).output(),
    )
    .await
    .context("capa timed out")?
    .context("failed to run capa")?;
    if !output.status.success() {
        anyhow::bail!(
            "capa exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("capa returned invalid JSON")?;
    let rules = value
        .get("rules")
        .and_then(|rules| rules.as_object())
        .context("capa JSON has no rules object")?;

    let mut capabilities = Vec::new();
    for (key, rule) in rules {
        let meta = rule.get("meta").unwrap_or(&serde_json::Value::Null);
        let name = meta
            .get("name")
            .and_then(|name| name.as_str())
            .unwrap_or_else(|| key.rsplit("::").next().unwrap_or(key));
        let namespace = meta
            .get("namespace")
            .and_then(|namespace| namespace.as_str())
            .unwrap_or_else(|| key.split("::").next().unwrap_or("capa"));
        let description = meta
            .get("description")
            .and_then(|description| description.as_str())
            .unwrap_or("Detected by capa.");
        capabilities.push(CapabilityFinding {
            name: name.to_string(),
            namespace: namespace.to_string(),
            description: description.to_string(),
            severity: capability_severity(name, namespace).to_string(),
            source: "capa".to_string(),
            file_path: rel_path.to_string(),
            attack: attack::from_capa_meta(meta),
        });
    }
    Ok(capabilities)
}

async fn run_floss(path: &Path) -> Result<Vec<String>> {
    let output = timeout(
        TOOL_TIMEOUT,
        Command::new("floss").arg("-j").arg(path).output(),
    )
    .await
    .context("FLOSS timed out")?
    .context("failed to run FLOSS")?;
    if !output.status.success() {
        anyhow::bail!(
            "FLOSS exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("FLOSS returned invalid JSON")?;
    let mut strings = Vec::new();
    collect_json_strings(&value, &mut strings);
    strings.retain(|string| string.len() >= 6 && string.len() <= 512);
    strings.sort();
    strings.dedup();
    strings.truncate(MAX_STRINGS);
    Ok(strings)
}

async fn run_diec(path: &Path, rel_path: &str) -> Result<Vec<CapabilityFinding>> {
    let output = timeout(
        TOOL_TIMEOUT,
        Command::new("diec").arg("-j").arg(path).output(),
    )
    .await
    .context("DIE timed out")?
    .context("failed to run DIE")?;
    if !output.status.success() {
        anyhow::bail!(
            "DIE exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("DIE returned invalid JSON")?;
    let mut strings = Vec::new();
    collect_die_strings(&value, &mut strings);
    strings.sort();
    strings.dedup();

    let interesting = [
        "upx",
        "themida",
        "vmprotect",
        "aspack",
        "mpress",
        "enigma",
        "packer",
        "protector",
        "packed",
        "pe32",
        "pe64",
        "elf",
        "macho",
        "compiler",
        "linker",
        "msvc",
        "mingw",
        "golang",
        "rust",
    ];

    let mut capabilities = Vec::new();
    for string in strings {
        let lower = string.to_ascii_lowercase();
        if !interesting.iter().any(|needle| lower.contains(needle)) {
            continue;
        }
        capabilities.push(CapabilityFinding {
            name: format!("DIE: {}", string),
            namespace: "die".to_string(),
            description: "Detected by Detect It Easy.".to_string(),
            severity: "medium".to_string(),
            source: "die".to_string(),
            file_path: rel_path.to_string(),
            attack: attack::map_text(&string),
        });
        if capabilities.len() >= 20 {
            break;
        }
    }
    Ok(capabilities)
}

fn collect_json_strings(value: &serde_json::Value, out: &mut Vec<String>) {
    if out.len() >= MAX_STRINGS {
        return;
    }
    match value {
        serde_json::Value::String(string) => out.push(string.clone()),
        serde_json::Value::Array(values) => {
            for value in values {
                collect_json_strings(value, out);
            }
        }
        serde_json::Value::Object(map) => {
            if let Some(string) = map.get("string").and_then(|value| value.as_str()) {
                out.push(string.to_string());
            }
            for value in map.values() {
                collect_json_strings(value, out);
            }
        }
        _ => {}
    }
}

fn collect_die_strings(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                collect_die_strings(value, out);
            }
        }
        serde_json::Value::Object(map) => {
            for key in ["name", "string", "type", "version", "info"] {
                if let Some(string) = map.get(key).and_then(|value| value.as_str()) {
                    if string.len() >= 2 {
                        out.push(string.to_string());
                    }
                }
            }
            for value in map.values() {
                collect_die_strings(value, out);
            }
        }
        _ => {}
    }
}

fn capability_severity(name: &str, namespace: &str) -> &'static str {
    let text = format!("{} {}", name, namespace).to_ascii_lowercase();
    if [
        "ransom",
        "encrypt",
        "inject",
        "credential",
        "steal",
        "keylog",
        "backdoor",
        "rootkit",
        "wiper",
    ]
    .iter()
    .any(|needle| text.contains(needle))
    {
        "critical"
    } else if [
        "persist",
        "evasion",
        "download",
        "execute",
        "network",
        "anti-debug",
        "packer",
        "protect",
        "socket",
    ]
    .iter()
    .any(|needle| text.contains(needle))
    {
        "high"
    } else {
        "medium"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_file_types() {
        assert_eq!(detect_kind(Path::new("a.exe"), b"MZ\x90\x00"), "PE");
        assert_eq!(detect_kind(Path::new("a.elf"), b"\x7fELF"), "ELF");
        assert_eq!(
            detect_kind(Path::new("a.zip"), b"PK\x03\x04"),
            "ZIP archive"
        );
        assert_eq!(
            detect_kind(Path::new("a.py"), b"print('hello')\n"),
            "Python source"
        );
        assert_eq!(
            detect_kind(Path::new("a.bin"), &[0, 1, 2, 3]),
            "Binary data"
        );
    }

    #[test]
    fn computes_sha256() {
        assert_eq!(
            sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn maps_packer_contribution() {
        let report = TriageReport {
            engine: ENGINE.to_string(),
            binaries: vec![BinaryArtifact {
                path: "evil.exe".to_string(),
                sha256: String::new(),
                size: 1,
                file_type: "PE".to_string(),
                architecture: Some("x86_64".to_string()),
                bits: Some(64),
                entrypoint: None,
                entropy: 7.5,
                sections: Vec::new(),
                imports: Vec::new(),
                packer: Some(PackerFinding {
                    name: "UPX".to_string(),
                    confidence: "high".to_string(),
                    evidence: "test".to_string(),
                }),
                indicators: Vec::new(),
                decoded_strings: Vec::new(),
            }],
            ..Default::default()
        };
        assert!(risk_contribution(&report) >= 8);
    }

    #[tokio::test]
    async fn triages_text_and_pe_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("main.py"), "print('hello')\n").unwrap();
        std::fs::write(temp.path().join("evil.exe"), b"MZ\x90\x00\x00\x00").unwrap();

        let report = analyze_directory(temp.path(), &[], false).await;
        assert_eq!(report.files_scanned, 2);
        assert!(report
            .file_types
            .iter()
            .any(|kind| kind.kind == "Python source"));
        assert!(report.file_types.iter().any(|kind| kind.kind == "PE"));
        assert_eq!(report.binaries.len(), 1);
        assert_eq!(report.binaries[0].file_type, "PE");
        assert_eq!(report.binaries[0].sha256.len(), 64);
    }
}
