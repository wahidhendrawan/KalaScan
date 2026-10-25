use crate::attack::{self, AttackTechnique};
use crate::triage::TriageReport;
use goblin::mach::{Mach, SingleArch};
use goblin::Object;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

const ENGINE: &str = "kalascan-emulation/1.8.0";
const MAX_FILES: usize = 16;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_REGION_BYTES: usize = 16 * 1024 * 1024;
const MAX_STACK_BYTES: usize = 64 * 1024;
const MAX_INSTRUCTIONS: usize = 50_000;
const MAX_STRINGS: usize = 40;
const MAX_API_CALLS: usize = 40;
const MAX_INDICATORS: usize = 20;
const EXTERNAL_BASE_64: u64 = 0xffff_ff00_0000_0000;
const EXTERNAL_BASE_32: u64 = 0x7f00_0000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmulationReport {
    pub engine: String,
    pub files_scanned: usize,
    pub traces: Vec<EmulationTrace>,
    pub attack_techniques: Vec<AttackTechnique>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationTrace {
    pub file_path: String,
    pub file_type: String,
    pub architecture: String,
    pub entrypoint: String,
    pub instructions: usize,
    pub stopped_reason: String,
    pub recovered_strings: Vec<String>,
    pub api_calls: Vec<String>,
    pub indicators: Vec<String>,
    pub attack: Vec<AttackTechnique>,
}

struct Region {
    start: u64,
    data: Vec<u8>,
    writable: bool,
    executable: bool,
}

struct Program {
    bitness: u32,
    entry: u64,
    file_type: String,
    regions: Vec<Region>,
    imports: Vec<(u64, String)>,
}

pub fn analyze_triage(dir: &Path, triage: &TriageReport) -> EmulationReport {
    let mut report = EmulationReport {
        engine: ENGINE.to_string(),
        ..Default::default()
    };

    for binary in triage
        .binaries
        .iter()
        .filter(|binary| matches!(binary.file_type.as_str(), "PE" | "ELF" | "Mach-O"))
        .take(MAX_FILES)
    {
        let absolute = dir.join(&binary.path);
        let metadata = match std::fs::metadata(&absolute) {
            Ok(metadata) => metadata,
            Err(error) => {
                report
                    .notes
                    .push(format!("Cannot inspect {}: {}", binary.path, error));
                continue;
            }
        };
        if metadata.len() > MAX_FILE_BYTES {
            report.notes.push(format!(
                "Skipped emulation for {} ({} bytes).",
                binary.path,
                metadata.len()
            ));
            continue;
        }
        let data = match std::fs::read(&absolute) {
            Ok(data) => data,
            Err(error) => {
                report
                    .notes
                    .push(format!("Cannot read {}: {}", binary.path, error));
                continue;
            }
        };
        report.files_scanned += 1;
        match emulate_binary(&binary.path, &data) {
            Ok(trace) => {
                if !trace.recovered_strings.is_empty()
                    || !trace.api_calls.is_empty()
                    || trace.instructions > 0
                {
                    report.traces.push(trace);
                }
            }
            Err(error) => report
                .notes
                .push(format!("Emulation skipped for {}: {}", binary.path, error)),
        }
    }

    if report.files_scanned == 0 {
        report
            .notes
            .push("No PE, ELF, or Mach-O binaries were available for emulation.".to_string());
    }

    report.traces.sort_by(|a, b| a.file_path.cmp(&b.file_path));
    for trace in &report.traces {
        attack::merge(&mut report.attack_techniques, trace.attack.clone());
    }
    report.attack_techniques.sort_by(|a, b| a.id.cmp(&b.id));
    report
}

pub fn risk_contribution(report: &EmulationReport) -> u8 {
    let mut score = 0u16;
    for trace in &report.traces {
        score += (trace.api_calls.len() * 2).min(10) as u16;
        score += (trace.indicators.len() * 2).min(10) as u16;
        if !trace.recovered_strings.is_empty() {
            score += 2;
        }
    }
    score.min(25) as u8
}

fn emulate_binary(file_path: &str, data: &[u8]) -> Result<EmulationTrace, String> {
    let program = build_program(data)?;
    if program.regions.is_empty() {
        return Err("no loadable sections found".to_string());
    }
    let mut memory = EmuMemory::new(program.regions, program.imports, program.bitness);
    if !memory.is_executable(program.entry) {
        return Err("entrypoint is not in an executable region".to_string());
    }

    let mut registers = Registers::new(program.bitness, memory.stack_pointer());
    let mut stats = Stats::default();
    let mut ip = program.entry;
    let mut instructions = 0usize;
    let stopped_reason;

    loop {
        if instructions >= MAX_INSTRUCTIONS {
            stopped_reason = format!("instruction budget reached ({})", MAX_INSTRUCTIONS);
            break;
        }
        let code = match memory.read_prefix(ip, 15) {
            Some(code) if !code.is_empty() => code,
            _ => {
                stopped_reason = format!("unmapped instruction fetch at 0x{:x}", ip);
                break;
            }
        };
        let mut decoder = Decoder::with_ip(program.bitness, &code, ip, DecoderOptions::NONE);
        let instruction = decoder.decode();
        if instruction.is_invalid() || instruction.len() == 0 {
            stopped_reason = format!("invalid instruction at 0x{:x}", ip);
            break;
        }
        stats.record(&instruction);
        let step = execute_instruction(&instruction, &mut registers, &mut memory, ip);
        instructions += 1;
        match step {
            Step::Next => ip = instruction.next_ip(),
            Step::Jump(target) => ip = target,
            Step::Stop(reason) => {
                stopped_reason = reason;
                break;
            }
        }
    }

    let recovered_strings = memory.extract_strings();
    let api_calls = memory.api_calls.clone();
    let mut indicators = crate::deobfuscate::detect_indicators(&recovered_strings.join(" "));
    indicators.extend(stats.indicators());
    indicators.sort();
    indicators.dedup();
    indicators.truncate(MAX_INDICATORS);

    let attack_text = format!(
        "{} {} {}",
        recovered_strings.join(" "),
        api_calls.join(" "),
        indicators.join(" ")
    );
    let attack = attack::map_text(&attack_text);

    Ok(EmulationTrace {
        file_path: file_path.to_string(),
        file_type: program.file_type,
        architecture: if program.bitness == 64 {
            "x86_64".to_string()
        } else {
            "x86".to_string()
        },
        entrypoint: format!("0x{:x}", program.entry),
        instructions,
        stopped_reason,
        recovered_strings,
        api_calls,
        indicators,
        attack,
    })
}

fn build_program(data: &[u8]) -> Result<Program, String> {
    match Object::parse(data).map_err(|error| error.to_string())? {
        Object::PE(pe) => {
            let mut regions = Vec::new();
            let mut total = 0usize;
            for section in &pe.sections {
                let size = section.virtual_size.max(section.size_of_raw_data) as usize;
                if size == 0 || total.saturating_add(size) > MAX_REGION_BYTES {
                    continue;
                }
                let mut bytes = vec![0u8; size];
                let offset = section.pointer_to_raw_data as usize;
                let raw_size = section.size_of_raw_data as usize;
                if offset < data.len() {
                    let copy = raw_size.min(data.len() - offset).min(size);
                    bytes[..copy].copy_from_slice(&data[offset..offset + copy]);
                }
                regions.push(Region {
                    start: pe.image_base + section.virtual_address as u64,
                    data: bytes,
                    writable: section.characteristics & 0x8000_0000 != 0,
                    executable: section.characteristics & 0x2000_0000 != 0,
                });
                total += size;
            }
            let imports = pe
                .imports
                .iter()
                .map(|import| {
                    (
                        pe.image_base + import.offset as u64,
                        format!("{}!{}", import.dll, import.name),
                    )
                })
                .collect();
            Ok(Program {
                bitness: if pe.is_64 { 64 } else { 32 },
                entry: pe.image_base + pe.entry as u64,
                file_type: "PE".to_string(),
                regions,
                imports,
            })
        }
        Object::Elf(elf) => {
            let mut regions = Vec::new();
            let mut total = 0usize;
            for section in &elf.section_headers {
                let size = section.sh_size as usize;
                if size == 0 || total.saturating_add(size) > MAX_REGION_BYTES {
                    continue;
                }
                let mut bytes = vec![0u8; size];
                if section.sh_type != 8 {
                    let offset = section.sh_offset as usize;
                    if offset < data.len() {
                        let copy = size.min(data.len() - offset);
                        bytes[..copy].copy_from_slice(&data[offset..offset + copy]);
                    }
                }
                regions.push(Region {
                    start: section.sh_addr,
                    data: bytes,
                    writable: section.sh_flags & 0x1 != 0,
                    executable: section.sh_flags & 0x4 != 0,
                });
                total += size;
            }
            Ok(Program {
                bitness: if elf.is_64 { 64 } else { 32 },
                entry: elf.entry,
                file_type: "ELF".to_string(),
                regions,
                imports: Vec::new(),
            })
        }
        Object::Mach(mach) => match mach {
            Mach::Binary(macho) => program_from_macho(&macho),
            Mach::Fat(fat) => match fat.get(0) {
                Ok(SingleArch::MachO(macho)) => program_from_macho(&macho),
                _ => Err("fat Mach-O has no usable x86 slice".to_string()),
            },
        },
        _ => Err("unsupported binary format".to_string()),
    }
}

fn program_from_macho(macho: &goblin::mach::MachO) -> Result<Program, String> {
    let mut regions = Vec::new();
    let mut total = 0usize;
    for segment in macho.segments.iter() {
        let sections = match segment.sections() {
            Ok(sections) => sections,
            Err(_) => continue,
        };
        for (section, bytes) in sections {
            let size = section.size as usize;
            if size == 0 || total.saturating_add(size) > MAX_REGION_BYTES {
                continue;
            }
            let mut data = vec![0u8; size];
            let copy = size.min(bytes.len());
            data[..copy].copy_from_slice(&bytes[..copy]);
            regions.push(Region {
                start: section.addr,
                data,
                writable: segment.initprot & 0x2 != 0,
                executable: segment.initprot & 0x4 != 0
                    || section.flags & 0x8000_0000 != 0
                    || section.flags & 0x400 != 0,
            });
            total += size;
        }
    }
    Ok(Program {
        bitness: if macho.is_64 { 64 } else { 32 },
        entry: macho.entry,
        file_type: "Mach-O".to_string(),
        regions,
        imports: Vec::new(),
    })
}

#[derive(Default, Clone, Copy)]
struct Flags {
    zf: bool,
    sf: bool,
    cf: bool,
    of: bool,
    pf: bool,
}

struct Registers {
    gpr: [u64; 16],
    flags: Flags,
}

impl Registers {
    fn new(bitness: u32, stack_pointer: u64) -> Self {
        let mut gpr = [0u64; 16];
        gpr[7] = stack_pointer;
        gpr[6] = stack_pointer;
        if bitness == 32 {
            gpr[7] &= 0xffff_ffff;
            gpr[6] &= 0xffff_ffff;
        }
        Self {
            gpr,
            flags: Flags::default(),
        }
    }
}

struct EmuMemory {
    regions: Vec<Region>,
    imports: HashMap<u64, (u64, String)>,
    fake_imports: HashMap<u64, String>,
    dirty: HashSet<u64>,
    api_calls: Vec<String>,
    stack_top: u64,
    bitness: u32,
    external_base: u64,
}

impl EmuMemory {
    fn new(mut regions: Vec<Region>, imports: Vec<(u64, String)>, bitness: u32) -> Self {
        let stack_start = if bitness == 64 {
            0x0000_7fff_0000_0000
        } else {
            0x7fff_0000
        };
        let stack_top = stack_start + MAX_STACK_BYTES as u64;
        regions.push(Region {
            start: stack_start,
            data: vec![0u8; MAX_STACK_BYTES],
            writable: true,
            executable: false,
        });

        let external_base = if bitness == 64 {
            EXTERNAL_BASE_64
        } else {
            EXTERNAL_BASE_32
        };
        let mut import_map = HashMap::new();
        let mut fake_imports = HashMap::new();
        for (index, (address, name)) in imports.into_iter().enumerate() {
            let fake = external_base + index as u64 * 0x10;
            import_map.insert(address, (fake, name.clone()));
            fake_imports.insert(fake, name);
        }

        Self {
            regions,
            imports: import_map,
            fake_imports,
            dirty: HashSet::new(),
            api_calls: Vec::new(),
            stack_top,
            bitness,
            external_base,
        }
    }

    fn stack_pointer(&self) -> u64 {
        self.stack_top - 0x100
    }

    fn is_executable(&self, address: u64) -> bool {
        self.regions
            .iter()
            .any(|region| region.executable && contains(region, address, 1))
    }

    fn read_prefix(&self, address: u64, max_size: usize) -> Option<Vec<u8>> {
        let region = self
            .regions
            .iter()
            .find(|region| contains(region, address, 1))?;
        let offset = (address - region.start) as usize;
        let end = (offset + max_size).min(region.data.len());
        Some(region.data[offset..end].to_vec())
    }

    fn read(&self, address: u64, size: usize) -> Option<Vec<u8>> {
        if size == 0 || size > 8 {
            return None;
        }
        if let Some((fake, _)) = self.imports.get(&address) {
            if size == 4 || size == 8 {
                return Some(fake.to_le_bytes()[..size].to_vec());
            }
        }
        let region = self
            .regions
            .iter()
            .find(|region| contains(region, address, size))?;
        let offset = (address - region.start) as usize;
        Some(region.data[offset..offset + size].to_vec())
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> bool {
        let region = self
            .regions
            .iter_mut()
            .find(|region| region.writable && contains(region, address, bytes.len()));
        let Some(region) = region else {
            return false;
        };
        let offset = (address - region.start) as usize;
        region.data[offset..offset + bytes.len()].copy_from_slice(bytes);
        for index in 0..bytes.len() {
            self.dirty.insert(address + index as u64);
        }
        true
    }

    fn read_value(&self, address: u64, size: usize) -> Option<u64> {
        let bytes = self.read(address, size)?;
        let mut value = 0u64;
        for (index, byte) in bytes.iter().enumerate() {
            value |= (*byte as u64) << (index * 8);
        }
        Some(value)
    }

    fn write_value(&mut self, address: u64, size: usize, value: u64) -> bool {
        let bytes = value.to_le_bytes();
        self.write(address, &bytes[..size])
    }

    fn is_external(&self, address: u64) -> bool {
        address >= self.external_base && address < self.external_base + 0x1_0000
    }

    fn record_external(&mut self, address: u64) -> Option<String> {
        let name = self.fake_imports.get(&address).cloned()?;
        if !self.api_calls.contains(&name) && self.api_calls.len() < MAX_API_CALLS {
            self.api_calls.push(name.clone());
        }
        Some(name)
    }

    fn extract_strings(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for region in self.regions.iter().filter(|region| region.writable) {
            let mut index = 0usize;
            while index < region.data.len() {
                let address = region.start + index as u64;
                if !self.dirty.contains(&address) {
                    index += 1;
                    continue;
                }
                let mut bytes = Vec::new();
                while index < region.data.len() {
                    let address = region.start + index as u64;
                    let byte = region.data[index];
                    if self.dirty.contains(&address) && (0x20..=0x7e).contains(&byte) {
                        bytes.push(byte);
                        index += 1;
                    } else {
                        break;
                    }
                }
                if bytes.len() >= 6 {
                    let value = String::from_utf8_lossy(&bytes).to_string();
                    if seen.insert(value.clone()) && out.len() < MAX_STRINGS {
                        out.push(value);
                    }
                }
                index += 1;
            }
        }
        out
    }
}

fn contains(region: &Region, address: u64, size: usize) -> bool {
    address >= region.start
        && address
            .checked_add(size as u64)
            .is_some_and(|end| end <= region.start + region.data.len() as u64)
}

#[derive(Default)]
struct Stats {
    cpuid: usize,
    rdtsc: usize,
    syscall: usize,
    interrupt: usize,
    io: usize,
    hypervisor: usize,
}

impl Stats {
    fn record(&mut self, instruction: &Instruction) {
        match instruction.mnemonic() {
            Mnemonic::Cpuid => self.cpuid += 1,
            Mnemonic::Rdtsc | Mnemonic::Rdtscp => self.rdtsc += 1,
            Mnemonic::Syscall | Mnemonic::Sysenter => self.syscall += 1,
            Mnemonic::Int | Mnemonic::Int3 | Mnemonic::Into => self.interrupt += 1,
            Mnemonic::In | Mnemonic::Out => self.io += 1,
            Mnemonic::Vmcall | Mnemonic::Vmmcall | Mnemonic::Vmrun | Mnemonic::Vmxon => {
                self.hypervisor += 1
            }
            _ => {}
        }
    }

    fn indicators(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.cpuid > 0 {
            out.push("Anti-VM instruction: CPUID".to_string());
        }
        if self.rdtsc > 0 {
            out.push("Anti-debug timing instruction: RDTSC".to_string());
        }
        if self.syscall > 0 {
            out.push("Direct system call instruction".to_string());
        }
        if self.interrupt > 0 {
            out.push("Interrupt instruction".to_string());
        }
        if self.io > 0 {
            out.push("I/O port instruction".to_string());
        }
        if self.hypervisor > 0 {
            out.push("Hypervisor instruction".to_string());
        }
        out
    }
}

enum Step {
    Next,
    Jump(u64),
    Stop(String),
}

fn execute_instruction(
    instruction: &Instruction,
    registers: &mut Registers,
    memory: &mut EmuMemory,
    ip: u64,
) -> Step {
    if instruction.has_rep_prefix() {
        return Step::Stop("rep-prefixed instruction is unsupported".to_string());
    }

    match instruction.mnemonic() {
        Mnemonic::Nop | Mnemonic::Pause | Mnemonic::Endbr32 | Mnemonic::Endbr64 => Step::Next,
        Mnemonic::Mov => {
            let value = match read_operand(instruction, 1, registers, memory, ip) {
                Some(value) => value,
                None => return Step::Stop("unsupported mov source".to_string()),
            };
            if write_operand(instruction, 0, value, registers, memory, ip) {
                Step::Next
            } else {
                Step::Stop("unsupported mov destination".to_string())
            }
        }
        Mnemonic::Movzx | Mnemonic::Movsx => {
            let source_size = operand_size(instruction, 1);
            let destination_size = operand_size(instruction, 0);
            if source_size == 0 || destination_size == 0 {
                return Step::Stop("unsupported extension operand".to_string());
            }
            let value = match read_operand(instruction, 1, registers, memory, ip) {
                Some(value) => value & mask(source_size),
                None => return Step::Stop("unsupported extension source".to_string()),
            };
            let value = if instruction.mnemonic() == Mnemonic::Movsx {
                sign_extend(value, source_size)
            } else {
                value
            };
            if write_operand(
                instruction,
                0,
                value & mask(destination_size),
                registers,
                memory,
                ip,
            ) {
                Step::Next
            } else {
                Step::Stop("unsupported extension destination".to_string())
            }
        }
        Mnemonic::Lea => {
            let address = match memory_address(instruction, registers, ip) {
                Some(address) => address,
                None => return Step::Stop("unsupported lea address".to_string()),
            };
            if write_operand(instruction, 0, address, registers, memory, ip) {
                Step::Next
            } else {
                Step::Stop("unsupported lea destination".to_string())
            }
        }
        Mnemonic::Push => {
            let width = stack_width(memory.bitness);
            let value = match read_operand(instruction, 0, registers, memory, ip) {
                Some(value) => value,
                None => return Step::Stop("unsupported push operand".to_string()),
            };
            registers.gpr[7] = registers.gpr[7].wrapping_sub(width as u64);
            if !memory.write_value(registers.gpr[7], width, value) {
                return Step::Stop("push to unmapped stack".to_string());
            }
            Step::Next
        }
        Mnemonic::Pop => {
            let width = stack_width(memory.bitness);
            let value = match memory.read_value(registers.gpr[7], width) {
                Some(value) => value,
                None => return Step::Stop("pop from unmapped stack".to_string()),
            };
            registers.gpr[7] = registers.gpr[7].wrapping_add(width as u64);
            if write_operand(instruction, 0, value, registers, memory, ip) {
                Step::Next
            } else {
                Step::Stop("unsupported pop destination".to_string())
            }
        }
        Mnemonic::Xor | Mnemonic::Add | Mnemonic::Sub | Mnemonic::And | Mnemonic::Or => {
            let size = operand_size(instruction, 0).max(operand_size(instruction, 1));
            let left = match read_operand(instruction, 0, registers, memory, ip) {
                Some(value) => value & mask(size),
                None => return Step::Stop("unsupported arithmetic destination".to_string()),
            };
            let right = match read_operand(instruction, 1, registers, memory, ip) {
                Some(value) => value & mask(size),
                None => return Step::Stop("unsupported arithmetic source".to_string()),
            };
            let (result, carry, overflow) = match instruction.mnemonic() {
                Mnemonic::Add => add_result(left, right, size),
                Mnemonic::Sub => sub_result(left, right, size),
                Mnemonic::Xor => (left ^ right, false, false),
                Mnemonic::And => (left & right, false, false),
                Mnemonic::Or => (left | right, false, false),
                _ => unreachable!(),
            };
            let result = result & mask(size);
            registers.flags = Flags {
                zf: result == 0,
                sf: result & sign_bit(size) != 0,
                cf: carry,
                of: overflow,
                pf: parity(result),
            };
            if write_operand(instruction, 0, result, registers, memory, ip) {
                Step::Next
            } else {
                Step::Stop("unsupported arithmetic write".to_string())
            }
        }
        Mnemonic::Inc | Mnemonic::Dec => {
            let size = operand_size(instruction, 0);
            let value = match read_operand(instruction, 0, registers, memory, ip) {
                Some(value) => value & mask(size),
                None => return Step::Stop("unsupported increment operand".to_string()),
            };
            let (result, overflow) = if instruction.mnemonic() == Mnemonic::Inc {
                let result = value.wrapping_add(1) & mask(size);
                (result, (value ^ result) & sign_bit(size) != 0)
            } else {
                let result = value.wrapping_sub(1) & mask(size);
                (result, (value ^ result) & sign_bit(size) != 0)
            };
            registers.flags.zf = result == 0;
            registers.flags.sf = result & sign_bit(size) != 0;
            registers.flags.of = overflow;
            registers.flags.pf = parity(result);
            if write_operand(instruction, 0, result, registers, memory, ip) {
                Step::Next
            } else {
                Step::Stop("unsupported increment write".to_string())
            }
        }
        Mnemonic::Not => {
            let size = operand_size(instruction, 0);
            let value = match read_operand(instruction, 0, registers, memory, ip) {
                Some(value) => value,
                None => return Step::Stop("unsupported not operand".to_string()),
            };
            if write_operand(instruction, 0, !value & mask(size), registers, memory, ip) {
                Step::Next
            } else {
                Step::Stop("unsupported not write".to_string())
            }
        }
        Mnemonic::Neg => {
            let size = operand_size(instruction, 0);
            let value = match read_operand(instruction, 0, registers, memory, ip) {
                Some(value) => value & mask(size),
                None => return Step::Stop("unsupported neg operand".to_string()),
            };
            let result = 0u64.wrapping_sub(value) & mask(size);
            registers.flags = Flags {
                zf: result == 0,
                sf: result & sign_bit(size) != 0,
                cf: value != 0,
                of: value == sign_bit(size),
                pf: parity(result),
            };
            if write_operand(instruction, 0, result, registers, memory, ip) {
                Step::Next
            } else {
                Step::Stop("unsupported neg write".to_string())
            }
        }
        Mnemonic::Cmp => {
            let size = operand_size(instruction, 0).max(operand_size(instruction, 1));
            let left = match read_operand(instruction, 0, registers, memory, ip) {
                Some(value) => value & mask(size),
                None => return Step::Stop("unsupported cmp operand".to_string()),
            };
            let right = match read_operand(instruction, 1, registers, memory, ip) {
                Some(value) => value & mask(size),
                None => return Step::Stop("unsupported cmp source".to_string()),
            };
            let (result, carry, overflow) = sub_result(left, right, size);
            registers.flags = Flags {
                zf: result & mask(size) == 0,
                sf: result & sign_bit(size) != 0,
                cf: carry,
                of: overflow,
                pf: parity(result),
            };
            Step::Next
        }
        Mnemonic::Test => {
            let size = operand_size(instruction, 0).max(operand_size(instruction, 1));
            let left = match read_operand(instruction, 0, registers, memory, ip) {
                Some(value) => value & mask(size),
                None => return Step::Stop("unsupported test operand".to_string()),
            };
            let right = match read_operand(instruction, 1, registers, memory, ip) {
                Some(value) => value & mask(size),
                None => return Step::Stop("unsupported test source".to_string()),
            };
            let result = left & right;
            registers.flags = Flags {
                zf: result == 0,
                sf: result & sign_bit(size) != 0,
                cf: false,
                of: false,
                pf: parity(result),
            };
            Step::Next
        }
        Mnemonic::Shl
        | Mnemonic::Shr
        | Mnemonic::Sal
        | Mnemonic::Sar
        | Mnemonic::Rol
        | Mnemonic::Ror => {
            let size = operand_size(instruction, 0);
            let value = match read_operand(instruction, 0, registers, memory, ip) {
                Some(value) => value & mask(size),
                None => return Step::Stop("unsupported shift operand".to_string()),
            };
            let count = match read_operand(instruction, 1, registers, memory, ip) {
                Some(value) => value as u32,
                None => return Step::Stop("unsupported shift count".to_string()),
            };
            let bits = (size * 8) as u32;
            let count = count % bits.max(1);
            let result = match instruction.mnemonic() {
                Mnemonic::Shl | Mnemonic::Sal => (value << count) & mask(size),
                Mnemonic::Shr => value >> count,
                Mnemonic::Sar => {
                    let signed = sign_extend(value, size) as i64;
                    ((signed >> count) as u64) & mask(size)
                }
                Mnemonic::Rol => ((value << count) | (value >> (bits - count))) & mask(size),
                Mnemonic::Ror => ((value >> count) | (value << (bits - count))) & mask(size),
                _ => unreachable!(),
            };
            registers.flags.zf = result == 0;
            registers.flags.sf = result & sign_bit(size) != 0;
            registers.flags.pf = parity(result);
            if write_operand(instruction, 0, result, registers, memory, ip) {
                Step::Next
            } else {
                Step::Stop("unsupported shift write".to_string())
            }
        }
        Mnemonic::Jmp => match branch_target(instruction, registers, memory, ip) {
            Some(target) => jump_target(target, memory),
            None => Step::Stop("unsupported jump target".to_string()),
        },
        Mnemonic::Call => {
            let target = match branch_target(instruction, registers, memory, ip) {
                Some(target) => target,
                None => return Step::Stop("unsupported call target".to_string()),
            };
            if let Some(name) = memory.record_external(target) {
                return Step::Stop(format!("external API call: {}", name));
            }
            let width = stack_width(memory.bitness);
            registers.gpr[7] = registers.gpr[7].wrapping_sub(width as u64);
            if !memory.write_value(registers.gpr[7], width, instruction.next_ip()) {
                return Step::Stop("call to unmapped stack".to_string());
            }
            jump_target(target, memory)
        }
        Mnemonic::Ret => {
            let width = stack_width(memory.bitness);
            let target = match memory.read_value(registers.gpr[7], width) {
                Some(target) => target,
                None => return Step::Stop("ret from unmapped stack".to_string()),
            };
            registers.gpr[7] = registers.gpr[7].wrapping_add(width as u64);
            jump_target(target, memory)
        }
        Mnemonic::Leave => {
            registers.gpr[7] = registers.gpr[6];
            let width = stack_width(memory.bitness);
            let value = match memory.read_value(registers.gpr[7], width) {
                Some(value) => value,
                None => return Step::Stop("leave from unmapped stack".to_string()),
            };
            registers.gpr[7] = registers.gpr[7].wrapping_add(width as u64);
            registers.gpr[6] = value;
            Step::Next
        }
        Mnemonic::Je
        | Mnemonic::Jne
        | Mnemonic::Jb
        | Mnemonic::Jae
        | Mnemonic::Jbe
        | Mnemonic::Ja
        | Mnemonic::Jl
        | Mnemonic::Jge
        | Mnemonic::Jle
        | Mnemonic::Jg
        | Mnemonic::Js
        | Mnemonic::Jns
        | Mnemonic::Jo
        | Mnemonic::Jno
        | Mnemonic::Jp
        | Mnemonic::Jnp => {
            if condition_met(instruction.mnemonic(), registers.flags) {
                match branch_target(instruction, registers, memory, ip) {
                    Some(target) => jump_target(target, memory),
                    None => Step::Stop("unsupported conditional target".to_string()),
                }
            } else {
                Step::Next
            }
        }
        Mnemonic::Cpuid => {
            registers.gpr[0] = 0;
            registers.gpr[1] = 0;
            registers.gpr[2] = 0;
            registers.gpr[3] = 0;
            Step::Next
        }
        Mnemonic::Rdtsc | Mnemonic::Rdtscp => {
            registers.gpr[0] = 0;
            registers.gpr[3] = 0;
            Step::Next
        }
        Mnemonic::Xgetbv => {
            registers.gpr[0] = 0;
            registers.gpr[3] = 0;
            Step::Next
        }
        Mnemonic::Clc => {
            registers.flags.cf = false;
            Step::Next
        }
        Mnemonic::Stc => {
            registers.flags.cf = true;
            Step::Next
        }
        Mnemonic::Cld | Mnemonic::Std => Step::Next,
        Mnemonic::Cdqe => {
            let value = registers.gpr[0] as u32 as i32 as i64 as u64;
            registers.gpr[0] = value;
            Step::Next
        }
        Mnemonic::Cwde => {
            let value = registers.gpr[0] as u16 as i16 as i32 as u64;
            registers.gpr[0] = value;
            Step::Next
        }
        Mnemonic::Cbw => {
            let value = registers.gpr[0] as u8 as i8 as i16 as u64;
            registers.gpr[0] = (registers.gpr[0] & !0xffff) | (value & 0xffff);
            Step::Next
        }
        Mnemonic::Int | Mnemonic::Int3 | Mnemonic::Into => {
            Step::Stop("interrupt instruction".to_string())
        }
        Mnemonic::Syscall | Mnemonic::Sysenter => Step::Stop("syscall instruction".to_string()),
        Mnemonic::In | Mnemonic::Out => Step::Stop("I/O port instruction".to_string()),
        Mnemonic::Vmcall | Mnemonic::Vmmcall | Mnemonic::Vmrun | Mnemonic::Vmxon => {
            Step::Stop("hypervisor instruction".to_string())
        }
        Mnemonic::Ud2 => Step::Stop("invalid instruction (ud2)".to_string()),
        other => Step::Stop(format!("unsupported instruction: {:?}", other)),
    }
}

fn jump_target(target: u64, memory: &mut EmuMemory) -> Step {
    if memory.is_external(target) {
        if let Some(name) = memory.record_external(target) {
            return Step::Stop(format!("external API call: {}", name));
        }
        return Step::Stop(format!("external call at 0x{:x}", target));
    }
    if !memory.is_executable(target) {
        return Step::Stop(format!("jump to non-executable address 0x{:x}", target));
    }
    Step::Jump(target)
}

fn branch_target(
    instruction: &Instruction,
    registers: &Registers,
    memory: &EmuMemory,
    ip: u64,
) -> Option<u64> {
    match instruction.op_kind(0) {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(instruction.near_branch_target())
        }
        _ => read_operand(instruction, 0, registers, memory, ip),
    }
}

fn read_operand(
    instruction: &Instruction,
    index: u32,
    registers: &Registers,
    memory: &EmuMemory,
    ip: u64,
) -> Option<u64> {
    match instruction.op_kind(index) {
        OpKind::Register => read_register(instruction.op_register(index), registers, ip),
        OpKind::Memory => {
            let address = memory_address(instruction, registers, ip)?;
            memory.read_value(address, operand_size(instruction, index))
        }
        OpKind::Immediate8
        | OpKind::Immediate8_2nd
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Some(instruction.immediate64()),
        _ => None,
    }
}

fn write_operand(
    instruction: &Instruction,
    index: u32,
    value: u64,
    registers: &mut Registers,
    memory: &mut EmuMemory,
    ip: u64,
) -> bool {
    match instruction.op_kind(index) {
        OpKind::Register => write_register(instruction.op_register(index), value, registers, ip),
        OpKind::Memory => {
            let Some(address) = memory_address(instruction, registers, ip) else {
                return false;
            };
            memory.write_value(address, operand_size(instruction, index), value)
        }
        _ => false,
    }
}

fn operand_size(instruction: &Instruction, index: u32) -> usize {
    match instruction.op_kind(index) {
        OpKind::Register => instruction.op_register(index).size(),
        OpKind::Memory => instruction.memory_size().size(),
        OpKind::Immediate8 | OpKind::Immediate8_2nd => 1,
        OpKind::Immediate16 | OpKind::Immediate8to16 => 2,
        OpKind::Immediate32 | OpKind::Immediate8to32 => 4,
        OpKind::Immediate64 | OpKind::Immediate8to64 | OpKind::Immediate32to64 => 8,
        _ => 0,
    }
}

fn memory_address(instruction: &Instruction, registers: &Registers, ip: u64) -> Option<u64> {
    if instruction.is_ip_rel_memory_operand() {
        return Some(instruction.ip_rel_memory_address());
    }
    let mut address = instruction.memory_displacement64();
    let base = instruction.memory_base();
    if base != Register::None {
        address = address.wrapping_add(read_register(base, registers, ip)?);
    }
    let index = instruction.memory_index();
    if index != Register::None {
        address = address.wrapping_add(
            read_register(index, registers, ip)?
                .wrapping_mul(instruction.memory_index_scale() as u64),
        );
    }
    Some(address)
}

fn read_register(register: Register, registers: &Registers, ip: u64) -> Option<u64> {
    if register == Register::RIP || register == Register::EIP {
        return Some(ip);
    }
    let index = register_index(register)?;
    let shift = register_shift(register);
    Some((registers.gpr[index] >> shift) & mask(register.size()))
}

fn write_register(register: Register, value: u64, registers: &mut Registers, _ip: u64) -> bool {
    if register == Register::RIP || register == Register::EIP {
        return false;
    }
    let Some(index) = register_index(register) else {
        return false;
    };
    let size = register.size();
    let shift = register_shift(register);
    let mask = mask(size);
    if size == 4 {
        registers.gpr[index] = value & 0xffff_ffff;
    } else if size == 8 {
        registers.gpr[index] = value;
    } else {
        let old = registers.gpr[index];
        registers.gpr[index] = (old & !(mask << shift)) | ((value & mask) << shift);
    }
    true
}

fn register_index(register: Register) -> Option<usize> {
    match register.full_register() {
        Register::RAX => Some(0),
        Register::RBX => Some(1),
        Register::RCX => Some(2),
        Register::RDX => Some(3),
        Register::RSI => Some(4),
        Register::RDI => Some(5),
        Register::RBP => Some(6),
        Register::RSP => Some(7),
        Register::R8 => Some(8),
        Register::R9 => Some(9),
        Register::R10 => Some(10),
        Register::R11 => Some(11),
        Register::R12 => Some(12),
        Register::R13 => Some(13),
        Register::R14 => Some(14),
        Register::R15 => Some(15),
        _ => None,
    }
}

fn register_shift(register: Register) -> u32 {
    match register {
        Register::AH | Register::BH | Register::CH | Register::DH => 8,
        _ => 0,
    }
}

fn stack_width(bitness: u32) -> usize {
    if bitness == 64 {
        8
    } else {
        4
    }
}

fn mask(size: usize) -> u64 {
    match size {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        8 => u64::MAX,
        _ => 0,
    }
}

fn sign_bit(size: usize) -> u64 {
    1u64 << (size * 8 - 1)
}

fn sign_extend(value: u64, size: usize) -> u64 {
    if size == 8 {
        return value;
    }
    let sign = sign_bit(size);
    if value & sign != 0 {
        value | !mask(size)
    } else {
        value & mask(size)
    }
}

fn parity(value: u64) -> bool {
    (value as u8).count_ones().is_multiple_of(2)
}

fn add_result(left: u64, right: u64, size: usize) -> (u64, bool, bool) {
    let result = left.wrapping_add(right);
    let carry = result > mask(size);
    let overflow = (!(left ^ right) & (left ^ result) & sign_bit(size)) != 0;
    (result, carry, overflow)
}

fn sub_result(left: u64, right: u64, size: usize) -> (u64, bool, bool) {
    let result = left.wrapping_sub(right);
    let carry = left < right;
    let overflow = ((left ^ right) & (left ^ result) & sign_bit(size)) != 0;
    (result, carry, overflow)
}

fn condition_met(mnemonic: Mnemonic, flags: Flags) -> bool {
    match mnemonic {
        Mnemonic::Je => flags.zf,
        Mnemonic::Jne => !flags.zf,
        Mnemonic::Jb => flags.cf,
        Mnemonic::Jae => !flags.cf,
        Mnemonic::Jbe => flags.cf || flags.zf,
        Mnemonic::Ja => !flags.cf && !flags.zf,
        Mnemonic::Jl => flags.sf != flags.of,
        Mnemonic::Jge => flags.sf == flags.of,
        Mnemonic::Jle => flags.zf || flags.sf != flags.of,
        Mnemonic::Jg => !flags.zf && flags.sf == flags.of,
        Mnemonic::Js => flags.sf,
        Mnemonic::Jns => !flags.sf,
        Mnemonic::Jo => flags.of,
        Mnemonic::Jno => !flags.of,
        Mnemonic::Jp => flags.pf,
        Mnemonic::Jnp => !flags.pf,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace(code: &[u8], bitness: u32, entry: u64) -> EmulationTrace {
        let regions = vec![Region {
            start: entry,
            data: code.to_vec(),
            writable: false,
            executable: true,
        }];
        let mut memory = EmuMemory::new(regions, Vec::new(), bitness);
        let mut registers = Registers::new(bitness, memory.stack_pointer());
        let mut ip = entry;
        let mut instructions = 0usize;
        let stopped_reason;
        loop {
            if instructions >= MAX_INSTRUCTIONS {
                stopped_reason = "instruction budget reached".to_string();
                break;
            }
            let code = match memory.read_prefix(ip, 15) {
                Some(code) if !code.is_empty() => code,
                _ => {
                    stopped_reason = format!("unmapped instruction fetch at 0x{:x}", ip);
                    break;
                }
            };
            let mut decoder = Decoder::with_ip(bitness, &code, ip, DecoderOptions::NONE);
            let instruction = decoder.decode();
            if instruction.is_invalid() || instruction.len() == 0 {
                stopped_reason = format!("invalid instruction at 0x{:x}", ip);
                break;
            }
            instructions += 1;
            match execute_instruction(&instruction, &mut registers, &mut memory, ip) {
                Step::Next => ip = instruction.next_ip(),
                Step::Jump(target) => ip = target,
                Step::Stop(reason) => {
                    stopped_reason = reason;
                    break;
                }
            }
        }
        let recovered_strings = memory.extract_strings();
        EmulationTrace {
            file_path: "test".into(),
            file_type: "raw".into(),
            architecture: if bitness == 64 {
                "x86_64".into()
            } else {
                "x86".into()
            },
            entrypoint: format!("0x{:x}", entry),
            instructions,
            stopped_reason,
            recovered_strings,
            api_calls: memory.api_calls.clone(),
            indicators: Vec::new(),
            attack: Vec::new(),
        }
    }

    #[test]
    fn recovers_stack_string_from_push() {
        let code = [
            0x48, 0xb8, b'H', b'e', b'l', b'l', b'o', b'!', 0x00, 0x00, 0x50, 0xc3,
        ];
        let trace = trace(&code, 64, 0x1000);
        assert!(trace
            .recovered_strings
            .iter()
            .any(|value| value == "Hello!"));
    }

    #[test]
    fn emulates_xor_loop() {
        let code = [
            0x48, 0xb8, b'X', b'X', b'X', b'X', b'X', b'X', 0x00, 0x00, 0x50, 0x48, 0x31, 0xc0,
            0x48, 0x31, 0xdb, 0x48, 0x31, 0xc9, 0x48, 0x31, 0xd2, 0xc3,
        ];
        let trace = trace(&code, 64, 0x1000);
        assert!(trace.instructions > 0);
    }

    #[test]
    fn stops_on_unsupported_instruction() {
        let trace = trace(&[0x0f, 0x0b], 64, 0x1000);
        assert!(trace.stopped_reason.contains("ud2"));
    }

    #[test]
    fn stops_on_instruction_budget() {
        let code = vec![0xeb, 0xfe];
        let trace = trace(&code, 64, 0x1000);
        assert!(trace.stopped_reason.contains("budget"));
        assert_eq!(trace.instructions, MAX_INSTRUCTIONS);
    }
}
