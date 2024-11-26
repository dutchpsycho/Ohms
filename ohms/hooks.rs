use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;

use crate::parser::{Section, PEInfo, find_section_name, va_from_raw_address};
use crate::disassembler::disassemble_bytes;
use crate::routines::{is_inline_hook, is_syscall_routine};

#[derive(Debug, Clone)]
pub struct HookInfo {
    pub address: usize,
    pub ida_address: String,
    pub bytes: Vec<u8>,
    pub disassembly: Vec<String>,
}

pub fn dump_hooks(buffer: &[u8], base: usize, sections: &[Section], pe_info: Option<PEInfo>, file_path: &str) {
    let filename = fs::canonicalize(file_path)
        .and_then(|path| {
            path.file_name()
                .map(|os_str| os_str.to_string_lossy().into_owned())
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "failed to get file name"))
        })
        .unwrap_or_else(|_| "wtf".to_string());

    let outname = format!("{}-Dump.Ohms", filename);
    let mut out_file = File::create(&outname).expect("failed to make output file");

    writeln!(out_file, "File: {}", filename).unwrap();
    writeln!(out_file, "File Size: {} bytes", buffer.len()).unwrap();

    if let Some(pe_info) = &pe_info {
        writeln!(out_file, "Image Base: 0x{:x}", pe_info.image_base).unwrap();
    } else {
        writeln!(out_file, "Image Base: ?").unwrap();
    }

    writeln!(out_file, "Module Base: 0x{:x}", base).unwrap();

    writeln!(out_file, "\n<======== Sections ========>\n").unwrap();
    for section in sections {
        writeln!(
            out_file,
            "Section: {}\n  Virtual Address: 0x{:x}\n  Virtual Size: 0x{:x}\n  Raw Offset: 0x{:x}\n  Raw Size: 0x{:x}\n",
            section.name, section.virtual_address, section.virtual_size, section.raw_offset, section.raw_size
        )
            .unwrap();
    }

    writeln!(out_file, "\n<======== Inline Hooks ========>\n").unwrap();
    let mut inlhook_bysec: HashMap<String, Vec<HookInfo>> = HashMap::new();
    let mut syscall_bysect: HashMap<String, Vec<HookInfo>> = HashMap::new();
    let mut uhashes = HashSet::new();

    let image_base: usize = pe_info.as_ref().map_or(base, |info| info.image_base);

    let mut i = 0;
    while i < buffer.len() {
        if let Some((start, end)) = is_syscall_routine(buffer, i) {
            let hook_bytes = buffer[start..end.min(buffer.len())].to_vec();
            let relative_address = start;
            if let Some(virtual_address) = va_from_raw_address(relative_address, sections, image_base) {
                let ida_address = format!("0x{:016x}", virtual_address);

                if uhashes.insert(format!("{:x}:{:x?}", relative_address, hook_bytes)) {
                    let section_name = find_section_name(sections, virtual_address);
                    let disassembly = disassemble_bytes(&hook_bytes, virtual_address);

                    syscall_bysect
                        .entry(section_name.clone())
                        .or_default()
                        .push(HookInfo {
                            address: virtual_address,
                            ida_address,
                            bytes: hook_bytes,
                            disassembly,
                        });
                }
            }
            i = end;
            continue;
        }

        if is_inline_hook(buffer, i) {
            let hook_bytes = buffer[i..i + 32.min(buffer.len() - i)].to_vec();
            let relative_address = i;
            if let Some(virtual_address) = va_from_raw_address(relative_address, sections, image_base) {
                let ida_address = format!("0x{:016x}", virtual_address);

                if uhashes.insert(format!("{:x}:{:x?}", relative_address, hook_bytes)) {
                    let section_name = find_section_name(sections, virtual_address);
                    let disassembly = disassemble_bytes(&hook_bytes, virtual_address);

                    inlhook_bysec
                        .entry(section_name.clone())
                        .or_default()
                        .push(HookInfo {
                            address: virtual_address,
                            ida_address,
                            bytes: hook_bytes,
                            disassembly,
                        });

                    i += 31;
                    continue;
                }
            }
        }

        i += 1;
    }

    for (section, hooks) in inlhook_bysec {
        writeln!(out_file, "\n== Section: {} ==\n", section).unwrap();
        for hook in hooks {
            writeln!(
                out_file,
                "Hook @ 0x{:x} (IDA: {})\nBytes: [{}]\nDisassembly:\n{}\n",
                hook.address,
                hook.ida_address,
                hook.bytes
                    .iter()
                    .map(|byte| format!("{:02x}", byte))
                    .collect::<Vec<_>>()
                    .join(" "),
                hook.disassembly.join("\n")
            )
                .unwrap();
        }
    }

    writeln!(out_file, "\n<======== Syscall Routines ========>\n").unwrap();
    for (section, hooks) in syscall_bysect {
        writeln!(out_file, "\n== Section: {} ==\n", section).unwrap();
        for hook in hooks {
            writeln!(
                out_file,
                "Hook @ 0x{:x} (IDA: {})\nBytes: [{}]\nDisassembly:\n{}\n",
                hook.address,
                hook.ida_address,
                hook.bytes
                    .iter()
                    .map(|byte| format!("{:02x}", byte))
                    .collect::<Vec<_>>()
                    .join(" "),
                hook.disassembly.join("\n")
            )
                .unwrap();
        }
    }

    println!("\nwritten to -> {}", outname);
}