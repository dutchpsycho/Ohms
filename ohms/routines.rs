/*

inline hooking:
    * practical malware analysis, chapter 9

tls callback hooks:
    * practical malware analysis, chapter 18

routine patterns:
    * winternals, pt 1, chapter 5

vmt hooks:
    * winternals, pt 2, chapter 7

eat hooks:
    * practical malware analysis, chapter 18
    * https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-address-table

obfuscation patterns:
    * https://www.fireeye.com/blog/threat-research.html

*/

pub fn is_inline_hook(buffer: &[u8], offset: usize) -> bool {
    offset + 4 < buffer.len()
        && buffer[offset] == 0x4C
        && buffer[offset + 1] == 0x8B
        && buffer[offset + 2] == 0xD1
        && buffer[offset + 3] == 0xB8
}

pub fn is_syscall_routine(buffer: &[u8], offset: usize) -> Option<(usize, usize)> {
    if offset + 2 <= buffer.len() && buffer[offset] == 0x0F && buffer[offset + 1] == 0x05 {
        let mut start = offset;
        let mut end = offset + 2;

        while start > 0 && start > offset.saturating_sub(200) {
            if buffer[start] == 0x48 && buffer[start + 1] == 0x89 {
                break;
            }
            if buffer[start] == 0xC3 || buffer[start] == 0xC2 {
                break;
            }
            start -= 1;
        }

        while end < buffer.len() && end < offset + 200 {
            if buffer[end] == 0xC3 || buffer[end] == 0xC2 {
                end += 1;
                break;
            }
            if buffer[end] == 0x90 || buffer[end] == 0xCC {
                break;
            }
            end += 1;
        }

        if start < offset && end > offset + 2 {
            return Some((start, end));
        }
    }

    None
}

pub fn is_iat_hook(buffer: &[u8], offset: usize, iat_addresses: &[usize]) -> bool {
    if offset + 5 <= buffer.len() {
        let opcode = buffer[offset];

        // jmp rel32 | call rel32
        if opcode == 0xE9 || opcode == 0xE8 {
            let rel32 = i32::from_le_bytes(buffer[offset + 1..offset + 5].try_into().unwrap_or_default());
            let target_address = offset.wrapping_add(5).wrapping_add(rel32 as usize);
            if iat_addresses.contains(&target_address) {
                return true;
            }
        }

        // mov reg, addr; xor reg, key; jmp reg
        if offset + 12 <= buffer.len() {
            let mov_pattern = buffer[offset] == 0x48 && buffer[offset + 1] == 0xB8; // mov rax, imm64
            let xor_pattern = buffer[offset + 10] == 0x31 || buffer[offset + 10] == 0x33; // xor reg, key
            let jmp_pattern = buffer[offset + 12] == 0xFF && buffer[offset + 13] & 0xF8 == 0xE0; // jmp reg
            if mov_pattern && xor_pattern && jmp_pattern {
                return true;
            }
        }
    }

    false
}

pub fn is_ext_hook(buffer: &[u8], offset: usize) -> bool {
    if offset + 12 <= buffer.len() {
        // mov reg, addr; jmp reg (extended to check registers other than rax, looking at u hyperion)
        let mov_pattern = buffer[offset] == 0x48
            && buffer[offset + 1] & 0xF8 == 0xB8; // mov reg, imm64 (supports alternative registers)
        let jmp_pattern = buffer[offset + 10] == 0xFF
            && (buffer[offset + 11] & 0xF8 == 0xE0); // jmp reg (alternative registers)

        if mov_pattern && jmp_pattern {
            return true;
        }

        // xor obfuscation; xor reg, key; jmp reg
        if buffer[offset] == 0x31 || buffer[offset] == 0x33 { // xor reg, reg
            if buffer[offset + 2] == 0xFF && buffer[offset + 3] & 0xF8 == 0xE0 { // jmp reg
                return true;
            }
        }

        // int3 padding
        if buffer[offset] == 0xCC {
            let mut skip = 1;
            while offset + skip < buffer.len() && buffer[offset + skip] == 0xCC {
                skip += 1;
            }
            if skip > 1 && offset + skip < buffer.len() {
                // check again
                return is_ext_hook(buffer, offset + skip);
            }
        }
    }

    false
}

pub fn is_tls_hook(tls_callbacks: &[usize], valid_ranges: &[(usize, usize)], buffer: &[u8]) -> bool {
    for &callback in tls_callbacks {
        if !valid_ranges.iter().any(|&(start, end)| callback >= start && callback < end) {
            return true;
        }

        if let Some(offset) = buffer.iter().position(|&b| b as usize == callback) {
            if offset + 12 <= buffer.len() {
                let mov_pattern = buffer[offset] == 0x48 && buffer[offset + 1] & 0xF8 == 0xB8; // mov reg, imm64
                let xor_pattern = buffer[offset + 10] == 0x31 || buffer[offset + 10] == 0x33; // xor reg, key
                let jmp_pattern = buffer[offset + 12] == 0xFF && buffer[offset + 13] & 0xF8 == 0xE0; // jmp reg
                if mov_pattern && xor_pattern && jmp_pattern {
                    return true;
                }
            }
        }
    }
    false
}

pub fn is_vmt_hook(vmt: &[usize], valid_functions: &[usize], buffer: &[u8]) -> bool {
    for &entry in vmt {
        if !valid_functions.contains(&entry) {
            if let Some(offset) = buffer.iter().position(|&b| b as usize == entry) {
                if offset + 12 <= buffer.len() {
                    let mov_pattern = buffer[offset] == 0x48 && buffer[offset + 1] & 0xF8 == 0xB8; // mov reg, imm64
                    let xor_pattern = buffer[offset + 10] == 0x31 || buffer[offset + 10] == 0x33; // xor reg, key
                    let jmp_pattern = buffer[offset + 12] == 0xFF && buffer[offset + 13] & 0xF8 == 0xE0; // jmp reg
                    if mov_pattern && xor_pattern && jmp_pattern {
                        return true;
                    }
                }
            }
        }
    }
    false
}

pub fn is_eat_hook(export_table: &[usize], valid_exports: &[usize], buffer: &[u8]) -> bool {
    for &entry in export_table {
        if !valid_exports.contains(&entry) {
            if let Some(offset) = buffer.iter().position(|&b| b as usize == entry) {
                if offset + 12 <= buffer.len() {
                    let mov_pattern = buffer[offset] == 0x48 && buffer[offset + 1] & 0xF8 == 0xB8; // mov reg, imm64
                    let xor_pattern = buffer[offset + 10] == 0x31 || buffer[offset + 10] == 0x33; // xor reg, key
                    let jmp_pattern = buffer[offset + 12] == 0xFF && buffer[offset + 13] & 0xF8 == 0xE0; // jmp reg
                    if mov_pattern && xor_pattern && jmp_pattern {
                        return true;
                    }
                }
            }
        }
    }
    false
}