use capstone::prelude::*;

pub fn disassemble_bytes(bytes: &[u8], address: usize) -> Vec<String> {
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel) // this supports amd dont cry
        .build()
        .expect("failed to create capstone obj");

    let instructions = cs.disasm_all(bytes, address as u64)
        .expect("failed to disassemble");

    instructions
        .iter()
        .map(|insn| format!("{:#x}: {}\t{}", insn.address(), insn.mnemonic().unwrap_or(""), insn.op_str().unwrap_or("")))
        .collect()
}