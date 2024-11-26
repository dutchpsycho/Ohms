use std::str;

#[derive(Debug, Clone)]
pub struct Section {
    pub virtual_address: usize,
    pub virtual_size: usize,
    pub raw_offset: usize,
    pub raw_size: usize,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct PEInfo {
    pub image_base: usize,
}

pub fn get_sections_and_pe_info(buffer: &[u8], _base: usize) -> (Vec<Section>, Option<PEInfo>) {
    let mut sections = Vec::new();

    if buffer.len() < 0x40 {
        eprintln!("invalid PE, no dos header found");
        return (sections, None);
    }

    let dos_header = &buffer[0..0x40];
    let e_lfanew = u32::from_le_bytes(dos_header[0x3c..0x40].try_into().unwrap()) as usize;

    if buffer.len() < e_lfanew + 0x108 {
        eprintln!("invalid PE, not NT headers found");
        return (sections, None);
    }

    let nt_headers = &buffer[e_lfanew..];
    let file_header_offset = e_lfanew + 0x4;

    let optional_header_offset = file_header_offset + 0x14; // file header 20byte
    let magic = u16::from_le_bytes(nt_headers[optional_header_offset..optional_header_offset + 2].try_into().unwrap());

    let image_base = if magic == 0x20B {
        // PE32+ (64-bit)
        u64::from_le_bytes(nt_headers[optional_header_offset + 0x18..optional_header_offset + 0x20].try_into().unwrap()) as usize
    } else {
        // PE32 (32-bit)
        u32::from_le_bytes(nt_headers[optional_header_offset + 0x1C..optional_header_offset + 0x20].try_into().unwrap()) as usize
    };

    let section_alignment = u32::from_le_bytes(nt_headers[optional_header_offset + 0x20..optional_header_offset + 0x24].try_into().unwrap()) as usize;

    let pe_info = PEInfo {
        image_base,
    };

    let number_of_sections = u16::from_le_bytes(nt_headers[0x6..0x8].try_into().unwrap()) as usize;

    for i in 0..number_of_sections {
        let section_offset = e_lfanew + 0x108 + (i * 0x28);
        if section_offset + 0x28 > buffer.len() {
            eprintln!("section header out of bounds");
            break;
        }

        let section = &buffer[section_offset..section_offset + 0x28];
        let virtual_address = u32::from_le_bytes(section[0xc..0x10].try_into().unwrap()) as usize;
        let virtual_size = u32::from_le_bytes(section[0x8..0xc].try_into().unwrap()) as usize;
        let raw_offset = u32::from_le_bytes(section[0x14..0x18].try_into().unwrap()) as usize;
        let raw_size = u32::from_le_bytes(section[0x10..0x14].try_into().unwrap()) as usize;
        let section_name = str::from_utf8(&section[0..8])
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_string();

        let aligned_virtual_size = ((virtual_size + section_alignment - 1) / section_alignment) * section_alignment;

        sections.push(Section {
            virtual_address,
            virtual_size: aligned_virtual_size,
            raw_offset,
            raw_size,
            name: section_name.clone(),
        });

        println!(
            "Section -> {} (VA: 0x{:x}, Raw: 0x{:x} - 0x{:x})",
            section_name, image_base + virtual_address, raw_offset, raw_offset + raw_size
        );
    }

    (sections, Some(pe_info))
}

pub fn find_section_name(sections: &[Section], address: usize) -> String {
    sections
        .iter()
        .find(|s| address >= s.virtual_address && address < s.virtual_address + s.virtual_size)
        .map(|s| s.name.clone())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn va_from_raw_address(raw_address: usize, sections: &[Section], image_base: usize) -> Option<usize> {
    for section in sections {
        let raw_start = section.raw_offset;
        let raw_end = raw_start + section.raw_size;

        if raw_address >= raw_start && raw_address < raw_end {
            let offset_within_section = raw_address - raw_start;
            let virtual_address = section.virtual_address + offset_within_section + image_base;
            return Some(virtual_address);
        }
    }
    None
}