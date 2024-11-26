mod hooks;
mod parser;
mod disassembler;
mod routines;

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

fn main() {
    println!("made by hatedamon lolol :p\n");

    println!("name of dll/exe? ");
    let mut file_name = String::new();
    io::stdin()
        .read_line(&mut file_name)
        .expect("failed to read input");
    let file_name = file_name.trim();

    if !Path::new(file_name).exists() {
        println!("failed to open the file, did u even put this in the right dir");
        wait_for_exit();
        return;
    }

    let mut file = File::open(file_name).expect("failed to open the file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("failed to read the file");

    println!("wna rebase?");
    println!("entr a rebase, default is 0x0");

    let mut base_input = String::new();
    io::stdin()
        .read_line(&mut base_input)
        .expect("wtf?");
    let base_address: usize = if let Ok(value) = usize::from_str_radix(base_input.trim_start_matches("0x"), 16) {
        println!("k, I use 0x{:x}", value);
        value
    } else {
        println!("k, I use 0x0");
        0x0
    };

    let (sections, pe_info) = parser::get_sections_and_pe_info(&buffer, base_address);
    hooks::dump_hooks(&buffer, base_address, &sections, pe_info, file_name);

    println!("done :3");
    wait_for_exit();
}

fn wait_for_exit() {
    println!("\npress enter to exit...");
    let mut exit = String::new();
    io::stdin().read_line(&mut exit).unwrap();
}