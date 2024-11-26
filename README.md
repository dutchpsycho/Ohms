# Ohms

**Ohms** is a Rust-based tool created for analyzing Windows dlls & exes. It identifies and dumps various types of hooks (e.g., inline hooks, syscall routines) present within the target, providing disassembly for each detected hook.

## Features

- **PE Parsing:** Extracts sections and PE information.
- **Hook Detection:** Identifies inline hooks and syscall routines using sig patterns.
- **Disassembly:** Utilizes Capstone to disassemble detected hook bytes for quick analysis.
- **Output** Outputs a [TargetName]-Dump.Ohms file, which can be opened in Notepad or any other text analyser.

## Installation

- **Rust:** Ensure that Rust is installed on your system. Install with RustInstaller.bat

### Clone the Repository

```bash
git clone https://github.com/dutchpsycho/Ohms.git
cd Ohms
```

### Build the Project

```bash
cargo build --release
```

Output located in /target/release (Ohms.exe)

## Usage

1. **Locate your target dll/exe**

   Place Ohms.exe in the same directory as your exe/dll
   Run Ohms.exe & input the target name

## Disclaimer

**Ohms** is intended for educational and authorized testing purposes only. Ensure you have permission to analyze and process anything using this tool.
