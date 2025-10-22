# .1337-patcher
# Process Memory Patcher

A Windows utility for applying binary patches to running processes in memory. Created by **dev0Rot**.

[![GitHub](https://img.shields.io/badge/GitHub-dev0Rot-blue?style=flat&logo=github)](https://github.com/backdoor831246)

## Features

- **Memory Patching**: Apply patches directly to running processes
- **Flexible Targeting**: Find processes by name or PID
- **Module Support**: Patch main executable or specific DLLs
- **Validation**: Verify existing bytes before patching
- **Process Listing**: View all running processes
- **Safe Memory Operations**: Proper memory protection handling

## Usage

### Basic Usage

1. Run the patcher:
   ```cmd
   myprogram.exe

    Enter the path to your patch file (.1337 format)

    Choose input method:

        1. Process Name: Enter the executable name (e.g., notepad.exe)

        2. Process ID: Enter the specific PID

        3. List Processes: View all running processes

    (Optional) Specify module name for DLL patching, or leave empty for main executable

Patch File Format

Create a text file with .1337 extension containing patches in the format:
text

OFFSET:OLD_BYTE->NEW_BYTE

Example (patches.1337):
text

00000000000015C6:74->75
0000000000001A2F:89->90
0000000000001A30:C3->90

Command Line Compilation
cmd

g++ main.cpp -o process_patcher.exe

Requirements

    Windows OS

    GCC or MinGW for compilation

    Administrator privileges (for patching protected processes)

Building

    Compile the source:
    cmd

g++ main.cpp -o process_patcher.exe -lpsapi

    For manifest support, place app.manifest alongside the executable and rename it to process_patcher.exe.manifest

Security Notes

    Requires appropriate permissions to access target processes

    Use responsibly and only on processes you own

    Always verify patches before applying to production systems

License

This project is provided for educational and legitimate use cases. Users are responsible for complying with applicable laws and software licenses.

Developer: dev0Rot
GitHub: https://github.com/backdoor831246
