
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <tuple>
#include <cstdint>
#include <iomanip>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

using Patch = std::tuple<uint64_t, uint8_t, uint8_t>; // offset, oldByte, newByte

bool ParsePatchLine(const std::string& line, uint64_t& offset, uint8_t& oldB, uint8_t& newB) {
    size_t colon = line.find(':');
    size_t arrow = line.find("->");
    if (colon == std::string::npos || arrow == std::string::npos) return false;
    try {
        std::string offStr = line.substr(0, colon);
        std::string oldStr = line.substr(colon + 1, arrow - (colon + 1));
        std::string newStr = line.substr(arrow + 2);
        offset = std::stoull(offStr, nullptr, 16);
        oldB = static_cast<uint8_t>(std::stoul(oldStr, nullptr, 16));
        newB = static_cast<uint8_t>(std::stoul(newStr, nullptr, 16));
        return true;
    } catch (...) {
        return false;
    }
}

bool LoadPatchesFromFile(const std::string& path, std::vector<Patch>& patches) {
    std::ifstream in(path);
    if (!in.is_open()) return false;
    std::string line;
    size_t lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        if (line.empty()) continue;
        uint64_t off; uint8_t oldB, newB;
        if (!ParsePatchLine(line, off, oldB, newB)) {
            std::cerr << "Invalid format in " << path << " line " << lineno << ": " << line << "\n";
            return false;
        }
        patches.emplace_back(off, oldB, newB);
    }
    return true;
}

DWORD FindProcessId(const std::string& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (processName == pe.szExeFile) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return 0;
}

void ListProcesses() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot\n";
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    std::cout << "Running processes:\n";
    std::cout << "PID\tProcess Name\n";
    std::cout << "---\t------------\n";

    if (Process32First(hSnapshot, &pe)) {
        do {
            std::cout << pe.th32ProcessID << "\t" << pe.szExeFile << "\n";
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
}

uint64_t GetModuleBaseAddress(DWORD pid, const std::string& moduleName = "") {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);

    uint64_t baseAddress = 0;

    if (Module32First(hSnapshot, &me)) {
        do {
            if (moduleName.empty() || moduleName == me.szModule) {
                baseAddress = reinterpret_cast<uint64_t>(me.modBaseAddr);
                break;
            }
        } while (Module32Next(hSnapshot, &me));
    }

    CloseHandle(hSnapshot);
    return baseAddress;
}

bool PatchProcess(DWORD pid, const std::vector<Patch>& patches, const std::string& moduleName = "") {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process PID " << pid << " (Error: " << GetLastError() << ")\n";
        return false;
    }
    uint64_t baseAddress = GetModuleBaseAddress(pid, moduleName);
    if (!baseAddress) {
        std::cerr << "Failed to get base address for module: " << (moduleName.empty() ? "main executable" : moduleName) << "\n";
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "Base address of " << (moduleName.empty() ? "main executable" : moduleName) << ": 0x" << std::hex << baseAddress << std::dec << "\n";

    bool ok = true;
    for (const auto& p : patches) {
        uint64_t offset = std::get<0>(p);
        uint8_t oldB = std::get<1>(p);
        uint8_t newB = std::get<2>(p);

        uint64_t patchAddress = baseAddress + offset;

        uint8_t currentByte;
        SIZE_T bytesRead;
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(patchAddress), &currentByte, sizeof(currentByte), &bytesRead)) {
            std::cerr << "Failed to read memory at 0x" << std::hex << patchAddress << " (Error: " << GetLastError() << ")\n";
            ok = false;
            continue;
        }

        if (currentByte != oldB) {
            std::cerr << "Warning: byte mismatch at 0x" << std::hex << patchAddress
                      << " (offset 0x" << offset << ")"
                      << " expected 0x" << std::setw(2) << std::setfill('0') << (int)oldB
                      << " but found 0x" << std::setw(2) << std::setfill('0') << (int)currentByte << "\n";
            // Можно раскомментировать следующую строку для отладки:
            // ok = false; continue;
        }
        DWORD oldProtect;
        // Меняем защиту памяти на запись
        if (!VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(patchAddress), sizeof(newB), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            std::cerr << "Failed to change memory protection at 0x" << std::hex << patchAddress << " (Error: " << GetLastError() << ")\n";
            ok = false;
            continue;
        }

        SIZE_T bytesWritten;
        if (!WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(patchAddress), &newB, sizeof(newB), &bytesWritten)) {
            std::cerr << "Failed to write memory at 0x" << std::hex << patchAddress << " (Error: " << GetLastError() << ")\n";
            VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(patchAddress), sizeof(newB), oldProtect, &oldProtect);
            ok = false;
            continue;
        }

        VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(patchAddress), sizeof(newB), oldProtect, &oldProtect);

        std::cout << "Patched 0x" << std::hex << patchAddress
                  << " (offset 0x" << offset << ")"
                  << " : 0x" << std::setw(2) << std::setfill('0') << (int)oldB
                  << " -> 0x" << std::setw(2) << std::setfill('0') << (int)newB << "\n";
    }

    CloseHandle(hProcess);
    return ok;
}

int main() {
    std::cout << "=== Process Memory Patcher ===\n";
    std::cout << "=== Made by dev0Rot ===\n";
    std::cout << "=== https://github.com/backdoor831246 ===\n";
    std::string patchFile;
    
    std::cout << "Enter path to .1337 file: ";
    std::getline(std::cin, patchFile);

    std::vector<Patch> patches;
    if (!LoadPatchesFromFile(patchFile, patches)) {
        std::cerr << "Failed to load patches from: " << patchFile << "\n";
        return 1;
    }

    int choice;
    std::cout << "\nChoose input method:\n";
    std::cout << "1. Process Name\n";
    std::cout << "2. Process ID (PID)\n";
    std::cout << "3. List all processes\n";
    std::cout << "Choice: ";
    std::cin >> choice;
    std::cin.ignore();

    DWORD pid = 0;
    std::string processName;

    switch (choice) {
        case 1: {
            std::cout << "Enter process name (e.g., notepad.exe): ";
            std::getline(std::cin, processName);
            pid = FindProcessId(processName);
            if (!pid) {
                std::cerr << "Process not found: " << processName << "\n";
                return 1;
            }
            break;
        }
        case 2: {
            std::cout << "Enter Process ID: ";
            std::cin >> pid;
            std::cin.ignore();
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (!hProcess) {
                std::cerr << "Process with PID " << pid << " not found\n";
                return 1;
            }
            CloseHandle(hProcess);
            break;
        }
        case 3: {
            ListProcesses();
            return 0;
        }
        default: {
            std::cerr << "Invalid choice\n";
            return 1;
        }
    }

    std::string moduleName;
    std::cout << "Enter module name to patch (leave empty for main executable): ";
    std::getline(std::cin, moduleName);

    std::cout << "Patching process PID " << pid << "...\n";
    
    if (!PatchProcess(pid, patches, moduleName)) {
        std::cerr << "Process patching failed.\n";
        return 1;
    }

    std::cout << "Process patching completed successfully!\n";
    return 0;
}