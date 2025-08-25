#include "pch.hpp"

// USAGE:
//
// You must place every VAC dll in the directory of the compiled binary, 
// and they must be named VAC-1.dll - VAC-14.dll, or however many dlls you 
// want to scan. The number of dlls should match the number of signatures.
// 
// The purpose of this is to make it easy to generate a unique signature for 
// each dll, allowing for easy self identification within hooks, as you can see 
// in the VAC logger included in this solution. A really good way to get unique 
// signatures is copying the bytes of encrypted strings, which are entirely unique 
// to the modules they're present in. Another good way is finding register based 
// calls to encrypted imports, because most modules have at least a couple functions 
// that only they call.
//

#define MODULE_COUNT 14

bool ScanFile(const char* sig, const char* base, size_t FileSz, size_t SigSz)
{
    for (const char* end = &base[FileSz] - SigSz; base < end; ++base)
    {
        bool found = true;

        for (int i = 0, PtrnIndex = 0; i < SigSz; ++i, ++PtrnIndex)
        {
            if (sig[PtrnIndex] == '?')
            {
                ++PtrnIndex;
                continue;
            }

            if (static_cast<unsigned char>(base[i]) != std::stoi(&sig[PtrnIndex], nullptr, 16))
            {
                found = false;
                break;
            }

            PtrnIndex += 2;
        }

        if (found) return true;
    }

    return false;
}

int main()
{
    // There should be one signature per module that you want checked.
    // Every module that the signature exists in will be listed, and at the end it will
    // list every module with no matching signature or multiple matches.

    constexpr std::string_view ModuleSigs[] =
    {
        "C7 85 46 FF FF FF 6B 43 4B 49 66 C7 85 4A FF FF FF 54 5F 88 95 4C FF FF FF 88 45 84 88 5D 85",                // 1  - NtQuerySystemInformation, volume logging, etc
        "7E 2F 8B 45 54 03 C6 51 8B CD FF B4 C5 FC 0F 00 00 FF B4 C5 F8 0F 00 00 6A 00 FF 74 85 58 E8",                // 2  - tlhelp process enumeration & NtQuerySystemInformation(SystemHandleInformation)
        "83 8B 38 02 00 00 20 BF 06 02 00 00 F6 44 24 1B 04 0F 84 D7 01 00 00 8D 44 24 14 50 6A 4C 8D 83 58 04 00 00", // 3  - PEB rpm's from flagged processes enumerated by previous module
        "6A 68 88 44 24 49 88 44 24 50 88 44 24 28 88 44 24 2E 88 44 24 3A 88 44 24 40 58 6A 36 66 89 44 24 70 58",    // 4  - MapViewOfFile calls
        "8D 4C 24 1C 51 55 8B 80 64 01 00 00 FF D0 85 C0 75 D7 8B 8B 50 02 00 00 85 C9 0F 8E D6 00 00 00 C1 E1 05",    // 5  - Module32FirstW calls
        "03 C3 FF D0 83 C4 0C 83 4E 14 20 8B 45 30 A8 40 74 13 68 00 00 01 00 FF 77 08 53 FF ? ? ? ? ? 83 4E 14",      // 6  - Shellcode stuff
        "88 84 24 B9 00 00 00 C7 44 24 4C 48 68 88 06 C7 44 24 50 06 06 06 06 C7 44 24 54 06 06 06 8B C7 44 24 58 E9", // 7  - BCD queries (HKLM\BCD00000000\Objects)
        "8B 45 0C 31 46 14 64 8B 0D 18 00 00 00 8B 49 30 0F B6 49 02 89 4D FC 8B 45 FC 89 46 18 8B 45 08 8B 40 64",    // 8  - SharedUserData tick count checks & PEB::BeingDebugged
        "8B 08 3B 4C F3 28 75 0D 8A 4C 24 0F 38 48 04 75 04 FF 44 F3 2C 47 3B 7C 24 20 72 D9 8B 74 24 14 8B 4C 24 18", // 9  - SYSCALL/SYSENTER stubs with indexes located from first module
        "8B C1 C7 44 24 3C 6E 77 7A 61 88 4C 24 40 C7 44 24 5C 7A 5B 48 7D C7 44 24 60 52 5F 4D 4D 66 C7 44 24 64 61", // 10 - SetupDiGetClassDevsA call
        "6A 0E 66 89 44 24 62 58 66 89 44 24 5C 8D 44 24 5C 89 84 24 80 00 00 00 8D 44 24 78 50 68 01 00 02 00 8D 44", // 11 - NtQueryDirectoryObject
        "33 FF 5E 47 EB 42 A1 ? ? ? ? FF 50 70 8B F8 A1 ? ? ? ? 6A 01 57 FF 90 B8 01 00 00 8B CB",                     // 12 - cpuid
        "8B 4C 24 10 68 00 01 00 00 89 5C 24 18 8D 56 1C 8B 0C 29 E8 ? ? ? ? 8B 4F 20 8D 96 1C 01 00 00 C7 04 24 00",  // 13 - QueryServiceConfigW (one routine)
        "74 28 8B C1 33 84 24 90 00 00 00 25 FF FF FF 7F 33 C1 89 46 28 8D 44 24 7C 6A 10 50 8D 46 74 50 E8"           // 14 - 3 routines & direct wvsprintfW import
    };

    static_assert(sizeof(ModuleSigs) / sizeof(std::string_view) == MODULE_COUNT, "Sig list doesn't match module count");

    // Loading the module images into memory

    char* ModuleBases[MODULE_COUNT]{};
    size_t ModuleSizes[MODULE_COUNT]{};

    for (int i = 0; i < MODULE_COUNT; ++i)
    {
        const std::string FileName = (std::string("VAC-") + std::to_string(i + 1)) + ".dll";
        std::ifstream file(FileName, std::ios::in | std::ios::binary | std::ios::ate);

        if (!file.is_open())
        {
            std::cout << "WARNING: " << FileName << " not found\n";
            continue;
        }

        const size_t sz = file.tellg();
        char* base = new char[sz];
        ModuleSizes[i] = sz;
        ModuleBases[i] = base;

        file.seekg(0, std::ios::beg);
        file.read(base, sz);
        file.close();
    }

    // Scanning for pattern matches

    int MatchCounts[MODULE_COUNT]{}; // tracks the amount of times a pattern matches each module

    for (const std::string_view& sig : ModuleSigs)
    {
        std::cout << "[!] " << sig << '\n';

        const int sz = std::count(sig.begin(), sig.end(), ' ') + 1;

        for (int i = 0; i < MODULE_COUNT; ++i)
        {
            if (!ModuleBases[i]) continue;

            if (ScanFile(sig.data(), ModuleBases[i], ModuleSizes[i], sz))
            {
                std::cout << "MATCH: VAC-" << i + 1 << ".dll\n";
                ++MatchCounts[i];
            }
        }

        std::cout << '\n';
    }

    // Freeing memory and listing repeat/unmatched modules

    for (int i = 0; i < MODULE_COUNT; ++i)
    {
        if (ModuleBases[i])
        {
            delete[] ModuleBases[i];
        }
        else continue;

        if (MatchCounts[i] > 1)
        {
            std::cout << "REPEAT MATCHES: VAC-" << i + 1 << ".dll\n";
        }
        else if (!MatchCounts[i])
        {
            std::cout << "NO MATCHES: VAC-" << i + 1 << ".dll\n";
        }
    }

    return 0;
}