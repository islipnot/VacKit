#include "pch.hpp"
#include "tools.hpp"

// Pattern scanning

static BYTE* FindPatternInternal(BYTE* base, SIZE_T ScanSize, PCSTR pattern, int PatternSz)
{
    for (BYTE* const end = (base + ScanSize) - PatternSz; base < end; ++base)
    {
        bool found = true;

        for (int i = 0, PtrnIndex = 0; i < PatternSz; ++i, ++PtrnIndex)
        {
            if (pattern[PtrnIndex] == '?')
            {
                ++PtrnIndex;
                continue;
            }

            if (base[i] != std::stoi(&pattern[PtrnIndex], nullptr, 16))
            {
                found = false;
                break;
            }

            PtrnIndex += 2;
        }
        
        if (found) return base;
    }
    
    return nullptr;
}

BYTE* FindPattern(PCWSTR ModuleName, PCSTR pattern, int PatternSize, int offset, void* ScanRegion)
{
    if (ModuleName)
    {
        const HMODULE hModule = GetModuleHandle(ModuleName);
        MODULEINFO ModuleInfo;

        if (hModule && GetModuleInformation(GetCurrentProcess(), hModule, &ModuleInfo, sizeof(ModuleInfo)))
        {
            return FindPatternInternal(reinterpret_cast<BYTE*>(hModule), ModuleInfo.SizeOfImage, pattern, PatternSize) + offset;
        }
    }
    else if (ScanRegion)
    {
        // Getting the module allocation base

        MEMORY_BASIC_INFORMATION MemInfo;
        VirtualQuery(ScanRegion, &MemInfo, sizeof(MemInfo));

        SIZE_T TotalSize = 0, LastRegion = 0;
        void* const AllocationBase = MemInfo.AllocationBase;
        void* QueryBase = AllocationBase;

        // Getting the size of the allocation

        while (VirtualQuery(QueryBase, &MemInfo, sizeof(MemInfo)))
        {
            if (MemInfo.AllocationBase != AllocationBase)
            {
                break;
            }

            LastRegion = MemInfo.RegionSize;
            TotalSize += LastRegion;
            QueryBase = static_cast<char*>(QueryBase) + LastRegion;
        }

        TotalSize -= LastRegion; // final region shouldn't be included in search (never needed + itll crash)

        if (AllocationBase && TotalSize)
        {
            return FindPatternInternal(static_cast<BYTE*>(AllocationBase), TotalSize, pattern, PatternSize) + offset;
        }
    }

    return nullptr;
}

int ModuleIndexFromPtr(void* ScanRegion)
{
    MEMORY_BASIC_INFORMATION MemInfo;
    VirtualQuery(ScanRegion, &MemInfo, sizeof(MemInfo));

    char* base = static_cast<char*>(MemInfo.AllocationBase);
    const auto NtHeader = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew);
    IMAGE_SECTION_HEADER* sh = IMAGE_FIRST_SECTION(NtHeader);

    for (WORD i = 0, const sz = NtHeader->FileHeader.NumberOfSections; i < sz; ++i, ++sh)
    {
        if (!strcmp(reinterpret_cast<const char*>(sh->Name), ".text"))
        {
            const std::unordered_map<uint32_t, int> CrcMap =
            {
                { 0x56915763, 1  }, // 1  - NtQuerySystemInformation, volume logging, etc (launch module)
                { 0x842AF523, 2  }, // 2  - 
                { 0xFDB6A44B, 3  }, // 3  - 
                { 0xA7ECD33D, 4  }, // 4  - 
                { 0xC4B0C5AB, 5  }, // 5  - 
                { 0xC92323D2, 6  }, // 6  - 
                { 0x405342DA, 7  }, // 7  - 
                { 0xB6C028D3, 8  }, // 8  - 
                { 0x635D1CB0, 9  }, // 9  - 
                { 0x93DF17D1, 10 }, // 10 - 
                { 0xF1304FA5, 11 }, // 11 - 
                { 0x4F53170F, 12 }, // 12 - 
                { 0x907C67B4, 13 }, // 13 - 
                { 0xB7076415, 14 }  // 14 - 
            };
            
            const uint32_t CrcHash = CRC::Calculate(base + sh->VirtualAddress, sh->SizeOfRawData, CRC::CRC_32());

            auto entry = CrcMap.find(CrcHash);
            if (entry == CrcMap.end())
            {
                logs::basic(nullptr, "WARNING: unknown module CRC: {:#x}", CrcHash);
                break;
            }

            return entry->second;
        }
    }

    logs::basic(nullptr, "ERROR: failed to locate .text section from ptr - {:p}", ScanRegion);
    return -1;
}