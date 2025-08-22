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
    /* UPDATING PATTERNS
    * 
    * All of the patterns below are randomly chosen by me from each module, allowing 
    * module identification within hooks. I personally chose instructions I found to be 
    * pretty unique to each given module, and I suggest doing the same if you need to update 
    * them. The notes next to the sigs are just unique stuff about the module so yk which theyre for
    */
    
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
        "57 FF 90 10 01 00 00 85 F6 74 2D 8B 4D 08 8B 45 E8 8B 75 0C 6A 04 89 01 8D 45 FC 50 56 E8 ? ? ? ? 6A 04 8D",  // 11 - OpenSCManagerA call
        "33 FF 5E 47 EB 42 A1 ? ? ? ? FF 50 70 8B F8 A1 ? ? ? ? 6A 01 57 FF 90 B8 01 00 00 8B CB",                     // 12 - cpuid
        "59 C7 45 DD 58 40 01 03 8D 55 DC C7 45 E1 73 5E 44 56 66 C7 45 E5 55 5B C6 45 E7 52 88 4D E8 C7 45 E9 58 40",
        "8B 51 08 89 44 24 10 89 94 24 D0 00 00 00 89 84 24 D4 00 00 00 89 94 24 A0 00 00 00 89 84 24 A4 00 00 00"
    };

    static_assert(sizeof(ModuleSigs) / sizeof(std::string_view) == MODULE_COUNT, "MODULE_COUNT must match sig count");

    for (int i = 0; i < MODULE_COUNT; ++i)
    {
        const std::string_view& sig = ModuleSigs[i];
        
        if (FindPattern(nullptr, sig.data(), std::count(sig.begin(), sig.end(), ' ') + 1, 0, ScanRegion))
        {
            return i;
        }
    }

    char msg[65];
    sprintf_s(msg, sizeof(msg), "ERROR: failed to identify module index with pointer %p", ScanRegion);
    LogMsgA(msg);

    return -1;
}

// Call logging

static std::mutex LogMutex;

void LogMsgW(const std::wstring& msg, void* RetAddr)
{
    const std::lock_guard<std::mutex> guard(LogMutex);
    std::wofstream log("vLog.txt", std::ios::out | std::ios::app);

    if (log.is_open())
    {
        SYSTEMTIME st;
        GetLocalTime(&st);

        const size_t sz = 23 + msg.size();
        wchar_t* buffer = new wchar_t[sz];
        swprintf_s(buffer, sz, L"[%02d:%02d:%02d][%p] %ls\n", st.wHour, st.wMinute, st.wSecond, RetAddr, msg.c_str());

        log.write(buffer, sz - 1);
        log.close();

        delete[] buffer;
    }
}

void LogMsgA(const std::string& msg, void* RetAddr)
{
    const std::lock_guard<std::mutex> guard(LogMutex);
    std::ofstream log("vLog.txt", std::ios::out | std::ios::app);

    if (log.is_open())
    {
        SYSTEMTIME st;
        GetLocalTime(&st);

        const size_t sz = 23 + msg.size();
        char* buffer = new char[sz];
        sprintf_s(buffer, sz, "[%02d:%02d:%02d][%p] %s\n", st.wHour, st.wMinute, st.wSecond, RetAddr, msg.c_str());

        log.write(buffer, sz - 1);
        log.close();

        delete[] buffer;
    }
}