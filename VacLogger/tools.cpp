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

        char msg[100];
        sprintf_s(msg, sizeof(msg), "Scan region/size: %p, %x", AllocationBase, TotalSize);
        LogMsgA(msg, ScanRegion);

        if (AllocationBase && TotalSize)
        {
            return FindPatternInternal(static_cast<BYTE*>(AllocationBase), TotalSize, pattern, PatternSize) + offset;
        }
    }

    return nullptr;
}

int ModuleIndexFromPtr(void* ScanRegion)
{
    const std::string_view ModuleSigs[] =
    {
        "C7 85 46 FF FF FF 6B 43 4B 49 66 C7 85 4A FF FF FF 54 5F 88 95 4C FF FF FF 88 45 84 88 5D 85",                // 1
        "33 D2 83 C4 14 33 F6 39 53 24 7E 42 8B 6C 24 24 8D 4B 4C 8B 79 F8 85 FF 74 0F 8B 44 24 18",                   // 2
        "56 55 68 10 04 00 00 FF 50 20 8B 8B 38 02 00 00 89 83 30 02 00 00 85 C0 75 25 81 C9 00 00 01 00",             // 3
        "66 89 84 24 84 00 00 00 58 6A 25 59 6A 2A 5A 6A 36 66 89 84 24 88 00 00 00 58 6A 21 66 89 84 24 92 00 00 00", // 4
        "8B 4C 24 44 81 E1 FF 0F 00 00 0B 4C 24 28 66 83 7C 24 50 00 74 06 81 C9 00 10 00 00 8B 75 0C",                // 5
        "FF 90 90 02 00 00 83 4E 14 10 8B 45 30 A8 20 74 18 8B 47 04 56 57 68 ? ? ? ? 03 C3 FF D0",                    // 6
        "C7 44 24 4C 48 68 88 06 C7 44 24 50 06 06 06 06 C7 44 24 54 06 06 06 8B",                                     // 7
        "BB 3D 04 74 C1 8B 8B E7 FE 89 BE 8B 93 E3 FE 89 BE 8B 83 EB FE 89 BE 3B C8 75 E5 0B C2 85 C0",                // 8
        "FF 50 1C EB 9F C6 44 24 0E 01 FF 90 28 02 00 00 21 74 24 28 89 44 24 34 8B ? ? ? ? ? FF 91 28 02 00 00",      // 9
        "8B 44 D3 20 83 E0 F0 C1 E6 08 0B 44 24 14 89 44 D3 20 8B 4B 18 0F B6 44 CB 20 0B C6 89 44 CB 20",             // 10
        "C7 84 24 90 00 00 00 40 00 00 00 89 9C 24 94 00 00 00 89 9C 24 98 00 00 00 FF 15 78 9F 00 10",                // 11
        "33 FF 5E 47 EB 42 A1 ?? ?? ?? ?? FF 50 70 8B F8 A1 ?? ?? ?? ?? 6A 01 57 FF 90 B8 01 00 00 8B CB",             // 12
        "50 6A 1B 52 FF 15 DC EE 00 10 39 6C 24 20 74 18 68 F4 01 00 00 8D 8B 8E 08 00 00 8D 94 24 DC 00 00 00",       // 13
        "89 44 24 14 FF 34 28 FF 74 24 20 FF 15 2C 6E 00 00 89 44 24 14 85 C0 74 A9 8D 4C 24 2C 51 68"                 // 14
    };

    for (int i = 0; i < MODULE_COUNT; ++i)
    {
        const std::string_view& sig = ModuleSigs[i];

        if (FindPattern(nullptr, sig.data(), std::count(sig.begin(), sig.end(), ' ') + 1, 0, ScanRegion))
        {
            return i;
        }
    }

    return -1;
}

// Call logging

void LogMsgW(const std::wstring& msg, void* RetAddr)
{
    std::wofstream log("vLog.txt", std::ios::out | std::ios::app);

    if (log.is_open())
    {
        SYSTEMTIME st;
        GetLocalTime(&st);

        const size_t sz = 30 + msg.size();
        wchar_t* buffer = new wchar_t[sz];
        swprintf_s(buffer, sz, L"[%02d:%02d:%02d][%p] %ls\n", st.wHour, st.wMinute, st.wSecond, RetAddr, msg.c_str());

        static std::mutex LogMutex;
        const std::lock_guard<std::mutex> lock(LogMutex);

        log << buffer;
        log.close();

        delete[] buffer;
    }
}

void LogMsgA(const std::string& msg, void* RetAddr)
{
    std::ofstream log("vLog.txt", std::ios::out | std::ios::app);

    if (log.is_open())
    {
        SYSTEMTIME st;
        GetLocalTime(&st);

        const size_t sz = 30 + msg.size();
        char* buffer = new char[sz];
        sprintf_s(buffer, sz, "[%02d:%02d:%02d][%p] %s\n", st.wHour, st.wMinute, st.wSecond, RetAddr, msg.c_str());

        static std::mutex LogMutex;
        const std::lock_guard<std::mutex> lock(LogMutex);

        log << buffer;
        log.close();

        delete[] buffer;
    }
}