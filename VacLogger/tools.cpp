#include "pch.hpp"
#include "tools.hpp"

// Pattern scanning

static BYTE* FindPatternInternal(BYTE* base, SIZE_T ScanSize, PCSTR pattern, int PatternSz)
{
    for (BYTE* const end = base + ScanSize; base < end; ++base)
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
        MEMORY_BASIC_INFORMATION MemInfo;
        VirtualQuery(ScanRegion, &MemInfo, sizeof(MemInfo));

        if (MemInfo.BaseAddress && MemInfo.RegionSize)
        {
            return FindPatternInternal(static_cast<BYTE*>(MemInfo.BaseAddress), MemInfo.RegionSize, pattern, PatternSize) + offset;
        }
    }

    return nullptr;
}

// Call logging

static std::mutex CallLogMutex;

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

        std::lock_guard<std::mutex> lock(CallLogMutex);

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

        std::lock_guard<std::mutex> lock(CallLogMutex);

        log << buffer;
        log.close();

        delete[] buffer;
    }
}