#include "pch.hpp"
#include "hooks.hpp"
#include "tools.hpp"

// Kernel32.dll

HANDLE WINAPI hkOpenFileMappingW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName)
{
    wchar_t msg[260];
    msg[219] = 0;
    wprintf_s(msg, sizeof(msg), L"OpenFileMappingW: lpName[%s]", lpName);
    LogMsgW(msg);

    return oOpenFileMappingW(dwDesiredAccess, bInheritHandle, lpName);
}

HANDLE WINAPI hkCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    std::wstring msg = L"CreateFileW: ";
    msg += lpFileName;
    LogMsgW(msg);

    return oCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL WINAPI hkReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
    wchar_t path[MAX_PATH];
    DWORD sz = MAX_PATH;

    if (QueryFullProcessImageName(hProcess, 0, path, &sz))
    {
        wchar_t msg[512];
        msg[511] = 0;
        wprintf_s(msg, sizeof(msg), L"ReadProcessMemory: hProcess[%s], lpBaseAddress[%p], nSize[%d]", path, lpBaseAddress, nSize);
        LogMsgW(msg);
    }

    return oReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

int WINAPI hkWideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar)
{
    std::wstring msg = L"WideCharToMultiByte: ";
    msg += lpWideCharStr;
    LogMsgW(msg);

    return oWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
}

// VAC module hooks

int __stdcall hkRunfunc(runfunc oRunfunc, int a1, DWORD* a2, UINT a3, char* a4, size_t* a5)
{
    // Determining which VAC module is being called

    const std::string ModuleSigs[] =
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

    int CurrentModule = -1;

    for (int i = 0; i < sizeof(ModuleSigs) / sizeof(std::string); ++i)
    {
        const std::string& sig = ModuleSigs[i];

        if (FindPattern(nullptr, sig.c_str(), std::count(sig.begin(), sig.end(), ' ') + 1, 0, oRunfunc))
        {
            CurrentModule = i;
            break;
        }
    }

    // Logging the call

    char CallMsg[35];

    if (CurrentModule != -1)
    {
        sprintf_s(CallMsg, sizeof(CallMsg), "_runfunc@20: VAC-%01d, %p", CurrentModule, oRunfunc);

        static std::mutex ParamLogMutex;
        std::lock_guard<std::mutex> lock(ParamLogMutex);

        // Dumping parameters

        std::ofstream ParamDump("pLog.txt", std::ios::out | std::ios::app);
        if (ParamDump.is_open())
        {
            char DumpMsg[60];
            sprintf_s(DumpMsg, sizeof(DumpMsg), "VAC-%d.dll!_runfunc@20 param a2[0-176]:\n", CurrentModule);

            ParamDump << DumpMsg;
            ParamDump.write(reinterpret_cast<const char*>(a2), 176);

            sprintf_s(DumpMsg, sizeof(DumpMsg), "\n** END OF: VAC-%d.dll!_runfunc@20 param a2[0-176]**\n\n", CurrentModule);
            ParamDump << DumpMsg;

            ParamDump.close();
        }
    }
    else sprintf_s(CallMsg, sizeof(CallMsg), "_runfunc@20: %p", oRunfunc);

    LogMsgA(CallMsg);

	return oRunfunc(a1, a2, a3, a4, a5);
}