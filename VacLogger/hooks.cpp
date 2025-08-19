#include "pch.hpp"
#include "hooks.hpp"
#include "tools.hpp"

// Globals

typedef void(__thiscall* IceDecrypt)(void* ik, BYTE* ctext, BYTE* ptext);

static IceDecrypt oIceDecrypt[MODULE_COUNT]{};

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

BOOL hkGetFileInformationByHandle(HANDLE hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation)
{
    wchar_t path[MAX_PATH];
    GetFinalPathNameByHandleW(hFile, path, MAX_PATH, FILE_NAME_NORMALIZED);

    std::wstring msg = L"GetFileInformationByHandle: ";
    msg += path;

    LogMsgW(msg);

    return oGetFileInformationByHandle(hFile, lpFileInformation);
}

// VAC module hooks

void __fastcall hkIceDecrypt(void* ik, int edx, BYTE* ctext, BYTE* ptext)
{
    // Detecting which module is calling and decrypting next 8 bytes

    const int i = ModuleIndexFromPtr(_ReturnAddress());
    oIceDecrypt[i](ik, ctext, ptext);

    // Checking the progress of the decryption routine (so it knows when to seperate the dumps)
    
    static bool DecryptionStatus[MODULE_COUNT]{};
    static int DecryptedBytes[MODULE_COUNT]{};

    bool& status = DecryptionStatus[i];
    int& count = DecryptedBytes[i];

    if (status == DECRYPTING_IMPORTS)
    {
        count += 8;

        if (count == 4032)
        {
            status = DECRYPTING_PARAMS;
            count = 0;
        }

        return;
    }

    // Dumping decrypted bytes

    std::ofstream file("pdLog.txt", std::ios::out | std::ios::ate); // ignore the lock release warning

    static std::mutex IceDumpMutex;
    const std::lock_guard<std::mutex> lock(IceDumpMutex);

    if (count == 160)
    {
        status = DECRYPTING_IMPORTS;
        count  = 0;
    }
    else
    {
        if (!count)
        {
            if (static_cast<size_t>(file.tellp()) != 0)
            {
                file << "\n\n";
            }

            file << "**VAC" << std::to_string(i) << " DUMP START**\n\n";
        }

        file.write(reinterpret_cast<const char*>(ptext), 8);
        file.close();

        count += 8;
    }
}

int __stdcall hkRunfunc(runfunc oRunfunc, int a1, DWORD* a2, UINT a3, char* a4, size_t* a5)
{
    // Determining which VAC module is being called

    const int CurrentModule = ModuleIndexFromPtr(oRunfunc);

    // Hooking IceDecrypt

    if (CurrentModule != -1 && !oIceDecrypt[CurrentModule])
    {
        BYTE* pIceDecrypt = FindPattern(nullptr, "0B D8 0F B6 42 ? 0B C8 0F B6 42 ? C1 E1 ? 0B C8 0F B6 42 ? C1 E1 ? 56", 25, -43, oRunfunc);

        if (pIceDecrypt)
        {
            BYTE wrapper[] =
            {
                0x8B, 0x54, 0x24, 0x04, // mov edx, [esp+4]
                0x53,                   // push ebx
                0xB8, 0,0,0,0,          // mov eax, IceKey::decrypt+5
                0xFF, 0xE0              // jmp eax
            };
            
            oIceDecrypt[CurrentModule] = CreateWrappedHook<IceDecrypt>(wrapper, sizeof(wrapper), 6, hkIceDecrypt, (DWORD)(pIceDecrypt + 5), (DWORD)pIceDecrypt);
            MH_EnableHook(pIceDecrypt);

            LogMsgA("Hooked IceKey::decrypt", pIceDecrypt);
        }
    }

    // Logging the call & dumping params
    
    char CallMsg[35];

    static std::mutex ParamLogMutex;
    const std::lock_guard<std::mutex> lock(ParamLogMutex);

    if (CurrentModule != -1)
    {
        sprintf_s(CallMsg, sizeof(CallMsg), "runfunc: VAC-%01d, %p", CurrentModule, oRunfunc);

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
    else sprintf_s(CallMsg, sizeof(CallMsg), "runfunc: %p", oRunfunc);

    LogMsgA(CallMsg);

	return oRunfunc(a1, a2, a3, a4, a5);
}