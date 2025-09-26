#include "pch.hpp"
#include "hooks.hpp"
#include "tools.hpp"

// Globals

typedef void(__thiscall* IceDecrypt)(void* ik, BYTE* ctext, BYTE* ptext);

static IceDecrypt oIceDecrypt[MODULE_COUNT] {};

// kernel32.dll

HANDLE WINAPI hkOpenFileMappingW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName)
{
    if (lpName && lstrlenW(lpName))
    {
        logs::basic(_ReturnAddress(), L"OpenFileMappingW: {}", lpName);
    }
    else logs::basic(_ReturnAddress(), "OpenFileMappingW: nullptr or empty string passed");

    return oOpenFileMappingW(dwDesiredAccess, bInheritHandle, lpName);
}

HANDLE WINAPI hkCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    if (lpFileName && lstrlenW(lpFileName))
    {
        logs::basic(_ReturnAddress(), L"CreateFileW: {}", lpFileName);
    }
    else logs::basic(_ReturnAddress(), "CreateFileW: nullptr or empty string passed");

    return oCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL WINAPI hkReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
    wchar_t path[MAX_PATH];
    DWORD sz = MAX_PATH;

    if (QueryFullProcessImageName(hProcess, 0, path, &sz))
    {
        logs::basic(_ReturnAddress(), L"ReadProcessMemory: hProcess[{}], lpBaseAddress[{:p}], nSize[{:#x}]", path, lpBaseAddress, nSize);
    }
    else logs::basic(_ReturnAddress(), "ReadProcessMemory: invalid handle passed");

    return oReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

int WINAPI hkWideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar)
{
    if (lpWideCharStr && lstrlenW(lpWideCharStr))
    {
        logs::basic(_ReturnAddress(), L"WideCharToMultiByte: {}", lpWideCharStr);
    }
    else logs::basic(_ReturnAddress(), "WideCharToMultiByte: nullptr or empty string passed");

    return oWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
}

BOOL WINAPI hkGetFileInformationByHandle(HANDLE hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation)
{
    wchar_t path[MAX_PATH];

    if (GetFinalPathNameByHandleW(hFile, path, MAX_PATH, FILE_NAME_NORMALIZED))
    {
        logs::basic(_ReturnAddress(), L"GetFileInformationByHandle: {}", path);
    }
    else logs::basic(_ReturnAddress(), "GetFileInformationByHandle: invalid handle passed");

    return oGetFileInformationByHandle(hFile, lpFileInformation);
}

BOOL WINAPI hkReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlappyed)
{
    wchar_t path[MAX_PATH];

    if (hFile != INVALID_HANDLE_VALUE && GetFinalPathNameByHandle(hFile, path, MAX_PATH, FILE_NAME_NORMALIZED))
    {
        logs::basic(_ReturnAddress(), L"ReadFile: FileName[{}], lpBuffer[{:p}]", path, lpBuffer);
    }

    return oReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlappyed);
}

// VAC module hooks

void __fastcall hkIceDecrypt(void* ik, int edx, BYTE* ctext, BYTE* ptext)
{
    UNREFERENCED_PARAMETER(edx); // IceKey::decrypt uses __thiscall, so this param is a placeholder

    // Detecting which module is calling and decrypting next 8 bytes

    const int i = ModuleIndexFromPtr(_ReturnAddress());
    oIceDecrypt[i](ik, ctext, ptext);
    
    // Checking the progress of the decryption routine (so it knows when to seperate the dumps)

    static std::mutex IceMutex;
    const std::lock_guard<std::mutex> guard(IceMutex);
    
    static bool DecryptionStatus[MODULE_COUNT]{};
    static int DecryptedBytes[MODULE_COUNT]{};

    bool& status = DecryptionStatus[i];
    int& count = DecryptedBytes[i];

    ++count;

    if (status == DECRYPTING_IMPORTS)
    {
        if (count == 504) // 4032 / 8 == 504
        {
            status = DECRYPTING_PARAMS;
            count = 0;
        }

        return;
    }

    // Dumping decrypted bytes

    if (count == 1)
    {
        logs::decrypted_params("*VAC{} START*\n", i + 1);
    }

    std::ofstream file("pdLog.txt", std::ios::out | std::ios::app | std::ios::ate);
    file.write(reinterpret_cast<const char*>(ptext), 8);
    file.close();

    if (count == 20 && i != ANTI_DBG_MODULE_INDEX) // 160 / 8 == 20
    {
        status = DECRYPTING_IMPORTS;
        count = 0;
    }
}

int __stdcall hkRunfunc(runfunc oRunfunc, int a1, DWORD* a2, UINT a3, char* a4, size_t* a5)
{
    // Determining which VAC module is being called

    const int i = ModuleIndexFromPtr(oRunfunc);

    static std::mutex LogMutex;
    const std::lock_guard<std::mutex> guard(LogMutex);

    // Hooking ICE decryption

    if (i != -1)
    {
        // Checked every time incase modules are reloaded

        BYTE* pTarget = FindPattern(nullptr, "0B D8 0F B6 42 ? 0B C8 0F B6 42 ? C1 E1 ? 0B C8 0F B6 42 ? C1 E1 ? 56", 25, -43, oRunfunc);

        if (!pTarget)
        {
            logs::basic(nullptr, "ERROR: failed to locate IceKey::decrypt in module {}", i);
        }
        else if (*pTarget != 0xE8)
        {
            BYTE wrapper[] =
            {
                0x8B, 0x54, 0x24, 0x04, // mov edx, [esp+4]
                0x53,                   // push ebx
                0xB8, 0,0,0,0,          // mov eax, IceKey::decrypt+5
                0xFF, 0xE0              // jmp eax
            };

            oIceDecrypt[i] = CreateWrappedHook<IceDecrypt>(wrapper, sizeof(wrapper), 6, hkIceDecrypt, (DWORD)(pTarget + 5), (DWORD)pTarget);
            MH_EnableHook(pTarget);

            logs::basic(nullptr, "[{:p}] Hooked IceKey::decrypt", static_cast<void*>(pTarget));
        }
    }
    
    // Logging the call & dumping params

    std::ofstream ParamDump("pLog.txt", std::ios::out | std::ios::app);

    if (i != -1)
    {
        logs::basic(nullptr, "runfunc: VAC{} ({:p})", i + 1, static_cast<void*>(oRunfunc));

        // Dumping parameters

        if (ParamDump.is_open())
        {
            logs::params("*VAC{} a2[0-176]*", i + 1);
        }
    }
    else
    {
        logs::basic(nullptr, "runfunc: {:p}", static_cast<void*>(oRunfunc));

        if (ParamDump.is_open())
        {
            logs::params("*UNKNOWN MODULE a2[0-176]*");
        }
    }

    if (ParamDump.is_open())
    {
        ParamDump.write(reinterpret_cast<const char*>(a2), 176);
        ParamDump << "\n\n";
        ParamDump.close();
    }
    
	return oRunfunc(a1, a2, a3, a4, a5);
}