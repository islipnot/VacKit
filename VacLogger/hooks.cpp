#include "pch.hpp"
#include "hooks.hpp"

#define LogMsgW(msg) _LogMsgW(msg, _ReturnAddress())

#define LogMsgA(msg) _LogMsgA(msg, _ReturnAddress())

void _LogMsgW(const std::wstring& msg, void* RetAddr)
{
    std::wofstream log("vLog.txt", std::ios::out | std::ios::app);

    if (log.is_open())
    {
        SYSTEMTIME st;
        GetLocalTime(&st);

        const size_t sz = 30 + msg.size();
        wchar_t* buffer = new wchar_t[sz];
        swprintf_s(buffer, sz, L"[%02d:%02d:%02d][%p] %ls\n", st.wHour, st.wMinute, st.wSecond, RetAddr, msg.c_str());
        
        log << buffer;
        log.close();
        delete[] buffer;
    }
}

void _LogMsgA(const std::string& msg, void* RetAddr)
{
    std::ofstream log("vLog.txt", std::ios::out | std::ios::app);

    if (log.is_open())
    {
        SYSTEMTIME st;
        GetLocalTime(&st);

        const size_t sz = 30 + msg.size();
        char* buffer = new char[sz];
        sprintf_s(buffer, sz, "[%02d:%02d:%02d][%p] %s\n", st.wHour, st.wMinute, st.wSecond, RetAddr, msg.c_str());

        log << buffer;
        log.close();
        delete[] buffer;
    }
}

// Kernel32.dll

HANDLE WINAPI hkOpenFileMappingW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName)
{
    const HANDLE result = oOpenFileMappingW(dwDesiredAccess, bInheritHandle, lpName);

    if (result)
    {
        PUBLIC_OBJECT_TYPE_INFORMATION TypeInfo;

        if (NT_SUCCESS(NtQueryObject(result, ObjectTypeInformation, &TypeInfo, sizeof(TypeInfo), nullptr)))
        {
            wchar_t msg[520];
            msg[519] = 0;
            wprintf_s(msg, sizeof(msg), L"OpenFileMappingW: access[%d], name[%s], ResolvedName[%.*s]", dwDesiredAccess, lpName, TypeInfo.TypeName.Length / sizeof(WCHAR), TypeInfo.TypeName.Buffer);
        }
    }

    return result;
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

static int(__stdcall* oRunfunc)(int, DWORD*, UINT, char*, size_t*);

int __stdcall hkRunfunc(int a1, DWORD* a2, UINT a3, char* a4, size_t* a5)
{
    LogMsgA("_runfunc@20");

    /*if (a2)
    {
        std::ofstream ParamDump("rf_params.txt", std::ios::out | std::ios::app);
        if (ParamDump.is_open())
        {
            ParamDump.write((const char*)&a2[1], 160);
            ParamDump << "\n\n/////// DUMP END \\\\\\\\\\\\\\\n\n";
            ParamDump.close();
        }
    }*/

	return oRunfunc(a1, a2, a3, a4, a5);
}

// steamservice.dll

uint32_t* __cdecl hkGetExportAddress(VAC_MAPPING_DATA* ModuleData, const char* ExportName)
{
    // Logging the call

	uint32_t* const pFunc = oGetExportAddress(ModuleData, ExportName);
    
    char msg[80];
    sprintf_s(msg, sizeof(msg), "MMap::GetExportAddress: ExportName[%s], address[%p]", ExportName, pFunc);
    LogMsgA(msg);

    // Hooking _runfunc@20

    if (!strcmp(ExportName, "_runfunc@20") && pFunc)
    {
        /* How this hook works
        * 
        * After steamservice.dll manual maps a VAC module, it will call 
        * MMap::GetExportAddress (which I called above for pFunc), which 
        * will parse the PE headers for the export address. This call is 
        * of course not made via IAT, so the call is made directly to the 
        * base of the function, which is what I'm hooking.
        */

        BYTE wrapper[] =
        {
            0x55,          // push ebp
            0x8B, 0xEC,    // mov ebp, esp
            0x56,          // push esi
            0x57,          // push edi
            0xB9, 0,0,0,0, // mov ecx, _runfunc@20
            0xFF, 0xE1     // jmp ecx
        };

        oRunfunc = CreateWrappedHook<decltype(oRunfunc)>(wrapper, sizeof(wrapper), 6, hkRunfunc, (DWORD)(pFunc + 5), (DWORD)pFunc);
        MH_EnableHook(MH_ALL_HOOKS);
    }

    return pFunc;
}