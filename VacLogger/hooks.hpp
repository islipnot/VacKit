#pragma once

//
//// HELPERS
//

#define LogMsgW(msg) _LogMsgW(msg, _ReturnAddress())

#define LogMsgA(msg) _LogMsgA(msg, _ReturnAddress())

void _LogMsgW(const std::wstring& msg, void* RetAddr);

void _LogMsgA(const std::string& msg, void* RetAddr);

template <typename t> auto CreateWrappedHook(BYTE* wrapper, SIZE_T WrapperSz, int RetIndex, void* pHook, DWORD_PTR WrapperRetAddr, DWORD_PTR pHookInsertion) -> t
{
    void* const pWrapper = VirtualAlloc(nullptr, WrapperSz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pWrapper) return nullptr;

    memcpy(&wrapper[RetIndex], &WrapperRetAddr, sizeof(void*));
    memcpy(pWrapper, wrapper, WrapperSz);

    if (MH_CreateHook(reinterpret_cast<void*>(pHookInsertion), pHook, nullptr) != MH_OK)
    {
        VirtualFree(pWrapper, 0, MEM_COMMIT | MEM_RELEASE);
        return nullptr;
    }

    return reinterpret_cast<t>(pWrapper);
}

//
//// TYPES
//

struct VAC_MAPPING_DATA
{
	bool DllMainRan;
	char* ModuleBase;
	IMAGE_NT_HEADERS32* NtHeaders;
	UINT LoadedModuleCount;
	void** ModuleBaseList;
};

//
//// FUNCTION POINTERS
//

// Kernel32.dll

inline HANDLE(WINAPI* oOpenFileMappingW)(DWORD, BOOL, LPCWSTR);

inline HANDLE(WINAPI* oCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

inline BOOL(WINAPI* oReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);

inline int(WINAPI* oWideCharToMultiByte)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);

// steamservice.dll

inline uint32_t*(__cdecl* oGetExportAddress)(VAC_MAPPING_DATA*, const char*);

//
//// HOOKS
//

// Kernel32.dll

HANDLE WINAPI hkOpenFileMappingW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName);

HANDLE WINAPI hkCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

BOOL WINAPI hkReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);

int WINAPI hkWideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);

// steamservice.dll

uint32_t* hkGetExportAddress(VAC_MAPPING_DATA* ModuleData, const char* ExportName);