#pragma once

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

typedef int(__stdcall* runfunc)(int, DWORD*, UINT, char*, size_t*);

//
//// FUNCTION POINTERS
//

// kernel32.dll

inline HANDLE(WINAPI* oOpenFileMappingW)(DWORD, BOOL, LPCWSTR);

inline HANDLE(WINAPI* oCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

inline BOOL(WINAPI* oReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);

inline int(WINAPI* oWideCharToMultiByte)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);

inline BOOL(WINAPI* oGetFileInformationByHandle)(HANDLE, LPBY_HANDLE_FILE_INFORMATION);

inline BOOL(WINAPI* oReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);

//
//// HOOKS
//

// kernel32.dll

HANDLE WINAPI hkOpenFileMappingW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName);

HANDLE WINAPI hkCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

BOOL WINAPI hkReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);

int WINAPI hkWideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);

BOOL WINAPI hkGetFileInformationByHandle(HANDLE hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation);

BOOL WINAPI hkReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlappyed);

// steamservice.dll

int __stdcall hkRunfunc(runfunc, int a1, DWORD* a2, UINT a3, char* a4, size_t* a5);