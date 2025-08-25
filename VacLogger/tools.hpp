#pragma once

//
//// MACROS
//

#define MODULE_COUNT           14

#define DECRYPTING_PARAMS      0

#define DECRYPTING_IMPORTS     1

#define ANTI_DBG_MODULE_INDEX  7 // this doesnt have an import decryption routine

#define SHELLCODE_MODULE_INDEX 5

//
//// FORWARD DECLARATIONS
//

BYTE* FindPattern(PCWSTR ModuleName, PCSTR pattern, int PatternSize, int offset, void* ScanRegion = nullptr);

int ModuleIndexFromPtr(void* ScanRegion);

void LogMsgW(const std::wstring& msg, void* RetAddr = _ReturnAddress());

void LogMsgA(const std::string& msg, void* RetAddr = _ReturnAddress());

//
//// TEMPLATES
//

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