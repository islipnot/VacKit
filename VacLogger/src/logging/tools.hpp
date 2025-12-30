#pragma once

//
//// MACROS
//

#define MODULE_COUNT           14

#define DECRYPTING_PARAMS      0

#define DECRYPTING_IMPORTS     1

#define ANTI_DBG_MODULE_INDEX  7 // this doesnt have an import decryption routine

//
//// FORWARD DECLARATIONS
//

BYTE* FindPattern(PCWSTR ModuleName, PCSTR pattern, int PatternSize, int offset, void* ScanRegion = nullptr);

int ModuleIndexFromPtr(void* ScanRegion);

//
//// HELPERS
//

namespace logs
{
	static std::mutex LogMutex;

	template <typename... Args> void params(std::format_string<Args...> fmt, Args&&... args)
	{
		const std::lock_guard<std::mutex> guard(LogMutex);

		std::ofstream file("pLog.txt", std::ios::out | std::ios::app);
		if (file.is_open())
		{
			file << std::format(fmt, std::forward<Args>(args)...) << '\n';
			file.close();
		}
	}

	template <typename... Args> void decrypted_params(std::format_string<Args...> fmt, Args&&... args)
	{
		const std::lock_guard<std::mutex> guard(LogMutex);

		std::ofstream file("pdLog.txt", std::ios::out | std::ios::app);
		if (file.is_open())
		{
			if (file.tellp() != 0)
			{
				file << "\n\n";
			}

			file << std::format(fmt, std::forward<Args>(args)...) << '\n';
			file.close();
		}
	}

	template <typename... Args> void basic(void* RetAddr, std::format_string<Args...> fmt, Args&&... args)
	{
		const std::lock_guard<std::mutex> guard(LogMutex);

		std::ofstream file("vLog.txt", std::ios::out | std::ios::app);
		if (file.is_open())
		{
			SYSTEMTIME st;
			GetLocalTime(&st);

			file << '[' << st.wHour << ':' << st.wMinute << ':' << st.wSecond << "] ";

			if (RetAddr)
			{
				file << "[0x" << std::hex << RetAddr << "] " << std::format(fmt, std::forward<Args>(args)...) << '\n';
			}
			else
			{
				file << std::format(fmt, std::forward<Args>(args)...) << '\n';
			}

			file.close();
		}
	}

	template <typename... Args> void basic(void* RetAddr, std::wformat_string<Args...> fmt, Args&&... args)
	{
		const std::lock_guard<std::mutex> guard(LogMutex);

		std::wofstream file("vLog.txt", std::ios::out | std::ios::app);
		if (file.is_open())
		{
			SYSTEMTIME st;
			GetLocalTime(&st);

			file << '[' << st.wHour << ':' << st.wMinute << ':' << st.wSecond << "] ";

			if (RetAddr)
			{
				file << "[0x" << std::hex << RetAddr << "] " << std::format(fmt, std::forward<Args>(args)...) << L'\n';
			}
			else
			{
				file << std::format(fmt, std::forward<Args>(args)...) << L'\n';
			}

			file.close();
		}
	}
}

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