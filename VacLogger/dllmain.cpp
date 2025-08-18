#include "pch.hpp"
#include "hooks.hpp"

#define CreateHookApi(dll, fn, dst, src) MH_CreateHookApi(dll, fn, dst, reinterpret_cast<void**>(src))

static BYTE* FindPattern(const wchar_t* ModuleName, const char* ptrn, int sz, int offset)
{
    const HMODULE hModule = GetModuleHandle(ModuleName);
    MODULEINFO ModuleInfo;

    if (hModule && GetModuleInformation(GetCurrentProcess(), hModule, &ModuleInfo, sizeof(ModuleInfo)))
    {
        for (BYTE* current = reinterpret_cast<BYTE*>(hModule), *end = (current + ModuleInfo.SizeOfImage); current < end; ++current)
        {
            bool found = true;
            std::string TempPtrn = ptrn;

            for (int i = 0; i < sz; ++i)
            {
                if (TempPtrn[0] == '?')
                {
                    TempPtrn.erase(0, 2);
                    continue;
                }

                if (current[i] != std::stoi(TempPtrn, nullptr, 16))
                {
                    found = false;
                    break;
                }

                if (TempPtrn.find(' ') != std::string::npos)
                {
                    TempPtrn.erase(0, 3);
                }
            }

            if (found) return current + offset;
        }
    }

    return nullptr;
}

static void ThreadEntry()
{
    // steamservice.dll

    {
        BYTE* pTarget = FindPattern(L"steamservice.dll", "8B 70 ? 8B 48", 5, -10);

        if (pTarget)
        {
            BYTE wrapper[] =
            {
                0x55,             // push ebp
                0x8B, 0xEC,       // mov ebp, esp
                0x51,             // push ecx
                0x8B, 0x45, 0x08, // mov eax, [ebp+8]
                0xB9, 0,0,0,0,    // mov ecx, MMap::GetExportAddress
                0xFF, 0xE1        // jmp ecx
            };

            oGetExportAddress = CreateWrappedHook<decltype(oGetExportAddress)>(wrapper, sizeof(wrapper), 8, hkGetExportAddress, (DWORD)(pTarget + 7), (DWORD)pTarget);
            
            char msg[50];
            sprintf_s(msg, sizeof(msg), "Hook set on MMap::GetExportAddress: %p", pTarget);
            LogMsgA(msg);
        }
    }

    // Kernel32.dll

    {
        constexpr wchar_t k32[] = L"Kernel32.dll";

        CreateHookApi(k32, "OpenFileMappingW", hkOpenFileMappingW, &oOpenFileMappingW);

        CreateHookApi(k32, "CreateFileW", hkCreateFileW, &oCreateFileW);

        CreateHookApi(k32, "ReadProcessMemory", hkReadProcessMemory, &oReadProcessMemory);

        CreateHookApi(k32, "WideCharToMultiByte", hkWideCharToMultiByte, &oWideCharToMultiByte);
    }
    
    MH_EnableHook(MH_ALL_HOOKS);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        MH_Initialize();
        std::thread(ThreadEntry).detach();
    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }

    return TRUE;
}