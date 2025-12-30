#include "pch.hpp"
#include "logging/hooks.hpp"
#include "logging/tools.hpp"

#define CreateHookApi(dll, fn, dst, src) MH_CreateHookApi(dll, fn, dst, reinterpret_cast<void**>(src))

static void ThreadEntry()
{
    // Clearing logs

    std::ofstream("vLog.txt",  std::ios::trunc).close();
    std::ofstream("pLog.txt",  std::ios::trunc).close();
    std::ofstream("pdLog.txt", std::ios::trunc).close();

    // steamservice.dll

    {
        BYTE* pRunfuncCall = FindPattern(L"steamservice.dll", "89 43 ? C7 45 ? ? ? ? ? EB ? 8B 45 ? 89 45 ? 8B 75 ? B9 ? ? ? ? 8B 36 8D 7D ? F3 A5 C7 45 ? ? ? ? ? 8B 45 ? C3 8B 65 ? 8B 5D ? 8B 43 ? 8B 7D", 55, -2);

        if (pRunfuncCall)
        {
            BYTE wrapper[] =
            {
                0x50,             // push eax
                0xB8, 0,0,0,0,    // mov eax, hkRunfunc
                0xFF, 0xD0,       // call eax
                0x89, 0x43, 0x10, // mov [ebx+16], eax
                0x68, 0,0,0,0,    // push pRunfuncCall+5
                0xC3              // ret
            };

            // Allocating wrapper

            void* pWrapper = VirtualAlloc(nullptr, sizeof(wrapper), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (pWrapper)
            {
                // Copying hook and return address to wrapper

                const void* buf = hkRunfunc;
                memcpy(&wrapper[2], &buf, sizeof(void*));

                buf = pRunfuncCall + 5;
                memcpy(&wrapper[12], &buf, sizeof(void*));

                memcpy(pWrapper, wrapper, sizeof(wrapper));

                // Creating hook

                if (MH_CreateHook(pRunfuncCall, pWrapper, nullptr) == MH_OK)
                {
                    logs::basic(pRunfuncCall, "Hooked runfunc call");
                }
                else
                {
                    logs::basic(pRunfuncCall, "ERROR: failed to hook runfunc call");
                    VirtualFree(pWrapper, 0, MEM_RELEASE);
                }
            }
        }
        else logs::basic(nullptr, "ERROR: failed to locate runfunc call");

    }

    // kernel32.dll

    {
        constexpr wchar_t k32[] = L"kernel32.dll";

        CreateHookApi(k32, "OpenFileMappingW",    hkOpenFileMappingW,    &oOpenFileMappingW);

        CreateHookApi(k32, "CreateFileW",         hkCreateFileW,         &oCreateFileW);

        CreateHookApi(k32, "ReadProcessMemory",   hkReadProcessMemory,   &oReadProcessMemory);

        CreateHookApi(k32, "WriteProcessMemory",  hkWriteProcessMemory,  &oWriteProcessMemory);

        CreateHookApi(k32, "WideCharToMultiByte", hkWideCharToMultiByte, &oWideCharToMultiByte);

        CreateHookApi(k32, "ReadFile",            hkReadFile,            &oReadFile);
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