#pragma once
#pragma comment(lib, "MinHook.lib")
#pragma comment(lib, "ntdll.lib")

#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <Psapi.h>
#include <winternl.h>

#include <thread>
#include <fstream>
#include <string>

#include "MinHook/MinHook.h"

static_assert(sizeof(void*) == 4, "VacLogger must compile for x86");