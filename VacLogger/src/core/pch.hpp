#pragma once

#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <Psapi.h>
#include <winternl.h>

#include <thread>
#include <mutex>
#include <fstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <format>

#include "MinHook/MinHook.h"
#include "crc32/crc.h"

static_assert(sizeof(void*) == 8, "VacLogger must compile for x64");