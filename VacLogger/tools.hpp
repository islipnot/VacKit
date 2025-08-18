#pragma once

BYTE* FindPattern(PCWSTR ModuleName, PCSTR pattern, int PatternSize, int offset, void* ScanRegion = nullptr);

void LogMsgW(const std::wstring& msg, void* RetAddr = _ReturnAddress());

void LogMsgA(const std::string& msg, void* RetAddr = _ReturnAddress());