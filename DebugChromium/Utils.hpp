#ifndef UTILS_H
#define UTILS_H

#include <windows.h>
#include <filesystem>
#include <iostream>
#include <regex>
#include <optional>

namespace fs = std::filesystem;

enum class DebugStatus
{
    Normal,
    DebuggerAttached,
    Waiting,
    Breakpoint,
    Error
};

WORD ColorForStatus(DebugStatus status)
{
	switch (status)
	{
	case DebugStatus::DebuggerAttached:
		return FOREGROUND_GREEN | FOREGROUND_INTENSITY; // hard green

	case DebugStatus::Waiting:
		return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; // yellow

	case DebugStatus::Breakpoint:
		return FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY; // magenta

	case DebugStatus::Error:
		return FOREGROUND_RED | FOREGROUND_INTENSITY; // red

	case DebugStatus::Normal:
	default:
		return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE; // normal gray
	}
}

void PrintBanner(DebugStatus status)
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    CONSOLE_SCREEN_BUFFER_INFO oldInfo = {};
    bool hasConsoleInfo = GetConsoleScreenBufferInfo(hConsole, &oldInfo);
	constexpr const char* Reset = "\x1b[0m";

    SetConsoleTextAttribute(hConsole, ColorForStatus(status));

    std::cout << R"BANNER(________        ___.               ___________.__                       __
\______ \   ____\_ |__  __ __  ____\_   _____/|  |   _______  _______ _/  |_  ___________
 |    |  \_/ __ \| __ \|  |  \/ ___\|    __)_ |  | _/ __ \  \/ /\__  \\   __\/  _ \_  __ \
 |    `   \  ___/| \_\ \  |  / /_/  >        \|  |_\  ___/\   /  / __ \|  | (  <_> )  | \/
/_______  /\___  >___  /____/\___  /_______  /|____/\___  >\_/  (____  /__|  \____/|__|
        \/     \/    \/     /_____/        \/           \/           \/
)BANNER" << Reset;

    if (hasConsoleInfo)
    {
        SetConsoleTextAttribute(hConsole, oldInfo.wAttributes);
    }

    std::cout << "\n";
}

std::optional<fs::path> FindChromeVersionFolder(const fs::path& chromeExePath)
{
	fs::path applicationDir = chromeExePath.parent_path();

	if (!fs::exists(applicationDir) || !fs::is_directory(applicationDir))
		return std::nullopt;

	// Example: 147.0.7729.123
	const std::wregex versionRegex(
		LR"(^\d+\.\d+\.\d+\.\d+$)"
	);

	for (const auto& entry : fs::directory_iterator(applicationDir))
	{
		if (!entry.is_directory())
			continue;

		std::wstring folderName = entry.path().filename().wstring();

		if (std::regex_match(folderName, versionRegex))
			return entry.path();
	}

	return std::nullopt;
}

bool EqualsIgnoreCase(const std::wstring& a, const std::wstring& b)
{
	return _wcsicmp(a.c_str(), b.c_str()) == 0;
}

std::vector<DWORD> KillProcessesByName(const std::wstring& processName)
{
	std::vector<DWORD> killedPids;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (snapshot == INVALID_HANDLE_VALUE)
		return killedPids;

	PROCESSENTRY32W pe = {};
	pe.dwSize = sizeof(pe);

	if (!Process32FirstW(snapshot, &pe))
	{
		CloseHandle(snapshot);
		return killedPids;
	}

	do
	{
		if (!EqualsIgnoreCase(pe.szExeFile, processName))
			continue;

		DWORD pid = pe.th32ProcessID;

		// Do not try to kill yourself accidentally
		if (pid == GetCurrentProcessId())
			continue;

		HANDLE hProcess = OpenProcess(
			PROCESS_TERMINATE,
			FALSE,
			pid
		);

		if (!hProcess)
			continue;

		if (TerminateProcess(hProcess, 0))
			killedPids.push_back(pid);

		CloseHandle(hProcess);

	} while (Process32NextW(snapshot, &pe));

	CloseHandle(snapshot);

	return killedPids;
}

#endif