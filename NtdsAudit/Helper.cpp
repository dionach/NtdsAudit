#include "stdafx.h"
#include "Helper.h"

void Helper::EnsureElevated() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	if (!fRet)
	{
		throw std::exception("NTDS Audit must be run as an administrator on the local system");
	}
}

void Helper::EnsureFileExists(std::string path)
{
	DWORD dwAttrib = GetFileAttributesA(path.c_str());
	if (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
	{
		return;
	}
	std::string error = "File '" + path + "' does not exist";
	throw std::exception(error.c_str());
}

void Helper::GetPriviledge(std::string privilege)
{
	HANDLE hToken;
	BOOL bResult;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	bResult = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);

	if (bResult)
	{
		if (!LookupPrivilegeValueA(
			NULL,            // lookup privilege on local system
			privilege.c_str(),   // privilege to lookup 
			&luid))        // receives LUID of privilege
		{
			std::string error = "Failed to look up priviledge value for '" + privilege + "' with error " + std::to_string(GetLastError());
			throw std::exception(error.c_str());
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(
			hToken,
			FALSE,
			&tp,
			sizeof(TOKEN_PRIVILEGES),
			(PTOKEN_PRIVILEGES)NULL,
			(PDWORD)NULL))
		{
			std::string error = "Failed to adjust token priviledges with '" + privilege + "' with error " + std::to_string(GetLastError());
			throw std::exception(error.c_str());
		}

		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

		{
			std::string error = "Token does not have priviledge '" + privilege + "', error " + std::to_string(GetLastError());
			throw std::exception(error.c_str());
		}
		CloseHandle(hToken);
	}
	else
	{
		std::string error = "Failed to open process token with error '" + std::to_string(GetLastError());
		throw std::exception(error.c_str());
	}
}

void Helper::ThrowError(const char * message, long errorCode)
{
	std::stringstream ss;
	ss << message << " " << errorCode;
	throw std::exception(ss.str().c_str());
}

void Helper::ThrowError(const char * message)
{
	throw std::exception(message);
}

void Helper::SetTextRed()
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
}

void Helper::SetTextGreen()
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
}

void Helper::SetTextDefault()
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

void Helper::DoneMessage()
{
	Helper::SetTextGreen();
	std::cout << "Done" "\n";
	Helper::SetTextDefault();
}

std::string Helper::LptstrToString(LPTSTR lptstrString)
{
	std::wstring wstrSid = std::wstring(lptstrString);
	return std::string(wstrSid.begin(), wstrSid.end());
}