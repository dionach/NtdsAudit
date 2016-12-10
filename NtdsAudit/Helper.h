#pragma once

class Helper
{
public:
	static void EnsureElevated();
	static void EnsureFileExists(std::string path);
	static void GetPriviledge(std::string privilege);
	static void ThrowError(const char * message);
	static void ThrowError(const char * message, long errorCode);
	static void SetTextRed();
	static void SetTextGreen();
	static void SetTextDefault();
	static void DoneMessage();
	static std::string LptstrToString(LPTSTR lptstrString);
};

