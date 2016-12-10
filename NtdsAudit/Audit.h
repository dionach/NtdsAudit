#pragma once

#include "Ntds.h"

class Audit
{
public:
	static DWORD Process(std::string ntdsPath, std::string systemPath, bool includeDn, bool groupMembers, bool userMembership, bool computers);
private:
	static void LoadHive(std::string path);
	static void GetKeyFromHive(PBYTE pKey);
	static DWORD GetControlSetSelectValue();
	static void UnloadHive();
	static void PrintRecursiveGroupMembers(std::map<DWORD, Ntds::GROUP_INFO>& dntToGroupMap, std::map<DWORD, Ntds::USER_INFO>& dntToUserMap, std::map<DWORD, std::vector<DWORD>>& linkBacklinksMap, std::set<DWORD>& recursionCheck, std::ofstream& outfile, const DWORD& dnt, DWORD indent, bool useDn);
	static void PrintRecursiveUserMembership(std::map<DWORD, Ntds::GROUP_INFO>& dntToGroupMap, std::map<DWORD, Ntds::USER_INFO>& dntToUserMap, std::map<DWORD, std::vector<DWORD>>& linkBacklinksMap, std::set<DWORD>& recursionCheck, std::ofstream& outfile, const DWORD& dnt, DWORD indent, bool useDn);
};

