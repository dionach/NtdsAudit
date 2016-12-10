#include "stdafx.h"
#include "Audit.h"

#define NTDS_AUDIT "NTDS_AUDIT"
#define NTDS_AUDIT_SELECT NTDS_AUDIT"\\Select"
#define SUBKEY_COUNT 4
#define SYSTEM_KEY_LENGTH 16

DWORD Audit::Process(std::string ntdsPath, std::string systemPath, bool includeDn, bool groupMembers, bool userMembership, bool computers)
{
	Helper::EnsureElevated();
	Helper::EnsureFileExists(ntdsPath);
	Helper::EnsureFileExists(systemPath);
	Helper::GetPriviledge("SeRestorePrivilege");

	// Get the system key
	BYTE systemKey[SYSTEM_KEY_LENGTH];

	std::cout << "Loading SYSTEM hive... ";
	LoadHive(systemPath);
	Helper::DoneMessage();
	std::cout << "Decoding Syskey from registry... ";
	GetKeyFromHive(systemKey);
	Helper::DoneMessage();
	std::cout << "Unloading SYSTEM hive... ";
	UnloadHive();
	Helper::DoneMessage();

	// Load NTDS file
	Ntds* ntds = new Ntds(ntdsPath, systemKey);

	// pwdump output
	std::cout << "Generating pwdump output... ";
	std::ofstream outfile;
	outfile.open("pwdump.txt");

	for (std::vector<Ntds::USER_INFO>::iterator iterator = ntds->users.begin(); iterator != ntds->users.end(); ++iterator)
	{
		// PWDump format
		// <domain\username>:<uid>:<LM-hash>:<NTLM-hash>:<comment>:<homedir>:
		outfile << iterator->domain << "\\" << std::string(iterator->samAccountName.begin(), iterator->samAccountName.end()) << ":";
		outfile << iterator->rid << ":";
		if (iterator->lmHash.empty())
		{
			outfile << "AAD3B435B51404EEAAD3B435B51404EE:";
		}
		else
		{
			outfile << iterator->lmHash << ":";
		}
		if (iterator->ntHash.empty())
		{
			outfile << "31D6CFE0D16AE931B73C59D7E0C089C0:";
		}
		else
		{
			outfile << iterator->ntHash << ":";
		}
		outfile
			<< "Disabled=" << iterator->disabled
			<< ",PasswordNeverExpires=" << iterator->passwordNeverExpires
			<< ",PasswordNotRequired=" << iterator->passwordNotRequired
			<< ",PasswordLastChanged=" << iterator->passwordLastChanged
			<< ",LastLogonTimestamp=" << iterator->lastLogonTimestamp
			<< ",IsAdministrator=" << iterator->isAdministrator
			<< ",IsDomainAdmin=" << iterator->isDomainAdmin
			<< ",IsEnterpriseAdmin=" << iterator->isEnterpriseAdmin;
		if (includeDn)
		{
			outfile
				<< ",DN='" << iterator->dn << "'";
		}
		outfile << ":"; // comment
		outfile << ":\n"; // homedir

		for (DWORD j = 0; j < iterator->ntHistory.size(); j++)
		{
			outfile << iterator->domain << "\\" << std::string(iterator->samAccountName.begin(), iterator->samAccountName.end()) << "__history_" << j << ":";
			outfile << iterator->rid << ":";
			if (iterator->lmHistory.size() <= j || iterator->lmHistory[j].empty())
			{
				outfile << "AAD3B435B51404EEAAD3B435B51404EE:";
			}
			else
			{
				outfile << iterator->lmHistory[j] << ":";
			}
			outfile << iterator->ntHistory[j] << ":";
			outfile << ":"; // comment
			outfile << ":\n"; // homedir
		}
	}

	outfile.close();
	Helper::DoneMessage();

	std::map<DWORD, Ntds::GROUP_INFO> dntToGroupMap;
	std::map<DWORD, Ntds::USER_INFO> dntToUserMap;

	if (groupMembers || userMembership)
	{
		// Create dnt group map
		for (std::vector<Ntds::GROUP_INFO>::iterator iterator = ntds->groups.begin(); iterator != ntds->groups.end(); ++iterator)
		{
			dntToGroupMap[iterator->dnt] = *iterator;
		}

		// Create dnt user map
		for (std::vector<Ntds::USER_INFO>::iterator iterator = ntds->users.begin(); iterator != ntds->users.end(); ++iterator)
		{
			dntToUserMap[iterator->dnt] = *iterator;
		}
	}

	if (groupMembers)
	{
		std::cout << "Generating group members output... ";
		std::ofstream groupMapFile;
		groupMapFile.open("group-members.txt");

		// Print recursive member groups for each group
		for (std::vector<Ntds::GROUP_INFO>::iterator iterator = ntds->groups.begin(); iterator != ntds->groups.end(); ++iterator)
		{
			std::set<DWORD> recursionCheck;
			PrintRecursiveGroupMembers(dntToGroupMap, dntToUserMap, ntds->linkBacklinksMap, recursionCheck, groupMapFile, iterator->dnt, 0, includeDn);
		}

		groupMapFile.close();
		Helper::DoneMessage();
	}

	if (userMembership)
	{
		std::cout << "Generating user membership output... ";
		std::ofstream userMembershipFile;
		userMembershipFile.open("user-membership.txt");

		// Print recursive member groups for each group
		for (std::vector<Ntds::USER_INFO>::iterator iterator = ntds->users.begin(); iterator != ntds->users.end(); ++iterator)
		{
			std::set<DWORD> recursionCheck;
			PrintRecursiveUserMembership(dntToGroupMap, dntToUserMap, ntds->backlinkLinksMap, recursionCheck, userMembershipFile, iterator->dnt, 0, includeDn);
		}

		userMembershipFile.close();
		Helper::DoneMessage();
	}


	if (computers)
	{
		std::cout << "Generating computers output... ";
		std::ofstream outfile;
		outfile.open("computers.txt");

		for (std::vector<Ntds::COMPUTER_INFO>::iterator iterator = ntds->computers.begin(); iterator != ntds->computers.end(); ++iterator)
		{
			outfile << "Disabled=";
			outfile << iterator->disabled;
			outfile << ";";
			outfile << iterator->domain << "\\" << iterator->name << "\n";
		}

		outfile.close();
		Helper::DoneMessage();
	}

	// Clean up
	std::cout << "Cleaning up... ";
	delete ntds;
	ntds = NULL;
	Helper::DoneMessage();

	return ERROR_SUCCESS;
}

void Audit::PrintRecursiveGroupMembers(std::map<DWORD, Ntds::GROUP_INFO>& dntToGroupMap, std::map<DWORD, Ntds::USER_INFO>& dntToUserMap, std::map<DWORD, std::vector<DWORD>>& linkBacklinksMap, std::set<DWORD> &recursionCheck, std::ofstream& outfile, const DWORD& dnt, DWORD indent, bool useDn)
{
	bool isGroup;
	std::string name;
	std::string sid;
	if (dntToGroupMap.count(dnt) > 0 && dntToUserMap.count(dnt) == 0)
	{
		isGroup = true;
		name = useDn ? dntToGroupMap[dnt].dn : dntToGroupMap[dnt].name;
		sid = dntToGroupMap[dnt].sid;
	}
	else if (dntToGroupMap.count(dnt) == 0 && dntToUserMap.count(dnt) > 0)
	{
		isGroup = false;
		name = useDn ? dntToUserMap[dnt].dn : std::string(dntToUserMap[dnt].samAccountName.begin(), dntToUserMap[dnt].samAccountName.end());
		sid = dntToUserMap[dnt].sid;
	}
	else
	{
		// return if dnt does not relate to a group or user
		return;
	}

	// Create indent
	std::string indentString = "";
	for (DWORD i = 0; i < indent; i++)
	{
		indentString += "\t";
	}

	if (isGroup)
	{
		// Check for recursion
		if (recursionCheck.find(dnt) != recursionCheck.end())
		{
			outfile << indentString << "Infinite recursion for: " << (isGroup ? "Group - " : "User - ") << name << " (" << sid << ")" << "\n";
			return;
		}
		recursionCheck.insert(dnt);
	}

	// print output
	outfile << indentString << (isGroup ? "Group - " : "User - ") << name << " (" << sid << ")" << "\n";

	// recurse for groups
	if (isGroup)
	{
		for (std::vector<DWORD>::iterator iterator = linkBacklinksMap[dnt].begin(); iterator != linkBacklinksMap[dnt].end(); ++iterator)
		{
			PrintRecursiveGroupMembers(dntToGroupMap, dntToUserMap, linkBacklinksMap, recursionCheck, outfile, *iterator, indent + 1, useDn);
		}
	}

	// print separator
	if (indent == 0)
	{
		outfile << "\n\n";
	}
}

void Audit::PrintRecursiveUserMembership(std::map<DWORD, Ntds::GROUP_INFO>& dntToGroupMap, std::map<DWORD, Ntds::USER_INFO>& dntToUserMap, std::map<DWORD, std::vector<DWORD>>& linkBacklinksMap, std::set<DWORD> &recursionCheck, std::ofstream& outfile, const DWORD& dnt, DWORD indent, bool useDn)
{
	bool isGroup;
	std::string name;
	std::string sid;
	if (dntToGroupMap.count(dnt) > 0 && dntToUserMap.count(dnt) == 0)
	{
		isGroup = true;
		name = useDn ? dntToGroupMap[dnt].dn : dntToGroupMap[dnt].name;
		sid = dntToGroupMap[dnt].sid;
	}
	else if (dntToGroupMap.count(dnt) == 0 && dntToUserMap.count(dnt) > 0)
	{
		isGroup = false;
		name = useDn ? dntToUserMap[dnt].dn : std::string(dntToUserMap[dnt].samAccountName.begin(), dntToUserMap[dnt].samAccountName.end());
		sid = dntToUserMap[dnt].sid;
	}
	else
	{
		// return if dnt does not relate to a group or user
		return;
	}

	// Create indent
	std::string indentString = "";
	for (DWORD i = 0; i < indent; i++)
	{
		indentString += "\t";
	}

	// Print top level user and start recursion
	if (indent == 0)
	{
		outfile << indentString << name << " (" << sid << ")" << "\n";

		// recurse
		for (std::vector<DWORD>::iterator iterator = linkBacklinksMap[dnt].begin(); iterator != linkBacklinksMap[dnt].end(); ++iterator)
		{
			PrintRecursiveUserMembership(dntToGroupMap, dntToUserMap, linkBacklinksMap, recursionCheck, outfile, *iterator, indent + 1, useDn);
		}
	}

	// Print recursive groups
	if (isGroup && indent > 0)
	{
		// Check for recursion
		if (recursionCheck.find(dnt) != recursionCheck.end())
		{
			outfile << indentString << "Infinite recursion for: " << (isGroup ? "Group - " : "User - ") << name << " (" << sid << ")" << "\n";
			return;
		}
		recursionCheck.insert(dnt);

		// print output
		outfile << indentString << name << " (" << sid << ")" << "\n";

		// recurse
		for (std::vector<DWORD>::iterator iterator = linkBacklinksMap[dnt].begin(); iterator != linkBacklinksMap[dnt].end(); ++iterator)
		{
			PrintRecursiveUserMembership(dntToGroupMap, dntToUserMap, linkBacklinksMap, recursionCheck, outfile, *iterator, indent + 1, useDn);
		}
	}

	// print separator
	if (indent == 0)
	{
		outfile << "\n\n";
	}
}

void Audit::LoadHive(std::string path)
{
	DWORD dwError = RegLoadKeyA(HKEY_LOCAL_MACHINE, NTDS_AUDIT, path.c_str());
	if (dwError != ERROR_SUCCESS)
	{
		std::string error = "Failed to load hive '" + path + "' with error " + std::to_string(dwError);
		throw std::exception(error.c_str());
	}
}

void Audit::GetKeyFromHive(PBYTE pKey)
{
	DWORD dwError;
	DWORD controlSetSelect = GetControlSetSelectValue();
	std::string subkeys[SUBKEY_COUNT] = { "JD", "Skew1", "GBG", "Data" };
	BYTE scrambledKey[SYSTEM_KEY_LENGTH] = { 0 };
	PBYTE pScrambledKey = scrambledKey;

	for (int i = 0; i < SUBKEY_COUNT; i++)
	{
		HKEY hSubKey;
		std::string path = NTDS_AUDIT"\\ControlSet00" + std::to_string(controlSetSelect) + "\\Control\\Lsa\\" + subkeys[i];

		// Open subkey
		dwError = RegOpenKeyA(HKEY_LOCAL_MACHINE, path.c_str(), &hSubKey);
		if (dwError != ERROR_SUCCESS)
		{
			std::string error = "Failed to open HKLM\\" + path + " with error " + std::to_string(dwError);
			throw std::exception(error.c_str());
		}

		// Read subkey class info
		char classInfo[MAX_PATH];
		DWORD cClass = MAX_PATH;
		dwError = RegQueryInfoKeyA(hSubKey, classInfo, &cClass, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		if (dwError != ERROR_SUCCESS)
		{
			std::string error = "Failed to read class info for HKLM\\" + path + " with error " + std::to_string(dwError);
			throw std::exception(error.c_str());
		}
		// Get bytes from class info
		for (int i = 0; i < 8; i += 2)
		{
			std::string classInfoString = std::string(classInfo);
			char byte = (char)strtol(classInfoString.substr(i, 2).c_str(), NULL, 16);
			*pScrambledKey++ = byte;
		}

		// Close key
		dwError = RegCloseKey(hSubKey);
	}

	// Unscramble key
	BYTE p[16] = { 0x8, 0x5, 0x4, 0x2,
		0xb, 0x9, 0xd, 0x3,
		0x0, 0x6, 0x1, 0xc,
		0xe, 0xa, 0xf, 0x7 };

	BYTE key[16];

	for (int i = 0; i < 16; i++)
	{
		key[i] = scrambledKey[p[i]];
	}

	// Copy key to buffer
	memcpy(pKey, key, SYSTEM_KEY_LENGTH);
}

DWORD Audit::GetControlSetSelectValue()
{
	DWORD dwError;
	HKEY selectKey;
	DWORD dwSize = sizeof(DWORD);
	DWORD selectValue;
	DWORD dwType = REG_DWORD;

	// Open HKLM\NTDS_AUDIT\Select
	dwError = RegOpenKeyA(HKEY_LOCAL_MACHINE, NTDS_AUDIT_SELECT, &selectKey);
	if (dwError != ERROR_SUCCESS)
	{
		std::string error = "Failed to open HKLM\\NTDS_AUDIT\\Select with error " + std::to_string(dwError);
		throw std::exception(error.c_str());
	}

	// Read value of HKLM\NTDS_AUDIT\Select\Default
	dwError = RegQueryValueExA(selectKey, "Default", NULL, &dwType, (LPBYTE)&selectValue, &dwSize);
	if (dwError != ERROR_SUCCESS)
	{
		std::string error = "Failed to open HKLM\\NTDS_AUDIT\\Select with error " + std::to_string(dwError);
		throw std::exception(error.c_str());
	}

	// Close key
	dwError = RegCloseKey(selectKey);

	return selectValue;
}

void Audit::UnloadHive()
{
	DWORD dwError = RegUnLoadKeyA(HKEY_LOCAL_MACHINE, NTDS_AUDIT);
}

