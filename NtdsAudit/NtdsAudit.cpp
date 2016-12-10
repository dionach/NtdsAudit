// NtdsAudit.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "ezOptionParser.h"
#include "Audit.h"

#define VERSION "1.0.13"

void PrintUsage(ez::ezOptionParser& options)
{
	std::string usage;
	options.getUsage(usage);
	std::cout << usage;
}

int main(int argc, const char * argv[])
{
	ez::ezOptionParser topLevelOptions;
	topLevelOptions.overview = "Utility for dumping and auditing Active Directory databases";
	topLevelOptions.syntax = "ntdsaudit (dump | audit) [options]";
	topLevelOptions.footer = "\nv" VERSION;

	topLevelOptions.add(
		"", // Default
		false, // Required?
		0, // Number of args expected
		0, // Delimiter if expecting multiple args
		"Display usage instructions.", // Help description
		"-h",     // Flag token
		"--help" // Flag token
	);

	topLevelOptions.add(
		"", // Default.
		false, // Required?
		0, // Number of args expected
		0, // Delimiter if expecting multiple args
		"Dump NTDS.dit and SYSTEM hive from local system", // Help description
		"dump"     // Flag token
	);

	topLevelOptions.add(
		"", // Default.
		false, // Required?
		0, // Number of args expected
		0, // Delimiter if expecting multiple args
		"Run audit against dumped NTDS.dit and SYSTEM hive", // Help description.
		"audit"     // Flag token. 
	);

	topLevelOptions.parse(argc, argv);

	if (!topLevelOptions.isSet("dump") && !topLevelOptions.isSet("audit"))
	{
		PrintUsage(topLevelOptions);
		return 0;
	}

	if (topLevelOptions.isSet("dump"))
	{
		std::cout << "Automated dump is not implemented at present.\n";
		std::cout << "\n";
		std::cout << "Please run the following commands on a domain controller:\n";
		std::cout << "\n";
		std::cout << "\tC:\\>ntdsutil\n";
		std::cout << "\tntdsutil: activate instance ntds\n";
		std::cout << "\tntdsutil: ifm\n";
		std::cout << "\tifm: create full c:\\pentest\n";
		std::cout << "\tifm: quit\n";
		std::cout << "\tntdsutil: quit\n";

		return 0;
	}

	if (topLevelOptions.isSet("audit"))
	{
		ez::ezOptionParser auditOptions;
		auditOptions.overview = "Run audit against dumped NTDS.dit and SYSTEM hive";
		auditOptions.syntax = "ntdsaudit audit [options]";

		auditOptions.add(
			"", // Default.
			false, // Required?
			1, // Number of args expected
			0, // Delimiter if expecting multiple args
			"NTDS.dit file path", // Help description.
			"-n",     // Flag token. 
			"--ntds"     // Flag token. 
		);

		auditOptions.add(
			"", // Default.
			false, // Required?
			1, // Number of args expected
			0, // Delimiter if expecting multiple args
			"SYSTEM hive file path", // Help description.
			"-s",     // Flag token. 
			"--system"     // Flag token. 
		);

		auditOptions.add(
			"", // Default.
			false, // Required?
			0, // Number of args expected
			0, // Delimiter if expecting multiple args
			"Include/use Distinguished Name", // Help description.
			"-d",     // Flag token. 
			"--dn"     // Flag token. 
		);

		auditOptions.add(
			"", // Default.
			false, // Required?
			0, // Number of args expected
			0, // Delimiter if expecting multiple args
			"Export group members file", // Help description.
			"-g",     // Flag token. 
			"--groupmembers"     // Flag token. 
		);

		auditOptions.add(
			"", // Default.
			false, // Required?
			0, // Number of args expected
			0, // Delimiter if expecting multiple args
			"Export user membership file", // Help description.
			"-u",     // Flag token. 
			"--usermembership"     // Flag token. 
		);

		auditOptions.add(
			"", // Default.
			false, // Required?
			0, // Number of args expected
			0, // Delimiter if expecting multiple args
			"Export computers file", // Help description.
			"-c",     // Flag token. 
			"--computers"     // Flag token. 
		);

		auditOptions.parse(argc, argv);

		if (!auditOptions.isSet("-n") || !auditOptions.isSet("-s"))
		{
			PrintUsage(auditOptions);
			return 0;
		}

		std::string ntdsPath;
		auditOptions.get("-n")->getString(ntdsPath);

		std::string systemPath;
		auditOptions.get("-s")->getString(systemPath);

		bool includeDn = auditOptions.isSet("-d");

		bool groupMembers = auditOptions.isSet("-g");

		bool userMembership = auditOptions.isSet("-u");

		bool computers = auditOptions.isSet("-c");

		try 
		{
			DWORD dwError = Audit::Process(ntdsPath, systemPath, includeDn, groupMembers, userMembership, computers);
		}
		catch (std::exception& e)
		{
			Helper::SetTextRed();
			std::cerr << "Error: " << e.what();
			Helper::SetTextDefault();
		}

	}
    return 0;
}