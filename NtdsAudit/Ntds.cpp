#include "stdafx.h"
#include "Ntds.h"
#include "Helper.h"
#include "NtCrypto.h"

#define NTDS_PAGE_SIZE 8192
#define JET_INSTANCE_NAME (JET_PCSTR)"NTDS_AUDIT"

#define TABLE_MSYSOBJECTS (JET_PCSTR)"MSysObjects"
#define TABLE_DATATABLE (JET_PCSTR)"datatable"
#define TABLE_LINK_TABLE (JET_PCSTR)"link_table"

// These IDs are required to be hardcoded in order to map attribute IDs to attribute LDAP display names
#define COLUMN_ATTRIBUTE_ID 131102
#define COLUMN_LDAP_DISPLAY_NAME 131532

Ntds::Ntds(std::string path, PBYTE systemKey)
{
	Helper::EnsureFileExists(path);
	JET_ERR jtError;

	std::cout << "Initialising ESE database handling... ";

	// Set page size
	jtError = JetSetSystemParameter(&jtInstance, JET_sesidNil, JET_paramDatabasePageSize, NTDS_PAGE_SIZE, NULL);
	if (jtError != JET_errSuccess)
	{
		Helper::ThrowError("Failed to set JET page size with JET_ERR", jtError);
	}

	// Turn off recovery mode
	jtError = JetSetSystemParameter(&jtInstance, JET_sesidNil, JET_paramRecovery, NULL, (JET_PCSTR)"Off");
	if (jtError != JET_errSuccess)
	{
		Helper::ThrowError("Failed to disable JET recovery mode with JET_ERR", jtError);
	}

	// Create instance
	jtError = JetCreateInstance(&jtInstance, JET_INSTANCE_NAME);
	if (jtError != JET_errSuccess)
	{
		Helper::ThrowError("Failed to create JET instance with JET_ERR", jtError);
	}

	// Initialise
	jtError = JetInit(&jtInstance);
	if (jtError != JET_errSuccess)
	{
		Helper::ThrowError("Failed to initialise JET with JET_ERR", jtError);
	}

	// Create session
	jtError = JetBeginSession(jtInstance, &jtSesId, NULL, NULL);
	if (jtError != JET_errSuccess)
	{
		Helper::ThrowError("Failed to create JET session with JET_ERR", jtError);
	}

	Helper::DoneMessage();

	// Load file
	std::cout << "Loading NTDS database... ";
	Load(path);
	Helper::DoneMessage();

	// Enumerate columns
	std::cout << "Enumerating columns and matching to Active Directory attributes... ";
	EnumColumns();
	Helper::DoneMessage();

	// Enumerate object categories
	std::cout << "Enumerating object categories from schema... ";
	EnumObjectCategories();
	Helper::DoneMessage();

	// Get Domain info
	std::cout << "Enumerating domain information... ";
	DumpDomainInfo();
	Helper::DoneMessage();

	// Enumerate DNTs
	std::cout << "Enumerating and mapping distinguished name tags to full DNs and names... ";
	EnumDnts();
	Helper::DoneMessage();

	// Enumerate backlinks
	std::cout << "Enumerating and mapping backlinks from link_table... ";
	EnumBacklinks();
	Helper::DoneMessage();

	// Map distinguished name tags to SIDs and RIDs
	std::cout << "Mapping distinguished name tags to SIDs and RIDs... ";
	EnumSids();
	Helper::DoneMessage();

	// Get password encryption key
	std::cout << "Locating and decrypting password encryption key... ";
	GetPasswordEncryptionKey(systemKey);
	Helper::DoneMessage();

	// Perform dump
	std::cout << "Dumping user information and decrypting hashes... ";
	Dump();
	Helper::DoneMessage();

	// Sort users
	std::cout << "Sorting users... ";
	std::sort(users.begin(), users.end());
	Helper::DoneMessage();

	// Unload file
	std::cout << "Unloaded NTDS database... ";
	Unload();
	Helper::DoneMessage();

	// Erase PEK
	std::cout << "Securely erasing password encryption key... ";
	SecureZeroMemory(bPek, sizeof(bPek));
	Helper::DoneMessage();
}

Ntds::~Ntds()
{
	JET_ERR jtError;

	// Unload file
	Unload();

	// End session
	if (jtSesId != NULL)
	{
		jtError = JetEndSession(jtSesId, 0);
		jtSesId = NULL;
	}

	// Terminate instance
	if (jtInstance != NULL)
	{
		jtError = JetTerm(jtInstance);
		jtInstance = NULL;
	}
}

void Ntds::Load(std::string path)
{
	JET_ERR jtError;

	// Unload an existing databse
	Unload();

	// Attach database
	jtError = JetAttachDatabase(jtSesId, path.c_str(), JET_bitDbReadOnly);
	if (jtError != JET_errSuccess)
	{
		Helper::ThrowError("Failed to attach JET database with JET_ERR", jtError);
	}
	loadedDatabasePath = path;

	// Open database
	jtError = JetOpenDatabase(jtSesId, path.c_str(), NULL, &jtDbId, JET_bitDbReadOnly);
	if (jtError != JET_errSuccess)
	{
		Helper::ThrowError("Failed to open JET database with JET_ERR", jtError);
	}
}

void Ntds::EnumBacklinks()
{
	JET_ERR jtError;
	DWORD dwResultSize;
	BYTE bResultBuffer[256];
	JET_TABLEID tableId;

	ULONG delTimeColumnId = GetColumnInfo("link_deltime").uColumnId;
	ULONG linkDntColumnId = GetColumnInfo("link_DNT").uColumnId;
	ULONG backlinkDntColumnId = GetColumnInfo("backlink_DNT").uColumnId;
	ULONG linkDeactivetimeColumnId = 0;

	// link_deactivetime was introduced in Server 2008, so catch the exception if it does not exist
	try
	{
		linkDeactivetimeColumnId = GetColumnInfo("link_deactivetime").uColumnId;
	}
	catch (std::exception&){}

	// Open link table
	tableId = OpenTable(TABLE_LINK_TABLE);

	// Move to first row
	jtError = JetMove(jtSesId, tableId, JET_MoveFirst, JET_bitNil);
	do
	{
		// Get link_deltime
		__int64 dwDelTime = 0;
		GetColumnData(tableId, delTimeColumnId, &dwDelTime, sizeof(dwDelTime));

		// Skip deleted
		if (dwDelTime != 0)
		{
			continue;
		}

		if (linkDeactivetimeColumnId != 0)
		{
			// Get link_deactivetime
			__int64 dwDeactiveTime = 0;
			GetColumnData(tableId, delTimeColumnId, &dwDeactiveTime, sizeof(dwDeactiveTime));

			// Skip recycled 
			if (dwDeactiveTime != 0)
			{
				continue;
			}
		}
		// Get forward object dnt
		DWORD dwLinkDnt = 0;
		GetColumnData(tableId, linkDntColumnId, &dwLinkDnt, sizeof(dwLinkDnt));

		// Get backward object dnt
		DWORD dwBacklinkDnt = 0;
		GetColumnData(tableId, backlinkDntColumnId, &dwBacklinkDnt, sizeof(dwBacklinkDnt));

		// Add to maps
		linkBacklinksMap[dwLinkDnt].push_back(dwBacklinkDnt);
		backlinkLinksMap[dwBacklinkDnt].push_back(dwLinkDnt);

	} while (JetMove(jtSesId, tableId, JET_MoveNext, JET_bitNil) == JET_errSuccess);

	// Close table
	CloseTable(&tableId);
}

void Ntds::EnumObjectCategories()
{
	JET_ERR jtError;
	BYTE bResultBuffer[512];
	DWORD dwResultSize;

	// Get columns ids
	ULONG nameColumnId = GetColumnInfo(L"name").uColumnId;
	ULONG objectCategoryColumnId = GetColumnInfo(L"objectCategory").uColumnId;
	ULONG dntColumnId = GetColumnInfo("DNT_col").uColumnId;
	ULONG ldapDisplayNameColumnId = GetColumnInfo(COLUMN_LDAP_DISPLAY_NAME).uColumnId;

	// Open datatable
	JET_TABLEID tableId = OpenTable(TABLE_DATATABLE);

	// Locate "Class-Schema" dnt
	// Move to first row
	jtError = JetMove(jtSesId, tableId, JET_MoveFirst, JET_bitNil);
	do
	{
		// Get DNT
		DWORD dwDnt = 0;
		GetColumnData(tableId, dntColumnId, &dwDnt, sizeof(dwDnt));

		// Get name
		dwResultSize = GetColumnData(tableId, nameColumnId, bResultBuffer, sizeof(bResultBuffer));
		if (BufferToWString(bResultBuffer, sizeof(bResultBuffer)) == std::wstring(L"Class-Schema"))
		{
			classSchemaDnt = dwDnt;
			break;
		}

	} while (JetMove(jtSesId, tableId, JET_MoveNext, JET_bitNil) == JET_errSuccess);

	// Move to first row
	jtError = JetMove(jtSesId, tableId, JET_MoveFirst, JET_bitNil);
	do
	{
		// Get object category
		DWORD dwObjectCategory;
		dwResultSize = GetColumnData(tableId, objectCategoryColumnId, &dwObjectCategory, sizeof(dwObjectCategory));

		if (dwObjectCategory == classSchemaDnt)
		{
			// Get DNT
			DWORD dwDnt = 0;
			GetColumnData(tableId, dntColumnId, &dwDnt, sizeof(dwDnt));

			// Get name
			dwResultSize = GetColumnData(tableId, ldapDisplayNameColumnId, bResultBuffer, sizeof(bResultBuffer));

			// Save 
			objectCategoryToDntMap[BufferToWString(bResultBuffer, sizeof(bResultBuffer))] = dwDnt;
		}

	} while (JetMove(jtSesId, tableId, JET_MoveNext, JET_bitNil) == JET_errSuccess);

	// Close table
	CloseTable(&tableId);
}

void Ntds::EnumDnts()
{
	JET_ERR jtError;
	DWORD dwResultSize;
	BYTE bResultBuffer[1024];
	JET_TABLEID tableId;

	ULONG dntColumnId = GetColumnInfo("DNT_col").uColumnId;
	ULONG pdntColumnId = GetColumnInfo("PDNT_col").uColumnId;
	ULONG rdnTypColumnId = GetColumnInfo("RDNtyp_col").uColumnId;
	ULONG nameColumnId = GetColumnInfo(L"name").uColumnId;
	ULONG displayNameColumnId = GetColumnInfo(L"displayName").uColumnId;
	ULONG objectCategoryColumnId = GetColumnInfo(L"objectCategory").uColumnId;

	ULONG cnAttrId = GetColumnInfo(L"cn").uAttrId;
	ULONG ouAttrId = GetColumnInfo(L"ou").uAttrId;
	ULONG dcAttrId = GetColumnInfo(L"dc").uAttrId;

	// Open datatable
	tableId = OpenTable(TABLE_DATATABLE);

	std::map<DWORD, RDN_INFO> rdnInfoMap;

	// Move to first row
	jtError = JetMove(jtSesId, tableId, JET_MoveFirst, JET_bitNil);
	do
	{
		// Get RDN type value 
		DWORD dwRdnType = 0;
		GetColumnData(tableId, rdnTypColumnId, &dwRdnType, sizeof(dwRdnType));

		if (dwRdnType != cnAttrId &&
			dwRdnType != ouAttrId &&
			dwRdnType != dcAttrId)
		{
			continue;
		}

		// Get distinguished name tag value 
		DWORD dwDnt = 0;
		GetColumnData(tableId, dntColumnId, &dwDnt, sizeof(dwDnt));

		// Get parent distinguished name tag value 
		DWORD dwPdnt = 0;
		GetColumnData(tableId, pdntColumnId, &dwPdnt, sizeof(dwPdnt));

		// Get Name
		dwResultSize = GetColumnData(tableId, nameColumnId, bResultBuffer, sizeof(bResultBuffer));
		std::wstring name = BufferToWString(bResultBuffer, sizeof(bResultBuffer));

		// Get object category and save value to map 
		DWORD dwObjectCategoryDnt = 0;
		GetColumnData(tableId, objectCategoryColumnId, &dwObjectCategoryDnt, sizeof(dwObjectCategoryDnt));
		dntToObjectCategoryDntMap[dwDnt] = dwObjectCategoryDnt;

		// Save name to map
		dntToNameMap[dwDnt] = std::string(name.begin(), name.end());

		// Save first part of DN to map
		if (dwRdnType == cnAttrId)
		{
			// Get Display Name
			dwResultSize = GetColumnData(tableId, displayNameColumnId, bResultBuffer, sizeof(bResultBuffer));
			std::wstring displayName = BufferToWString(bResultBuffer, sizeof(bResultBuffer));

			dntToDnMap[dwDnt] = "CN=";
			if (displayName.length() != 0)
			{
				dntToDnMap[dwDnt] += std::string(displayName.begin(), displayName.end());
			}
			else
			{
				dntToDnMap[dwDnt] += dntToNameMap[dwDnt];
			}
		}
		else if (dwRdnType == ouAttrId)
		{
			dntToDnMap[dwDnt] = "OU=";
			dntToDnMap[dwDnt] += dntToNameMap[dwDnt];
		}
		else
		{
			dntToDnMap[dwDnt] = "DC=";
			dntToDnMap[dwDnt] += dntToNameMap[dwDnt];
		}

		// store DNT and PDN for later construction of full DN
		RDN_INFO rdnInfo;
		rdnInfo.dnt = dwDnt;
		rdnInfo.pnt = dwPdnt;
		rdnInfo.name = dntToDnMap[dwDnt];
		rdnInfoMap[dwDnt] = rdnInfo;

	} while (JetMove(jtSesId, tableId, JET_MoveNext, JET_bitNil) == JET_errSuccess);

	for (std::map<DWORD, std::string>::iterator iterator = dntToDnMap.begin(); iterator != dntToDnMap.end(); ++iterator)
	{
		DWORD dwDnt = rdnInfoMap[iterator->first].pnt;
		while (dwDnt > 2)
		{
			dntToDnMap[iterator->first] += ",";
			dntToDnMap[iterator->first] += rdnInfoMap[dwDnt].name;
			dwDnt = rdnInfoMap[dwDnt].pnt;
		}
	}
	

	// Close table
	CloseTable(&tableId);
}

void Ntds::EnumSids()
{
	JET_ERR jtError;
	BYTE bResultBuffer[512];
	DWORD dwResultSize;

	// Get columns ids
	ULONG sidColumnId = GetColumnInfo(L"objectSid").uColumnId;
	ULONG dntColumnId = GetColumnInfo("DNT_col").uColumnId;
	ULONG isDeletedColumnId = GetColumnInfo(L"isDeleted").uColumnId;
	ULONG objColumnId = GetColumnInfo("OBJ_col").uColumnId;

	// Open datatable
	JET_TABLEID tableId = OpenTable(TABLE_DATATABLE);

	// Move to first row
	jtError = JetMove(jtSesId, tableId, JET_MoveFirst, JET_bitNil);
	do
	{
		// Get OBJ_col and skip phantoms
		dwResultSize = GetColumnData(tableId, objColumnId, bResultBuffer, sizeof(bResultBuffer));
		if (bResultBuffer[0] == 0)
		{
			continue;
		}
		// Check if record is deleted and if so skip it
		DWORD dwIsDeleted = 0;
		GetColumnData(tableId, isDeletedColumnId, &dwIsDeleted, sizeof(dwIsDeleted));
		if (dwIsDeleted != 0)
		{
			continue;
		}

		// Get DNT
		DWORD dwDnt = 0;
		GetColumnData(tableId, dntColumnId, &dwDnt, sizeof(dwDnt));

		// Get sid
		dwResultSize = GetColumnData(tableId, sidColumnId, bResultBuffer, sizeof(bResultBuffer));

		if (dwResultSize > 0)
		{
			// Extract rid
			DWORD dwSidSubAuthorityCount = *GetSidSubAuthorityCount((PSID)&bResultBuffer);
			DWORD dwRid = *GetSidSubAuthority((PSID)&bResultBuffer, dwSidSubAuthorityCount - 1);

			// Save sid
			memcpy(dntToSidMap[dwDnt], bResultBuffer, dwResultSize);
			if (dntToObjectCategoryDntMap[dwDnt] == objectCategoryToDntMap[L"person"] ||
				dntToObjectCategoryDntMap[dwDnt] == objectCategoryToDntMap[L"group"] ||
				dntToObjectCategoryDntMap[dwDnt] == objectCategoryToDntMap[L"builtin"] ||
				dntToObjectCategoryDntMap[dwDnt] == objectCategoryToDntMap[L"computer"])
			{
				// Match sid to domain sid
				std::string domainName = GetDomainName(dntToSidMap[dwDnt]);

				// Save rid
				domains[domainName].dntToRidMap[dwDnt] = _byteswap_ulong(dwRid);
			}

		}
		

	} while (JetMove(jtSesId, tableId, JET_MoveNext, JET_bitNil) == JET_errSuccess);

	// Close table
	CloseTable(&tableId);
}

void Ntds::EnumColumns()
{
	JET_ERR jtError;
	DWORD dwResultLength;
	BYTE bResultBuffer[256];
	JET_TABLEID tableId;

	// First map attribute ids and columns ids from the MSysObjects table

	// Open MSysObjects table
	tableId = OpenTable(TABLE_MSYSOBJECTS);

	// Get list of columns
	JET_COLUMNLIST columnList;
	columnList.cbStruct = sizeof(columnList);
	jtError = JetGetTableColumnInfo(jtSesId, tableId, NULL, &columnList, sizeof(columnList), JET_ColInfoListSortColumnid);
	if (jtError != JET_errSuccess)
	{
		Helper::ThrowError("JetGetTableColumnInfo failed:", jtError);
	}

	// Loop over columns and get column information
	JetMove(jtSesId, tableId, JET_MoveFirst, JET_bitNil);
	do 
	{
		COLUMN_INFO info;
		memset(info.name, 0, sizeof(info.name));
		jtError = JetRetrieveColumn(jtSesId, tableId, columnList.columnidcolumnname, info.name, sizeof(info.name), NULL, JET_bitNil, NULL);
		if (jtError != JET_errSuccess)
		{
			Helper::ThrowError("JetRetrieveColumn failed:", jtError);
		}

		jtError = JetRetrieveColumn(jtSesId, tableId, columnList.columnidcoltyp, &info.uColumnId, sizeof(info.uColumnId), NULL, JET_bitNil, NULL);
		if (jtError != JET_errSuccess)
		{
			Helper::ThrowError("JetRetrieveColumn failed:", jtError);
		}

		info.uAttrId = atol(&info.name[4]);
		columns.push_back(info);

	} while (JetMove(jtSesId, tableId, JET_MoveNext, JET_bitNil) == JET_errSuccess);

	// Close table
	CloseTable(&tableId);

	// Next map attribute names from the datatable to previous mapping

	// Get columns ids
	ULONG attributeIdColumnId = GetColumnInfo(COLUMN_ATTRIBUTE_ID).uColumnId;
	ULONG ldapDisplayNameColumnId = GetColumnInfo(COLUMN_LDAP_DISPLAY_NAME).uColumnId;

	// Open datatable
	tableId = OpenTable(TABLE_DATATABLE);

	// Move to first row
	jtError = JetMove(jtSesId, tableId, JET_MoveFirst, JET_bitNil);
	do
	{
		// Get an attribute id if available
		DWORD dwAttributeId;
		dwResultLength = GetColumnData(tableId, attributeIdColumnId, &dwAttributeId, sizeof(dwAttributeId));
		if (dwResultLength == 0)
		{
			continue;
		}

		// Get the LDAP display name
		dwResultLength = GetColumnData(tableId, ldapDisplayNameColumnId, bResultBuffer, sizeof(bResultBuffer));
		if (dwResultLength == 0)
		{
			continue;
		}

		// Loop over columns and add display name if attribute id matches
		for (DWORD i = 0; i < columns.size(); i++)
		{
			if (columns[i].uAttrId == dwAttributeId)
			{
				columns[i].ldapDisplayName = BufferToWString(bResultBuffer, sizeof(bResultBuffer));
				break;
			}
		}

	} while (JetMove(jtSesId, tableId, JET_MoveNext, JET_bitNil) == JET_errSuccess);

	// Close table
	CloseTable(&tableId);
}

void Ntds::GetPasswordEncryptionKey(PBYTE pbSysKey)
{
	JET_ERR jtError;
	BYTE bResultBuffer[256];
	DWORD dwResultLength;
	JET_TABLEID tableId;

	ULONG pekListColumnId = GetColumnInfo(L"pekList").uColumnId;

	// Open datatable
	tableId = OpenTable(TABLE_DATATABLE);

	// Move to first row
	jtError = JetMove(jtSesId, tableId, JET_MoveFirst, JET_bitNil);
	do 
	{
		dwResultLength = GetColumnData(tableId, pekListColumnId, bResultBuffer, sizeof(bResultBuffer));
		if (dwResultLength == 0)
		{
			continue;
		}

		NTCrypto::DecryptPek(pbSysKey, bResultBuffer, bPek);

		break;

	} while (JetMove(jtSesId, tableId, JET_MoveNext, JET_bitNil) == JET_errSuccess);

	// Close table
	CloseTable(&tableId);
}

Ntds::COLUMN_INFO Ntds::GetColumnInfo(ULONG uAttrId)
{
	ULONG id = 0;
	for (size_t i = 0; i < columns.size(); i++) {
		if (uAttrId == columns[i].uAttrId) {
			return columns[i];
		}
	}
	Helper::ThrowError("Failed to get column info for:", uAttrId);
}

Ntds::COLUMN_INFO Ntds::GetColumnInfo(std::wstring ldapDisplayName)
{
	ULONG id = 0;
	for (size_t i = 0; i < columns.size(); i++) {
		if (ldapDisplayName == columns[i].ldapDisplayName) {
			return columns[i];
		}
	}
	std::string error = "Failed to get column info for: " + std::string(ldapDisplayName.begin(), ldapDisplayName.end());
	Helper::ThrowError(error.c_str());
}

Ntds::COLUMN_INFO Ntds::GetColumnInfo(std::string name)
{
	ULONG id = 0;
	for (size_t i = 0; i < columns.size(); i++) {
		if (name == columns[i].name) {
			return columns[i];
		}
	}
	std::string error = "Failed to get column info for: " + name;
	Helper::ThrowError(error.c_str());
}

void Ntds::DumpDomainInfo()
{
	JET_ERR jtError;
	BYTE bResultBuffer[512];
	DWORD dwResultSize;

	// Get columns ids
	ULONG sidColumnId = GetColumnInfo(L"objectSid").uColumnId;
	ULONG nameColumnId = GetColumnInfo(L"name").uColumnId;

	// Open datatable
	JET_TABLEID tableId = OpenTable(TABLE_DATATABLE);

	// Move to first row
	jtError = JetMove(jtSesId, tableId, JET_MoveFirst, JET_bitNil);
	do
	{
		// Get sid
		dwResultSize = GetColumnData(tableId, sidColumnId, bResultBuffer, sizeof(bResultBuffer));
		if (dwResultSize == 24)
		{
			LPSTR szSID = NULL;
			DOMAIN_INFO domainInfo;

			// Save sid
			domainInfo.sid = GetSidString(bResultBuffer);

			// Save sid bytes
			memcpy(domainInfo.sidBytes, bResultBuffer, 24);

			// Create well known SIDs
			domainInfo.administratorsSid = GetWellKnownSidString(WinBuiltinAdministratorsSid, bResultBuffer);
			domainInfo.domainAdminsSid = GetWellKnownSidString(WinAccountDomainAdminsSid, bResultBuffer);
			domainInfo.enterpriseAdminsSid = GetWellKnownSidString(WinAccountEnterpriseAdminsSid, bResultBuffer);

			// Get name
			dwResultSize = GetColumnData(tableId, nameColumnId, bResultBuffer, sizeof(bResultBuffer));
			std::wstring name = BufferToWString(bResultBuffer, dwResultSize);
			domainInfo.name = std::string(name.begin(), name.end());

			domains[domainInfo.name] = domainInfo;
		}

	} while (JetMove(jtSesId, tableId, JET_MoveNext, JET_bitNil) == JET_errSuccess);
}

void Ntds::Dump()
{
	JET_ERR jtError;
	BYTE bResultBuffer[512];
	DWORD dwResultSize;

	// Get columns ids
	ULONG uacColumnId = GetColumnInfo(L"userAccountControl").uColumnId;
	ULONG samAccountNameColumnId = GetColumnInfo(L"sAMAccountName").uColumnId;
	ULONG isDeletedColumnId = GetColumnInfo(L"isDeleted").uColumnId;
	ULONG lmColumnId = GetColumnInfo(L"dBCSPwd").uColumnId;
	ULONG ntColumnId = GetColumnInfo(L"unicodePwd").uColumnId;
	ULONG sidColumnId = GetColumnInfo(L"objectSid").uColumnId;
	ULONG lmPwdHistoryColumnId = GetColumnInfo(L"lmPwdHistory").uColumnId;
	ULONG ntPwdHistoryColumnId = GetColumnInfo(L"ntPwdHistory").uColumnId;
	ULONG pwdLastSetColumnId = GetColumnInfo(L"pwdLastSet").uColumnId;
	ULONG ancestorsColumnId = GetColumnInfo("Ancestors_col").uColumnId;
	ULONG dntColumnId = GetColumnInfo("DNT_col").uColumnId;
	ULONG objColumnId = GetColumnInfo("OBJ_col").uColumnId;
	ULONG nameColumnId = GetColumnInfo(L"name").uColumnId;
	ULONG lastLogonColumnId = GetColumnInfo(L"lastLogonTimestamp").uColumnId;
	ULONG groupTypeColumnId = GetColumnInfo(L"groupType").uColumnId;
	ULONG objectCategoryColumnId = GetColumnInfo(L"objectCategory").uColumnId;
	ULONG primaryGroupIdColumnID = GetColumnInfo(L"primaryGroupID").uColumnId;

	COLUMN_INFO test = GetColumnInfo(L"objectCategory");

	ULONG cnAttrId = GetColumnInfo(L"cn").uAttrId;

	// Open datatable
	JET_TABLEID tableId = OpenTable(TABLE_DATATABLE);

	// Move to first row
	jtError = JetMove(jtSesId, tableId, JET_MoveFirst, JET_bitNil);
	do
	{	// Get object category
		DWORD dwObjectCategory;
		dwResultSize = GetColumnData(tableId, objectCategoryColumnId, &dwObjectCategory, sizeof(dwObjectCategory));

		if (dwObjectCategory != objectCategoryToDntMap[L"person"] &&
			dwObjectCategory != objectCategoryToDntMap[L"group"] &&
			dwObjectCategory != objectCategoryToDntMap[L"builtin"] &&
			dwObjectCategory != objectCategoryToDntMap[L"computer"])
		{
			continue;
		}

		// Get DNT
		DWORD dwDnt = 0;
		GetColumnData(tableId, dntColumnId, &dwDnt, sizeof(dwDnt));

		// Get OBJ_col and skip phantoms
		dwResultSize = GetColumnData(tableId, objColumnId, bResultBuffer, sizeof(bResultBuffer));
		if (bResultBuffer[0] == 0)
		{
			continue;
		}

		// Check if record is deleted and if so skip it
		DWORD dwIsDeleted = 0;
		GetColumnData(tableId, isDeletedColumnId, &dwIsDeleted, sizeof(dwIsDeleted));
		if (dwIsDeleted != 0)
		{
			continue;
		}

		if (dwObjectCategory == objectCategoryToDntMap[L"person"])
		{
			// Get user account control value 
			DWORD dwUac = 0;
			GetColumnData(tableId, uacColumnId, &dwUac, sizeof(dwUac));

			// Skip machine accounts
			if ((dwUac & ADS_UF_NORMAL_ACCOUNT) == 0)
			{
				continue;
			}

			USER_INFO userInfo;
			userInfo.dnt = dwDnt;
			userInfo.dn = dntToDnMap[dwDnt];

			// Get values from user account control flags
			userInfo.disabled = (dwUac & ADS_UF_ACCOUNTDISABLE) == ADS_UF_ACCOUNTDISABLE;
			userInfo.passwordNeverExpires = (dwUac & ADS_UF_DONT_EXPIRE_PASSWD) == ADS_UF_DONT_EXPIRE_PASSWD;
			userInfo.passwordNotRequired = (dwUac & ADS_UF_PASSWD_NOTREQD) == ADS_UF_PASSWD_NOTREQD;

			// Get last password set date
			dwResultSize = GetColumnData(tableId, pwdLastSetColumnId, bResultBuffer, sizeof(bResultBuffer));
			userInfo.passwordLastChanged = BufferToIsoDateTimeString(bResultBuffer);

			// Get last logon date
			dwResultSize = GetColumnData(tableId, lastLogonColumnId, bResultBuffer, sizeof(bResultBuffer));
			userInfo.lastLogonTimestamp = BufferToIsoDateTimeString(bResultBuffer);

			// Get sam account name
			dwResultSize = GetColumnData(tableId, samAccountNameColumnId, bResultBuffer, sizeof(bResultBuffer));
			userInfo.samAccountName = BufferToWString(bResultBuffer, sizeof(bResultBuffer));

			// Match sid to domain sid
			std::string domainName = GetDomainName(dntToSidMap[dwDnt]);
			userInfo.domain = domains[domainName].name;

			// Lookup rid from map and save
			userInfo.rid = domains[domainName].dntToRidMap[dwDnt];

			// Lookup sid from map and save
			userInfo.sid = GetSidUserGroupString(dntToSidMap[dwDnt]);

			// Get LM hash
			dwResultSize = GetColumnData(tableId, lmColumnId, bResultBuffer, sizeof(bResultBuffer));
			if (dwResultSize > 0)
			{
				NTCrypto::DecryptHash(bPek, userInfo.rid, bResultBuffer, sizeof(bResultBuffer));
				userInfo.lmHash = HexArrayToStr(bResultBuffer, 16);
				SecureZeroMemory(bResultBuffer, sizeof(bResultBuffer));
			}

			// Get NT hash
			dwResultSize = GetColumnData(tableId, ntColumnId, bResultBuffer, sizeof(bResultBuffer));
			if (dwResultSize > 0)
			{
				NTCrypto::DecryptHash(bPek, userInfo.rid, bResultBuffer, sizeof(bResultBuffer));
				userInfo.ntHash = HexArrayToStr(bResultBuffer, 16);
				SecureZeroMemory(bResultBuffer, sizeof(bResultBuffer));
			}

			// Get LM history
			if (!userInfo.lmHash.empty()) // skip LM history if LM hash is blank, as this means LM hashing is disabled and the history will be junk
			{
				dwResultSize = GetColumnData(tableId, lmPwdHistoryColumnId, bResultBuffer, sizeof(bResultBuffer));
				if (dwResultSize > 0)
				{
					NTCrypto::DecryptHashHistory(bPek, userInfo.rid, bResultBuffer, dwResultSize);
					// Start at index 16 to skip the first hash as this will be the same as the current hash
					// Skip the last 24 bytes (8 byte header, 16 byte salt)
					for (DWORD i = 16; i < dwResultSize - 24; i += 16)
					{
						userInfo.lmHistory.push_back(HexArrayToStr(bResultBuffer + i, 16));
					}
					SecureZeroMemory(bResultBuffer, sizeof(bResultBuffer));
				}
			}

			// Get NT history
			dwResultSize = GetColumnData(tableId, ntPwdHistoryColumnId, bResultBuffer, sizeof(bResultBuffer));
			if (dwResultSize > 0)
			{
				NTCrypto::DecryptHashHistory(bPek, userInfo.rid, bResultBuffer, dwResultSize);
				// Start at index 16 to skip the first hash as this will be the same as the current hash
				// Skip the last 24 bytes (8 byte header, 16 byte salt)
				for (DWORD i = 16; i < dwResultSize - 24; i += 16)
				{
					userInfo.ntHistory.push_back(HexArrayToStr(bResultBuffer + i, 16));
				}
				SecureZeroMemory(bResultBuffer, sizeof(bResultBuffer));
			}

			// Get primary group rid
			DWORD dwPrimaryGroupRid = 0;
			dwResultSize = GetColumnData(tableId, primaryGroupIdColumnID, &dwPrimaryGroupRid, sizeof(dwPrimaryGroupRid));
			try
			{
				// Get DNT for rid
				DWORD dwPrimaryGroupDnt = FindDntFromDomainRid(domainName, dwPrimaryGroupRid);
				// Create fake links for group membersip
				backlinkLinksMap[dwDnt].push_back(dwPrimaryGroupDnt);
				linkBacklinksMap[dwPrimaryGroupDnt].push_back(dwDnt);
			}
			catch (std::exception& e)
			{
				// catch the exception and dont add fake links if lookup of primary group failed. This can occur when the users primary group is "None" in AD.
			}

			// Get group membership
			GetGroupMembershipSids(dwDnt, &userInfo.groupSids, false);

			// Get recursive group membership
			GetGroupMembershipSids(dwDnt, &userInfo.groupSidsRecursive, true);

			// Check privileged groups
			for (std::map<std::string, DOMAIN_INFO>::iterator iterator = domains.begin(); iterator != domains.end(); ++iterator)
			{
				if (userInfo.groupSidsRecursive.count(iterator->second.administratorsSid) > 0)
				{
					userInfo.isAdministrator = true;
				}
				if (userInfo.groupSidsRecursive.count(iterator->second.domainAdminsSid) > 0)
				{
					userInfo.isDomainAdmin = true;
				}
				if (userInfo.groupSidsRecursive.count(iterator->second.enterpriseAdminsSid) > 0)
				{
					userInfo.isEnterpriseAdmin = true;
				}
			}

			users.push_back(userInfo);
		}
		else if (dwObjectCategory == objectCategoryToDntMap[L"computer"])
		{
			COMPUTER_INFO computerInfo;
			computerInfo.dnt = dwDnt;
			computerInfo.name = dntToNameMap[dwDnt];
			computerInfo.dn = dntToDnMap[dwDnt];

			// Get user account control value 
			DWORD dwUac = 0;
			GetColumnData(tableId, uacColumnId, &dwUac, sizeof(dwUac));

			// Get values from user account control flags
			computerInfo.disabled = (dwUac & ADS_UF_ACCOUNTDISABLE) == ADS_UF_ACCOUNTDISABLE;

			// Match sid to domain sid
			std::string domainName = GetDomainName(dntToSidMap[dwDnt]);
			computerInfo.domain = domains[domainName].name;

			// Save to vector
			computers.push_back(computerInfo);
		}
		else
		{
			// If we didnt get a uac value, check to see if this row relates to a group

			// Get groupType value 
			DWORD dwGroupType = 0;
			GetColumnData(tableId, groupTypeColumnId, &dwGroupType, sizeof(dwGroupType));
			
			if (dwGroupType != 0)
			{
				GROUP_INFO groupInfo;
				groupInfo.dnt = dwDnt;
				groupInfo.name = dntToNameMap[dwDnt];
				groupInfo.dn = dntToDnMap[dwDnt];

				// Match sid to domain sid
				std::string domainName = GetDomainName(dntToSidMap[dwDnt]);

				// Lookup rid from map and save
				groupInfo.rid = domains[domainName].dntToRidMap[dwDnt];

				// Lookup sid from map and save
				groupInfo.sid = GetSidUserGroupString(dntToSidMap[dwDnt]);

				// Save to vector
				groups.push_back(groupInfo);
			}
		}


	} while (JetMove(jtSesId, tableId, JET_MoveNext, JET_bitNil) == JET_errSuccess);

	// Close table
	CloseTable(&tableId);
}

void Ntds::GetGroupMembershipSids(DWORD dwDnt, std::set<std::string> * groups, bool recurse)
{
	if (backlinkLinksMap.count(dwDnt) == 0)
	{
		return;
	}
	std::vector<DWORD> links = backlinkLinksMap[dwDnt];
	for (std::vector<DWORD>::iterator iterator = links.begin(); iterator != links.end(); ++iterator)
	{
		// skip if iterator dnt is equal to current dnt to prevent infinite recursion
		if (*iterator == dwDnt)
		{
			continue;
		}

		if (dntToSidMap.count(*iterator) > 0 &&
			dntToObjectCategoryDntMap.count(*iterator) > 0 &&
			(dntToObjectCategoryDntMap[*iterator] == objectCategoryToDntMap[L"group"] ||
				dntToObjectCategoryDntMap[*iterator] == objectCategoryToDntMap[L"builtin"]))
		{
			if (groups->count(GetSidUserGroupString(dntToSidMap[*iterator])) == 0)
			{
				groups->insert(GetSidUserGroupString(dntToSidMap[*iterator]));

				if (recurse)
				{
					GetGroupMembershipSids(*iterator, groups, recurse);
				}
			}
		}
	}
}

DWORD Ntds::GetColumnData(JET_TABLEID tableId, ULONG columnId, PVOID pbBuffer, DWORD cbBufSize) {
	JET_ERR jtError;
	ZeroMemory(pbBuffer, cbBufSize);
	DWORD dwSize = 0;
	jtError = JetRetrieveColumn(jtSesId, tableId, columnId, (PVOID)pbBuffer, cbBufSize, &dwSize, JET_bitNil, NULL);
	if (jtError != JET_errSuccess && jtError != JET_wrnColumnNull)
	{
		Helper::ThrowError("Failed to get column with JET_ERR", jtError);
	}

	return dwSize;
}

std::string Ntds::HexArrayToStr(unsigned char *data, int len) {
	constexpr char hexmap[] = { '0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	std::string s(len * 2, ' ');
	for (int i = 0; i < len; ++i) {
		s[2 * i] = hexmap[(data[i] & 0xF0) >> 4];
		s[2 * i + 1] = hexmap[data[i] & 0x0F];
	}
	return s;
}

void Ntds::Unload()
{
	JET_ERR jtError;

	// Close database
	if (jtDbId != NULL)
	{
		jtError = JetCloseDatabase(jtSesId, jtDbId, 0);
		jtDbId = NULL;
	}

	// Detach database
	if (!loadedDatabasePath.empty())
	{
		jtError = JetDetachDatabase(jtSesId, loadedDatabasePath.c_str());
		loadedDatabasePath.clear();
	}

	// Clear columns
	columns.clear();
}

std::wstring Ntds::BufferToWString(PBYTE pbData, DWORD dwDataLength)
{
	WORD wStringEnd;
	for (wStringEnd = 0; wStringEnd < dwDataLength; wStringEnd++)
	{
		if (pbData[wStringEnd] == '\0' && pbData[wStringEnd - 1] == '\0')
		{
			break;
		}
	}
	return std::wstring((wchar_t *)pbData, wStringEnd / 2);
}

JET_TABLEID Ntds::OpenTable(JET_PCSTR tableName)
{
	JET_ERR jtError;
	JET_TABLEID tableId;

	jtError = JetOpenTable(jtSesId, jtDbId, tableName, NULL, 0, JET_bitTableReadOnly | JET_bitTableSequential, &tableId);
	if (jtError != JET_errSuccess)
	{
		Helper::ThrowError("JetOpenTable failed:", jtError);
	}
	return tableId;
}

void Ntds::CloseTable(JET_TABLEID * tableId)
{
	JET_ERR jtError;
	jtError = JetCloseTable(jtSesId, *tableId);
	if (jtError != JET_errSuccess)
	{
		Helper::ThrowError("JetCloseTable failed:", jtError);
	}
	*tableId = 0;
}

std::string Ntds::BufferToIsoDateTimeString(PBYTE pbData)
{
	SYSTEMTIME time;
	char szLocalDate[255], szLocalTime[255];
	FileTimeToSystemTime((FILETIME *)pbData, &time);
	GetDateFormatA(LOCALE_INVARIANT, 0, &time, "yyyyMMdd", szLocalDate, sizeof(szLocalDate));
	DWORD test = GetLastError();
	GetTimeFormatA(LOCALE_INVARIANT, TIME_FORCE24HOURFORMAT, &time, "HHmm", szLocalTime, sizeof(szLocalTime));
	return std::string(szLocalDate) + std::string(szLocalTime);
}

std::string Ntds::GetWellKnownSidString(WELL_KNOWN_SID_TYPE WellKnownSidType, PSID DomainSid) 
{
	DWORD dwSidSize = SECURITY_MAX_SID_SIZE;
	PSID sid;

	if (!(sid = LocalAlloc(LMEM_FIXED, dwSidSize)))
	{
		Helper::ThrowError("Could not allocate memory to create well known sid");
	}
	if (!CreateWellKnownSid(WellKnownSidType, DomainSid, sid, &dwSidSize))
	{
		Helper::ThrowError("CreateWellKnownSid failed:", GetLastError());
	}
	else
	{
		std::string stringSid = GetSidString(sid);
		LocalFree(sid);
		return stringSid;
	}
}

std::string Ntds::GetSidString(PSID sid)
{
	LPTSTR lptstrSid;
	std::string stringSid;

	if (!(ConvertSidToStringSid(sid, &lptstrSid)))
	{
		Helper::ThrowError("ConvertSidToStringSid failed:", GetLastError());
	}

	stringSid = Helper::LptstrToString(lptstrSid);
	LocalFree(lptstrSid);

	return stringSid;
}

std::string Ntds::GetSidUserGroupString(PSID sid)
{
	DWORD dwSidSubAuthorityCount = *GetSidSubAuthorityCount(sid);

	if (dwSidSubAuthorityCount >= 5)
	{
		byte buffer[MAX_SID_SIZE];
		DWORD dsSize = GetLengthSid(sid);
		memcpy(buffer, sid, dsSize);

		// convert last two sub authorities to little endian and get sid string
		for (DWORD i = dwSidSubAuthorityCount - 2; i < dwSidSubAuthorityCount; i++)
		{
			DWORD offset = 1; // revision
			offset += 1; // sub authority count
			offset += 6; // identifier authority
			offset += i * 4; // subauthorities

			DWORD bigValue = *GetSidSubAuthority(sid, i);
			DWORD littlevalue = _byteswap_ulong(bigValue);

			memcpy(buffer + offset, &littlevalue, 4);
		}
		return GetSidString(buffer);
	}

	if (dwSidSubAuthorityCount == 2)
	{
		byte buffer[MAX_SID_SIZE];
		DWORD dsSize = GetLengthSid(sid);
		memcpy(buffer, sid, dsSize);

		// convert last sub authorities to little endian and get sid string
		DWORD offset = 1; // revision
		offset += 1; // sub authority count
		offset += 6; // identifier authority
		offset += (dwSidSubAuthorityCount - 1) * 4; // subauthorities

		DWORD bigValue = *GetSidSubAuthority(sid, dwSidSubAuthorityCount - 1);
		DWORD littlevalue = _byteswap_ulong(bigValue);

		memcpy(buffer + offset, &littlevalue, 4);
		return GetSidString(buffer);
	}
	return GetSidString(sid);
}

std::string Ntds::GetDomainName(PSID sid)
{
	BYTE userAccountDomainSid[24];
	DWORD dwSidSize = GetLengthSid(sid);
	if (GetWindowsAccountDomainSid(sid, userAccountDomainSid, &dwSidSize))
	{
		for (std::map<std::string, DOMAIN_INFO>::iterator iterator = domains.begin(); iterator != domains.end(); ++iterator)
		{
			if (EqualPrefixSid(iterator->second.sidBytes, userAccountDomainSid))
			{
				return iterator->first;
			}
		}
		Helper::ThrowError("GetDomainName failed: Could not match sid to a domain");
	}
	return "";
}

DWORD Ntds::FindDntFromDomainRid(std::string domainName, DWORD rid)
{
	for (std::map<DWORD, DWORD>::iterator iterator = domains[domainName].dntToRidMap.begin(); iterator != domains[domainName].dntToRidMap.end(); ++iterator)
	{
		if (iterator->second == rid)
		{
			return iterator->first;
		}
	}
	Helper::ThrowError("FindDntFromDomainRid failed");
}