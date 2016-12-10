#pragma once

class Ntds
{
public:
	typedef struct _DOMAIN_INFO {
		byte sidBytes[24];
		std::string name;
		std::string sid;
		std::string administratorsSid;
		std::string domainAdminsSid;
		std::string enterpriseAdminsSid;
		std::map<DWORD, DWORD> dntToRidMap;
	} DOMAIN_INFO, *PDOMAIN_INFO;

	typedef struct _GROUP_INFO {
		std::string name;
		std::string dn;
		std::string sid;
		DWORD dnt;
		DWORD rid;

		bool operator<(const _GROUP_INFO& other) const { return (dn < other.dn); }
	} GROUP_INFO, *PGROUP_INFO;

	typedef struct _COMPUTER_INFO {
		std::string name;
		std::string dn;
		std::string domain;
		DWORD dnt;
		BOOL disabled;

		bool operator<(const _COMPUTER_INFO& other) const { return (dn < other.dn); }
	} COMPUTER_INFO, *PCOMPUTER_INFO;

	typedef struct _USER_INFO {
		std::wstring samAccountName;
		BOOL disabled;
		BOOL passwordNeverExpires;
		BOOL passwordNotRequired;
		std::string passwordLastChanged;
		std::string lastLogonTimestamp;
		std::string sid;
		DWORD rid;
		std::string lmHash;
		std::string ntHash;
		std::vector<std::string> lmHistory;
		std::vector<std::string> ntHistory;
		std::string domain;
		std::string dn;
		std::set<std::string> groupSids;
		std::set<std::string> groupSidsRecursive;
		DWORD dnt;
		bool isAdministrator = false;
		bool isDomainAdmin = false;
		bool isEnterpriseAdmin = false;

		bool operator<(const _USER_INFO& other) const { return (dn < other.dn); }
	} USER_INFO, *PUSER_INFO;

	Ntds(std::string path, PBYTE pbSystemKey);
	~Ntds();

	std::map<std::string, DOMAIN_INFO> domains;
	std::vector<USER_INFO> users;
	std::vector<GROUP_INFO> groups;
	std::vector<COMPUTER_INFO> computers;

	// Map forward links to a list of backward links. E.g. "Members". For example, Domain Admins (group) -> Administrator (user), ...
	std::map<DWORD, std::vector<DWORD>> linkBacklinksMap;
	// Map backward links to a list of forward links. E.g. "Member of". . For example, Administrator (user) -> Domain Admins (group), ...
	std::map<DWORD, std::vector<DWORD>> backlinkLinksMap;
private:
	typedef struct _COLUMN_INFO {
		char name[JET_cbNameMost + 1];   
		ULONG uColumnId;
		ULONG uAttrId;
		std::wstring ldapDisplayName;
	} COLUMN_INFO, *PCOLUMN_INFO;
	typedef struct _RDN_INFO {
		std::string name;
		DWORD dnt;
		DWORD pnt;
	} RDN_INFO, *PRDN_INFO;

	JET_INSTANCE jtInstance;
	JET_SESID jtSesId;
	std::string loadedDatabasePath;
	JET_DBID jtDbId;
	BYTE bPek[16];
	std::vector<COLUMN_INFO> columns;
	std::map<DWORD, std::string> dntToDnMap;
	std::map<DWORD, std::string> dntToNameMap;
	std::map<DWORD, DWORD> dntToObjectCategoryDntMap;
	std::map<DWORD, BYTE[SECURITY_MAX_SID_SIZE]> dntToSidMap;
	std::map<std::wstring, DWORD> objectCategoryToDntMap;
	DWORD classSchemaDnt = 0;

	void Load(std::string path);
	void EnumColumns();
	void EnumObjectCategories();
	void EnumDnts();
	void EnumBacklinks();
	void EnumSids();
	void GetPasswordEncryptionKey(PBYTE pbSystemKey);
	COLUMN_INFO GetColumnInfo(ULONG uAttrId);
	COLUMN_INFO GetColumnInfo(std::wstring ldapDisplayName);
	COLUMN_INFO GetColumnInfo(std::string name);
	void Dump();
	void GetGroupMembershipSids(DWORD dwDnt, std::set<std::string> * groups, bool recurse);
	void DumpDomainInfo();
	DWORD GetColumnData(JET_TABLEID tableId, ULONG columnId, PVOID pbBuffer, DWORD cbBufSize);
	std::string static HexArrayToStr(unsigned char *data, int len);
	void Unload();
	std::wstring BufferToWString(PBYTE pbData, DWORD dwDataLength);
	JET_TABLEID OpenTable(JET_PCSTR tableName);
	void CloseTable(JET_TABLEID * tableId);
	std::string BufferToIsoDateTimeString(PBYTE pbData);
	std::string GetWellKnownSidString(WELL_KNOWN_SID_TYPE WellKnownSidType, PSID DomainSid);
	std::string GetSidString(PSID sid);
	std::string GetSidUserGroupString(PSID sid);
	std::string GetDomainName(PSID sid);
	DWORD FindDntFromDomainRid(std::string domainName, DWORD rid);
};

