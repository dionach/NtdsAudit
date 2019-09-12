namespace NtdsAudit
{
    using Microsoft.Isam.Esent.Interop;
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Security.Principal;
    using System.Text;
    using System.Text.RegularExpressions;

    /// <summary>
    /// Processes an NTDS database.
    /// </summary>
    internal class NtdsAudit
    {
        private const string DATATABLE = "datatable";
        private const string LINKTABLE = "link_table";
        private const string MSYSOBJECTS = "MSysObjects";
        private readonly DatatableRow[] _datatable;
        private readonly IReadOnlyDictionary<string, string> _ldapDisplayNameToDatatableColumnNameDictionary;
        private readonly LinkTableRow[] _linkTable;
        private readonly MSysObjectsRow[] _mSysObjects;
        private readonly bool _useOUFilter;
        private readonly IEnumerable<string> _ouFilter;

        /// <summary>
        /// Initializes a new instance of the <see cref="NtdsAudit"/> class.
        /// </summary>
        /// <param name="ntdsPath">The path to the NTDS file.</param>
        /// <param name="dumphashes">A value indicating whether to dump hashes.</param>
        /// <param name="includeHistoryHashes">A value indicating whether to include history hashes</param>
        /// <param name="systemHivePath">The path to the System hive.</param>
        /// <param name="wordlistPath">The path to a wordlist for simple hash cracking.</param>
        public NtdsAudit(string ntdsPath, bool dumphashes, bool includeHistoryHashes, string systemHivePath, string wordlistPath, string ouFilterFilePath)
        {
            ntdsPath = ntdsPath ?? throw new ArgumentNullException(nameof(ntdsPath));

            ProgressBar progress = null;
            if (!ShowDebugOutput)
            {
                progress = new ProgressBar("Performing audit...");
            }

            if (!string.IsNullOrWhiteSpace(ouFilterFilePath))
            {
                _useOUFilter = true;
                _ouFilter = File.ReadAllLines(ouFilterFilePath).Where(x => !string.IsNullOrWhiteSpace(x));
            }

            try
            {
                using (var db = new JetDb(ntdsPath))
                {
                    _mSysObjects = EnumerateMSysObjects(db);
                    if (!ShowDebugOutput)
                    {
                        progress.Report(8 / (double)100);
                    }

                    _linkTable = EnumerateLinkTable(db);
                    if (!ShowDebugOutput)
                    {
                        progress.Report(16 / (double)100);
                    }

                    _ldapDisplayNameToDatatableColumnNameDictionary = EnumerateDatatableTableLdapDisplayNames(db, _mSysObjects);
                    if (!ShowDebugOutput)
                    {
                        progress.Report(24 / (double)100);
                    }

                    _datatable = EnumerateDatatableTable(db, _ldapDisplayNameToDatatableColumnNameDictionary, dumphashes, includeHistoryHashes);
                    if (!ShowDebugOutput)
                    {
                        progress.Report(32 / (double)100);
                    }
                }

                if (dumphashes)
                {
                    DecryptSecretData(systemHivePath, includeHistoryHashes);
                    if (!ShowDebugOutput)
                    {
                        progress.Report(40 / (double)100);
                    }
                }

                CalculateDnsForDatatableRows();
                if (!ShowDebugOutput)
                {
                    progress.Report(48 / (double)100);
                }

                CalculateObjectCategoryStringForDatableRows();
                if (!ShowDebugOutput)
                {
                    progress.Report(56 / (double)100);
                }

                Domains = CalculateDomainInfo();
                if (!ShowDebugOutput)
                {
                    progress.Report(64 / (double)100);
                }

                Users = CalculateUserInfo();
                if (!ShowDebugOutput)
                {
                    progress.Report(72 / (double)100);
                }

                if (dumphashes)
                {
                    if (!string.IsNullOrWhiteSpace(wordlistPath))
                    {
                        var ntlmHashToPasswordDictionary = PrecomputeHashes(wordlistPath);
                        CheckUsersForWeakPasswords(ntlmHashToPasswordDictionary);
                    }
                }

                if (!ShowDebugOutput)
                {
                    progress.Report(80 / (double)100);
                }

                Groups = CalculateSecurityGroupInfo();
                if (!ShowDebugOutput)
                {
                    progress.Report(88 / (double)100);
                }

                Computers = CalculateComputerInfo();
                if (!ShowDebugOutput)
                {
                    progress.Report(96 / (double)100);
                }

                CalculateGroupMembership();
                if (!ShowDebugOutput)
                {
                    progress.Report(100 / (double)100);
                }
            }
            finally
            {
                (progress as IDisposable)?.Dispose();
            }
        }

        private enum ADS_GROUP_TYPE_ENUM : uint
        {
            ADS_GROUP_TYPE_GLOBAL_GROUP = 0x00000002,
            ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP = 0x00000004,
            ADS_GROUP_TYPE_LOCAL_GROUP = 0x00000004,
            ADS_GROUP_TYPE_UNIVERSAL_GROUP = 0x00000008,
            ADS_GROUP_TYPE_SECURITY_ENABLED = 0x80000000
        }

        private enum ADS_USER_FLAG : int
        {
            ADS_UF_SCRIPT = 0x1,
            ADS_UF_ACCOUNTDISABLE = 0x2,
            ADS_UF_HOMEDIR_REQUIRED = 0x8,
            ADS_UF_LOCKOUT = 0x10,
            ADS_UF_PASSWD_NOTREQD = 0x20,
            ADS_UF_PASSWD_CANT_CHANGE = 0x40,
            ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x80,
            ADS_UF_TEMP_DUPLICATE_ACCOUNT = 0x100,
            ADS_UF_NORMAL_ACCOUNT = 0x200,
            ADS_UF_INTERDOMAIN_TRUST_ACCOUNT = 0x800,
            ADS_UF_WORKSTATION_TRUST_ACCOUNT = 0x1000,
            ADS_UF_SERVER_TRUST_ACCOUNT = 0x2000,
            ADS_UF_DONT_EXPIRE_PASSWD = 0x10000,
            ADS_UF_MNS_LOGON_ACCOUNT = 0x20000,
            ADS_UF_SMARTCARD_REQUIRED = 0x40000,
            ADS_UF_TRUSTED_FOR_DELEGATION = 0x80000,
            ADS_UF_NOT_DELEGATED = 0x100000,
            ADS_UF_USE_DES_KEY_ONLY = 0x200000,
            ADS_UF_DONT_REQUIRE_PREAUTH = 0x400000,
            ADS_UF_PASSWORD_EXPIRED = 0x800000,
            ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x1000000
        }

        /// <summary>
        /// Gets the well known empty LM hash.
        /// </summary>
        public static string EMPTY_LM_HASH => "AAD3B435B51404EEAAD3B435B51404EE";

        /// <summary>
        /// Gets the well known empty NT hash.
        /// </summary>
        public static string EMPTY_NT_HASH => "31D6CFE0D16AE931B73C59D7E0C089C0";

        /// <summary>
        /// Gets or sets a value indicating whether to show debug output.
        /// </summary>
        public static bool ShowDebugOutput { get; set; } = false;

        /// <summary>
        /// Gets an array of computer info.
        /// </summary>
        public ComputerInfo[] Computers { get; }

        /// <summary>
        /// Gets an array of domain info.
        /// </summary>
        public DomainInfo[] Domains { get; }

        /// <summary>
        /// Gets an array of group info.
        /// </summary>
        public GroupInfo[] Groups { get; }

        /// <summary>
        /// Gets an array of user info.
        /// </summary>
        public UserInfo[] Users { get; }

        private static string ByteArrayToHexString(byte[] ba)
        {
            string hex = BitConverter.ToString(ba);
            return hex.Replace("-", string.Empty);
        }

        private static DatatableRow[] EnumerateDatatableTable(JetDb db, IReadOnlyDictionary<string, string> ldapDisplayNameToDatatableColumnNameDictionary, bool dumpHashes, bool includeHistoryHashes)
        {
            Stopwatch stopwatch = null;
            if (ShowDebugOutput)
            {
                ConsoleEx.WriteDebug($"Called: {nameof(NtdsAudit)}::{nameof(EnumerateDatatableTable)}");
                stopwatch = new Stopwatch();
                stopwatch.Start();
            }

            var datatable = new List<DatatableRow>();
            var deletedCount = 0;

            using (var table = db.OpenJetDbTable(DATATABLE))
            {
                // Get a dictionary mapping column names to column ids
                var columnDictionary = table.GetColumnDictionary();

                // Loop over the table
                table.MoveBeforeFirst();
                while (table.TryMoveNext())
                {
                    var accountExpiresColumn = new BytesColumnValue { Columnid = columnDictionary[ldapDisplayNameToDatatableColumnNameDictionary["accountExpires"]] };
                    var displayNameColumn = new StringColumnValue { Columnid = columnDictionary[ldapDisplayNameToDatatableColumnNameDictionary["displayName"]] };
                    var distinguishedNameTagColumn = new Int32ColumnValue { Columnid = columnDictionary["DNT_col"] };
                    var groupTypeColumn = new Int32ColumnValue { Columnid = columnDictionary[ldapDisplayNameToDatatableColumnNameDictionary["groupType"]] };
                    var isDeletedColumn = new Int32ColumnValue { Columnid = columnDictionary[ldapDisplayNameToDatatableColumnNameDictionary["isDeleted"]] };
                    var lastLogonColumn = new LdapDateTimeColumnValue { Columnid = columnDictionary[ldapDisplayNameToDatatableColumnNameDictionary["lastLogonTimestamp"]] };
                    var lmColumn = new BytesColumnValue { Columnid = columnDictionary[ldapDisplayNameToDatatableColumnNameDictionary["dBCSPwd"]] };
                    var lmHistoryColumn = new BytesColumnValue { Columnid = columnDictionary[ldapDisplayNameToDatatableColumnNameDictionary["lmPwdHistory"]] };
                    var nameColumn = new StringColumnValue { Columnid = columnDictionary[ldapDisplayNameToDatatableColumnNameDictionary["name"]] };
                    var ntColumn = new BytesColumnValue { Columnid = columnDictionary[ldapDisplayNameToDatatableColumnNameDictionary["unicodePwd"]] };
                    var ntHistoryColumn = new BytesColumnValue { Columnid = columnDictionary[ldapDisplayNameToDatatableColumnNameDictionary["ntPwdHistory"]] };
                    var objColumn = new BoolColumnValue { Columnid = columnDictionary["OBJ_col"] };
                    var objectCategoryColumn = new Int32ColumnValue { Columnid = columnDictionary[ldapDisplayNameToDatatableColumnNameDictionary["objectCategory"]] };
                    var objectSidColumn = new BytesColumnValue { Columnid = columnDictionary[ldapDisplayNameToDatatableColumnNameDictionary["objectSid"]] };
                    var parentDistinguishedNameTagColumn = new Int32ColumnValue { Columnid = columnDictionary["PDNT_col"] };
                    var passwordLastSetColumn = new LdapDateTimeColumnValue { Columnid = columnDictionary[ldapDisplayNameToDatatableColumnNameDictionary["pwdLastSet"]] };
                    var pekListColumn = new BytesColumnValue { Columnid = columnDictionary[ldapDisplayNameToDatatableColumnNameDictionary["pekList"]] };
                    var primaryGroupIdColumn = new Int32ColumnValue { Columnid = columnDictionary[ldapDisplayNameToDatatableColumnNameDictionary["primaryGroupID"]] };
                    var rdnTypeColumn = new Int32ColumnValue { Columnid = columnDictionary["RDNtyp_col"] }; // The RDNTyp_col holds the Attribute-ID for the attribute being used as the RDN, such as CN, OU, DC
                    var samAccountNameColumn = new StringColumnValue { Columnid = columnDictionary[ldapDisplayNameToDatatableColumnNameDictionary["sAMAccountName"]] };
                    var timeColumn = new LdapDateTimeColumnValue { Columnid = columnDictionary["time_col"] };
                    var userAccountControlColumn = new Int32ColumnValue { Columnid = columnDictionary[ldapDisplayNameToDatatableColumnNameDictionary["userAccountControl"]] };
                    var supplementalCredentialsColumn = new BytesColumnValue { Columnid = columnDictionary[ldapDisplayNameToDatatableColumnNameDictionary["supplementalCredentials"]] };

                    var columns = new List<ColumnValue>
                    {
                        accountExpiresColumn,
                        displayNameColumn,
                        distinguishedNameTagColumn,
                        groupTypeColumn,
                        isDeletedColumn,
                        lastLogonColumn,
                        nameColumn,
                        objColumn,
                        objectCategoryColumn,
                        objectSidColumn,
                        parentDistinguishedNameTagColumn,
                        passwordLastSetColumn,
                        primaryGroupIdColumn,
                        rdnTypeColumn,
                        samAccountNameColumn,
                        timeColumn,
                        userAccountControlColumn,
                    };

                    if (dumpHashes)
                    {
                        columns.Add(pekListColumn);
                        columns.Add(lmColumn);
                        columns.Add(ntColumn);
                        columns.Add(supplementalCredentialsColumn);

                        if (includeHistoryHashes)
                        {
                            columns.Add(lmHistoryColumn);
                            columns.Add(ntHistoryColumn);
                        }
                    }

                    table.RetrieveColumns(columns.ToArray());

                    // Skip deleted objects
                    if (isDeletedColumn.Value.HasValue && isDeletedColumn.Value != 0)
                    {
                        deletedCount++;
                        continue;
                    }

                    // Some deleted objects do not have the isDeleted flag but do have a string appended to the DN (https://support.microsoft.com/en-us/help/248047/phantoms--tombstones-and-the-infrastructure-master)
                    if (nameColumn.Value?.Contains("\nDEL:") ?? false)
                    {
                        deletedCount++;
                        continue;
                    }

                    SecurityIdentifier sid = null;
                    uint rid = 0;
                    if (objectSidColumn.Error == JET_wrn.Success)
                    {
                        var sidBytes = objectSidColumn.Value;
                        var ridBytes = sidBytes.Skip(sidBytes.Length - sizeof(int)).Take(sizeof(int)).Reverse().ToArray();
                        sidBytes = sidBytes.Take(sidBytes.Length - sizeof(int)).Concat(ridBytes).ToArray();
                        rid = BitConverter.ToUInt32(ridBytes, 0);
                        sid = new SecurityIdentifier(sidBytes, 0);
                    }

                    var row = new DatatableRow
                    {
                        AccountExpires = accountExpiresColumn.Value,
                        DisplayName = displayNameColumn.Value,
                        Dnt = distinguishedNameTagColumn.Value,
                        GroupType = groupTypeColumn.Value,
                        LastLogon = lastLogonColumn.Value,
                        Name = nameColumn.Value,
                        ObjectCategoryDnt = objectCategoryColumn.Value,
                        Rid = rid,
                        Sid = sid,
                        ParentDnt = parentDistinguishedNameTagColumn.Value,
                        Phantom = objColumn.Value == false,
                        LastPasswordChange = passwordLastSetColumn.Value,
                        PrimaryGroupDnt = primaryGroupIdColumn.Value,
                        RdnType = rdnTypeColumn.Value,
                        SamAccountName = samAccountNameColumn.Value,
                        UserAccountControlValue = userAccountControlColumn.Value,
                    };

                    if (dumpHashes)
                    {
                        if (pekListColumn.Value != null)
                        {
                            row.PekList = pekListColumn.Value;
                        }

                        if (lmColumn.Value != null)
                        {
                            row.EncryptedLmHash = lmColumn.Value;
                        }

                        if (ntColumn.Value != null)
                        {
                            row.EncryptedNtHash = ntColumn.Value;
                        }

                        if (includeHistoryHashes)
                        {
                            if (lmHistoryColumn.Value != null)
                            {
                                row.EncryptedLmHistory = lmHistoryColumn.Value;
                            }

                            if (ntHistoryColumn.Value != null)
                            {
                                row.EncryptedNtHistory = ntHistoryColumn.Value;
                            }
                        }

                        if (supplementalCredentialsColumn.Value != null)
                        {
                            row.SupplementalCredentialsBlob = supplementalCredentialsColumn.Value;
                        }
                    }

                    datatable.Add(row);
                }
            }

            if (ShowDebugOutput)
            {
                ConsoleEx.WriteDebug($"  Skipped {deletedCount} deleted objects");
                ConsoleEx.WriteDebug($"  Enumerated {datatable.Count} objects");

                stopwatch.Stop();
                ConsoleEx.WriteDebug($"  Completed in {stopwatch.Elapsed}");
            }

            return datatable.ToArray();
        }

        private static IReadOnlyDictionary<string, string> EnumerateDatatableTableLdapDisplayNames(JetDb db, MSysObjectsRow[] mSysObjects)
        {
            Stopwatch stopwatch = null;
            if (ShowDebugOutput)
            {
                ConsoleEx.WriteDebug($"Called: {nameof(NtdsAudit)}::{nameof(EnumerateDatatableTableLdapDisplayNames)}");
                stopwatch = new Stopwatch();
                stopwatch.Start();
            }

            var ldapDisplayNameToColumnNameDictionary = new Dictionary<string, string>();
            var unmatchedCount = 0;

            using (var table = db.OpenJetDbTable(DATATABLE))
            {
                // Get a dictionary mapping column names to column ids
                var columnDictionary = table.GetColumnDictionary();

                // Loop over the table
                table.MoveBeforeFirst();
                while (table.TryMoveNext())
                {
                    var ldapDisplayNameColumn = new StringColumnValue { Columnid = columnDictionary["ATTm131532"] };
                    var attributeIdColumn = new Int32ColumnValue { Columnid = columnDictionary["ATTc131102"] };
                    table.RetrieveColumns(attributeIdColumn, ldapDisplayNameColumn);

                    if (attributeIdColumn.Value != null)
                    {
                        if (Array.Find(mSysObjects, x => x.AttributeId == attributeIdColumn.Value) == null)
                        {
                            unmatchedCount++;
                        }
                        else
                        {
                            ldapDisplayNameToColumnNameDictionary.Add(ldapDisplayNameColumn.Value, mSysObjects.First(x => x.AttributeId == attributeIdColumn.Value).ColumnName);
                        }
                    }
                }
            }

            if (ShowDebugOutput)
            {
                ConsoleEx.WriteDebug($"  Failed to match {unmatchedCount} LDAP display names to datatable column names");
                ConsoleEx.WriteDebug($"  Matched {ldapDisplayNameToColumnNameDictionary.Count} LDAP display names to datatable column names");

                stopwatch.Stop();
                ConsoleEx.WriteDebug($"  Completed in {stopwatch.Elapsed}");
            }

            return new ReadOnlyDictionary<string, string>(ldapDisplayNameToColumnNameDictionary);
        }

        private static LinkTableRow[] EnumerateLinkTable(JetDb db)
        {
            Stopwatch stopwatch = null;
            if (ShowDebugOutput)
            {
                ConsoleEx.WriteDebug($"Called: {nameof(NtdsAudit)}::{nameof(EnumerateLinkTable)}");
                stopwatch = new Stopwatch();
                stopwatch.Start();
            }

            using (var table = db.OpenJetDbTable(LINKTABLE))
            {
                // Get a dictionary mapping column names to column ids
                var columnDictionary = table.GetColumnDictionary();

                var linktable = new List<LinkTableRow>();
                var deletedLinkCount = 0;

                // Loop over the table
                table.MoveBeforeFirst();
                while (table.TryMoveNext())
                {
                    var linkDelTimeColumn = new DateTimeColumnValue { Columnid = columnDictionary["link_deltime"] };
                    var linkDntColumn = new Int32ColumnValue { Columnid = columnDictionary["link_DNT"] };
                    var backlinkDnt = new Int32ColumnValue { Columnid = columnDictionary["backlink_DNT"] };
                    table.RetrieveColumns(linkDelTimeColumn, linkDntColumn, backlinkDnt);

                    // Ignore deleted links
                    if (linkDelTimeColumn.Error == JET_wrn.Success)
                    {
                        deletedLinkCount++;
                        continue;
                    }

                    linktable.Add(new LinkTableRow
                    {
                        LinkDnt = linkDntColumn.Value.Value,
                        BacklinkDnt = backlinkDnt.Value.Value,
                    });
                }

                if (ShowDebugOutput)
                {
                    ConsoleEx.WriteDebug($"  Ignored {deletedLinkCount} deleted backlinks");
                    ConsoleEx.WriteDebug($"  Found {linktable.Count} backlinks");

                    stopwatch.Stop();
                    ConsoleEx.WriteDebug($"  Completed in {stopwatch.Elapsed}");
                }

                return linktable.ToArray();
            }
        }

        private static MSysObjectsRow[] EnumerateMSysObjects(JetDb db)
        {
            Stopwatch stopwatch = null;
            if (ShowDebugOutput)
            {
                ConsoleEx.WriteDebug($"Called: {nameof(NtdsAudit)}::{nameof(EnumerateMSysObjects)}");
                stopwatch = new Stopwatch();
                stopwatch.Start();
            }

            var mSysObjects = new List<MSysObjectsRow>();

            using (var table = db.OpenJetDbTable(MSYSOBJECTS))
            {
                // Get a dictionary mapping column names to column ids
                var columnDictionary = table.GetColumnDictionary();

                // Loop over the table adding attribute ids and column names to the dictionary
                table.MoveBeforeFirst();
                while (table.TryMoveNext())
                {
                    var nameColumn = new Utf8StringColumnValue { Columnid = columnDictionary["Name"] };
                    table.RetrieveColumns(nameColumn);
                    if (nameColumn.Value.StartsWith("ATT", StringComparison.Ordinal))
                    {
                        mSysObjects.Add(new MSysObjectsRow
                        {
                            AttributeId = int.Parse(Regex.Replace(nameColumn.Value, "[A-Za-z-]", string.Empty, RegexOptions.None), CultureInfo.InvariantCulture),
                            ColumnName = nameColumn.Value,
                        });
                    }
                }
            }

            if (ShowDebugOutput)
            {
                ConsoleEx.WriteDebug($"  Found {mSysObjects.Count} datatable column names");

                stopwatch.Stop();
                ConsoleEx.WriteDebug($"  Completed in {stopwatch.Elapsed}");
            }

            return mSysObjects.ToArray();
        }

        private static DateTime? GetAccountExpiresDateTimeFromByteArray(byte[] value)
        {
            // https://msdn.microsoft.com/en-us/library/ms675098(v=vs.85).aspx
            if (value == null)
            {
                return null;
            }

            var ticks = BitConverter.ToInt64(value, 0);
            if (ticks == 0 || ticks == 9223372036854775807)
            {
                return null;
            }

            return new DateTime(1601, 1, 1).AddTicks(ticks);
        }

        private static Dictionary<string, string> PrecomputeHashes(string wordlistPath)
        {
            Stopwatch stopwatch = null;
            if (ShowDebugOutput)
            {
                ConsoleEx.WriteDebug($"Called: {nameof(NtdsAudit)}::{nameof(PrecomputeHashes)}");
                stopwatch = new Stopwatch();
                stopwatch.Start();
            }

            var ntlmHashToPasswordDictionary = new Dictionary<string, string>();
            foreach (var line in File.ReadAllLines(wordlistPath))
            {
                var hash = Ntlm.ComputeHash(line);
                if (!ntlmHashToPasswordDictionary.ContainsKey(hash))
                {
                    ntlmHashToPasswordDictionary[hash] = line;
                }
            }

            if (ShowDebugOutput)
            {
                stopwatch.Stop();
                ConsoleEx.WriteDebug($"  Completed in {stopwatch.Elapsed}");
            }

            return ntlmHashToPasswordDictionary;
        }

        private ComputerInfo[] CalculateComputerInfo()
        {
            Stopwatch stopwatch = null;
            if (ShowDebugOutput)
            {
                ConsoleEx.WriteDebug($"Called: {nameof(NtdsAudit)}::{nameof(CalculateComputerInfo)}");
                stopwatch = new Stopwatch();
                stopwatch.Start();
            }

            var computers = new List<ComputerInfo>();
            foreach (var row in _datatable)
            {
                if (row.ObjectCategory?.Equals("Computer") ?? false)
                {
                    var computerInfo = new ComputerInfo
                    {
                        Name = row.Name,
                        Dn = row.Dn,
                        DomainSid = row.Sid.AccountDomainSid,
                        Disabled = (row.UserAccountControlValue & (int)ADS_USER_FLAG.ADS_UF_ACCOUNTDISABLE) == (int)ADS_USER_FLAG.ADS_UF_ACCOUNTDISABLE,
                        LastLogon = row.LastLogon ?? DateTime.Parse("01.01.1601 00:00:00", CultureInfo.InvariantCulture),
                    };

                    if (_useOUFilter && !_ouFilter.Any(filterOU => computerInfo.Dn.EndsWith(filterOU)))
                    {
                        continue;
                    }

                    computers.Add(computerInfo);
                }
            }

            if (ShowDebugOutput)
            {
                stopwatch.Stop();
                ConsoleEx.WriteDebug($"  Completed in {stopwatch.Elapsed}");
            }

            return computers.ToArray();
        }

        private void CalculateDnsForDatatableRows()
        {
            Stopwatch stopwatch = null;
            if (ShowDebugOutput)
            {
                ConsoleEx.WriteDebug($"Called: {nameof(NtdsAudit)}::{nameof(CalculateDnsForDatatableRows)}");
                stopwatch = new Stopwatch();
                stopwatch.Start();
            }

            var commonNameAttrbiuteId = int.Parse(Regex.Replace(_ldapDisplayNameToDatatableColumnNameDictionary["cn"], "[A-Za-z-]", string.Empty, RegexOptions.None), CultureInfo.InvariantCulture);
            var organizationalUnitAttrbiuteId = int.Parse(Regex.Replace(_ldapDisplayNameToDatatableColumnNameDictionary["ou"], "[A-Za-z-]", string.Empty, RegexOptions.None), CultureInfo.InvariantCulture);
            var domainComponentAttrbiuteId = int.Parse(Regex.Replace(_ldapDisplayNameToDatatableColumnNameDictionary["dc"], "[A-Za-z-]", string.Empty, RegexOptions.None), CultureInfo.InvariantCulture);

            var attributeIdToDistinguishedNamePrefexDictionary = new Dictionary<int, string>
            {
                [commonNameAttrbiuteId] = "CN=",
                [organizationalUnitAttrbiuteId] = "OU=",
                [domainComponentAttrbiuteId] = "DC=",
            };

            var dntToPartialDnDictionary = new Dictionary<int, string>();
            var dntToPdntDictionary = new Dictionary<int, int>();

            foreach (var row in _datatable)
            {
                if (row.RdnType == commonNameAttrbiuteId
                        || row.RdnType == organizationalUnitAttrbiuteId
                        || row.RdnType == domainComponentAttrbiuteId)
                {
                    dntToPartialDnDictionary[row.Dnt.Value] = attributeIdToDistinguishedNamePrefexDictionary[row.RdnType.Value] + row.Name;
                    if (row.ParentDnt.Value != 0)
                    {
                        dntToPdntDictionary[row.Dnt.Value] = row.ParentDnt.Value;
                    }
                }
            }

            var dntToDnDictionary = new Dictionary<int, string>();

            foreach (var kvp in dntToPartialDnDictionary)
            {
                dntToDnDictionary[kvp.Key] = dntToPartialDnDictionary[kvp.Key];
                var parentDnt = dntToPdntDictionary[kvp.Key];
                while (dntToPartialDnDictionary.ContainsKey(parentDnt))
                {
                    dntToDnDictionary[kvp.Key] += "," + dntToPartialDnDictionary[parentDnt];
                    parentDnt = dntToPdntDictionary[parentDnt];
                }
            }

            foreach (var row in _datatable)
            {
                if (row.RdnType == commonNameAttrbiuteId
                        || row.RdnType == organizationalUnitAttrbiuteId
                        || row.RdnType == domainComponentAttrbiuteId)
                {
                    row.Dn = dntToDnDictionary[row.Dnt.Value];
                }
            }

            if (ShowDebugOutput)
            {
                stopwatch.Stop();
                ConsoleEx.WriteDebug($"  Completed in {stopwatch.Elapsed}");
            }
        }

        private DomainInfo[] CalculateDomainInfo()
        {
            Stopwatch stopwatch = null;
            if (ShowDebugOutput)
            {
                ConsoleEx.WriteDebug($"Called: {nameof(NtdsAudit)}::{nameof(CalculateDomainInfo)}");
                stopwatch = new Stopwatch();
                stopwatch.Start();
            }

            var domains = new List<DomainInfo>();
            foreach (var row in _datatable)
            {
                if (row.Sid?.BinaryLength == 24)
                {
                    var domainInfo = new DomainInfo
                    {
                        Sid = row.Sid,
                        Name = row.Name,
                        Dn = row.Dn,
                    };
                    domainInfo.AdministratorsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, domainInfo.Sid);
                    domainInfo.DomainAdminsSid = new SecurityIdentifier(WellKnownSidType.AccountDomainAdminsSid, domainInfo.Sid);
                    domainInfo.EnterpriseAdminsSid = new SecurityIdentifier(WellKnownSidType.AccountEnterpriseAdminsSid, domainInfo.Sid);
                    domainInfo.Fqdn = domainInfo.Dn.Replace("DC=", ".").Replace(",", string.Empty).TrimStart('.');

                    domains.Add(domainInfo);
                }
            }

            if (ShowDebugOutput)
            {
                stopwatch.Stop();
                ConsoleEx.WriteDebug($"  Completed in {stopwatch.Elapsed}");
            }

            return domains.ToArray();
        }

        private void CalculateGroupMembership()
        {
            Stopwatch stopwatch = null;
            if (ShowDebugOutput)
            {
                ConsoleEx.WriteDebug($"Called: {nameof(NtdsAudit)}::{nameof(CalculateGroupMembership)}");
                stopwatch = new Stopwatch();
                stopwatch.Start();
            }

            // Create a dictionary mapping DNTs to object category names which can later be used to ignore any backlinks that do not relate to users or groups
            var dntToObjectCategoryDictionary = _datatable.ToDictionary(x => x.Dnt, x => x.ObjectCategory);

            // Create dictionary mapping DNTs to a list of backlinks (members)
            var linkDictionary = _linkTable.GroupBy(x => x.LinkDnt).ToDictionary(g => g.Key, g => g.Select(x => x.BacklinkDnt));

            // Look over the groups using the above dictionaries to populate the group members DNTs
            foreach (var group in Groups)
            {
                // If the group DNT is not in the link dictionary, then no relevant group members were found
                if (!linkDictionary.ContainsKey(group.Dnt))
                {
                    group.MembersDnts = new int[] { };
                }
                else
                {
                    group.MembersDnts = linkDictionary[group.Dnt]
                        .Where(x => x != group.Dnt && (dntToObjectCategoryDictionary.ContainsKey(x) && (dntToObjectCategoryDictionary[x] == "Group" || dntToObjectCategoryDictionary[x] == "Builtin" || dntToObjectCategoryDictionary[x] == "Person")))
                        .ToArray();
                }
            }

            // Loop over each group again calculating recursive group membership
            foreach (var group in Groups)
            {
                var recursiveMembersDnts = new HashSet<int>();
                CalculateRecursiveGroupMembership(group, recursiveMembersDnts);
                group.RecursiveMembersDnts = recursiveMembersDnts.ToArray();
            }

            // Loop over each user and add group sids
            foreach (var user in Users)
            {
                user.RecursiveGroupSids = Groups.Where(x => x.RecursiveMembersDnts.Contains(user.Dnt)).Select(x => x.Sid).ToArray();
            }

            if (ShowDebugOutput)
            {
                stopwatch.Stop();
                ConsoleEx.WriteDebug($"  Completed in {stopwatch.Elapsed}");
            }
        }

        private void CalculateObjectCategoryStringForDatableRows()
        {
            Stopwatch stopwatch = null;
            if (ShowDebugOutput)
            {
                ConsoleEx.WriteDebug($"Called: {nameof(NtdsAudit)}::{nameof(CalculateObjectCategoryStringForDatableRows)}");
                stopwatch = new Stopwatch();
                stopwatch.Start();
            }

            var classSchemaRowDnt = _datatable.Single(x => x.Name.Equals("Class-Schema")).Dnt;

            var objectCategoryDntToObjectCategoryStringDictionary = _datatable.Where(x => x.ObjectCategoryDnt == classSchemaRowDnt).ToDictionary(x => x.Dnt, x => x.Name);

            foreach (var row in _datatable)
            {
                if (row.ObjectCategoryDnt.HasValue)
                {
                    row.ObjectCategory = objectCategoryDntToObjectCategoryStringDictionary[row.ObjectCategoryDnt];
                }
            }

            if (ShowDebugOutput)
            {
                stopwatch.Stop();
                ConsoleEx.WriteDebug($"  Completed in {stopwatch.Elapsed}");
            }
        }

        private void CalculateRecursiveGroupMembership(GroupInfo group, HashSet<int> recursiveMembersDnts)
        {
            foreach (var memberDnt in group.MembersDnts)
            {
                // Do not add self to prevent infinite recursion
                if (memberDnt == group.Dnt)
                {
                    continue;
                }

                // HashSet returns false if the item is already in the set, this can be used to prevent infinite recursion
                if (recursiveMembersDnts.Add(memberDnt))
                {
                    // If member DNT relates to a known group, get is members
                    var childGroup = Groups.SingleOrDefault(x => x.Dnt == memberDnt);
                    if (childGroup != null)
                    {
                        CalculateRecursiveGroupMembership(childGroup, recursiveMembersDnts);
                    }
                }
            }
        }

        private GroupInfo[] CalculateSecurityGroupInfo()
        {
            Stopwatch stopwatch = null;
            if (ShowDebugOutput)
            {
                ConsoleEx.WriteDebug($"Called: {nameof(NtdsAudit)}::{nameof(CalculateSecurityGroupInfo)}");
                stopwatch = new Stopwatch();
                stopwatch.Start();
            }

            var groups = new List<GroupInfo>();
            foreach (var row in _datatable)
            {
                if (row.ObjectCategory?.Equals("Group") ?? false)
                {
                    if ((row.GroupType & (uint)ADS_GROUP_TYPE_ENUM.ADS_GROUP_TYPE_SECURITY_ENABLED) == (uint)ADS_GROUP_TYPE_ENUM.ADS_GROUP_TYPE_SECURITY_ENABLED)
                    {
                        var groupInfo = new GroupInfo
                        {
                            Name = row.Name,
                            Dn = row.Dn,
                            DomainSid = row.Sid.AccountDomainSid,
                            Dnt = row.Dnt.Value,
                            Sid = row.Sid,
                        };
                        groups.Add(groupInfo);
                    }
                    else
                    {
                    }
                }
            }

            if (ShowDebugOutput)
            {
                stopwatch.Stop();
                ConsoleEx.WriteDebug($"  Completed in {stopwatch.Elapsed}");
            }

            return groups.ToArray();
        }

        private UserInfo[] CalculateUserInfo()
        {
            Stopwatch stopwatch = null;
            if (ShowDebugOutput)
            {
                ConsoleEx.WriteDebug($"Called: {nameof(NtdsAudit)}::{nameof(CalculateUserInfo)}");
                stopwatch = new Stopwatch();
                stopwatch.Start();
            }

            var users = new List<UserInfo>();
            foreach (var row in _datatable)
            {
                if ((row.UserAccountControlValue & (int)ADS_USER_FLAG.ADS_UF_NORMAL_ACCOUNT) == (int)ADS_USER_FLAG.ADS_UF_NORMAL_ACCOUNT && row.ObjectCategory.Equals("Person"))
                {
                    var userInfo = new UserInfo
                    {
                        Dnt = row.Dnt.Value,
                        Name = row.Name,
                        Dn = row.Dn,
                        DomainSid = row.Sid.AccountDomainSid,
                        Disabled = (row.UserAccountControlValue & (int)ADS_USER_FLAG.ADS_UF_ACCOUNTDISABLE) == (int)ADS_USER_FLAG.ADS_UF_ACCOUNTDISABLE,
                        LastLogon = row.LastLogon ?? DateTime.Parse("01.01.1601 00:00:00", CultureInfo.InvariantCulture),
                        PasswordNotRequired = (row.UserAccountControlValue & (int)ADS_USER_FLAG.ADS_UF_PASSWD_NOTREQD) == (int)ADS_USER_FLAG.ADS_UF_PASSWD_NOTREQD,
                        PasswordNeverExpires = (row.UserAccountControlValue & (int)ADS_USER_FLAG.ADS_UF_DONT_EXPIRE_PASSWD) == (int)ADS_USER_FLAG.ADS_UF_DONT_EXPIRE_PASSWD,
                        Expires = GetAccountExpiresDateTimeFromByteArray(row.AccountExpires),
                        PasswordLastChanged = row.LastPasswordChange ?? DateTime.Parse("01.01.1601 00:00:00", CultureInfo.InvariantCulture),
                        SamAccountName = row.SamAccountName,
                        Rid = row.Rid,
                        LmHash = row.LmHash,
                        NtHash = row.NtHash,
                        LmHistory = row.LmHistory,
                        NtHistory = row.NtHistory,
                        ClearTextPassword = row.SupplementalCredentials?.ContainsKey("Primary:CLEARTEXT") ?? false ? Encoding.Unicode.GetString(row.SupplementalCredentials["Primary:CLEARTEXT"]) : null
                    };

                    if (_useOUFilter && !_ouFilter.Any(filterOU => userInfo.Dn.EndsWith(filterOU)))
                    {
                        continue;
                    }

                    users.Add(userInfo);
                }
            }

            if (ShowDebugOutput)
            {
                stopwatch.Stop();
                ConsoleEx.WriteDebug($"  Completed in {stopwatch.Elapsed}");
            }

            return users.ToArray();
        }

        private void CheckUsersForWeakPasswords(Dictionary<string, string> ntlmHashToPasswordDictionary)
        {
            Stopwatch stopwatch = null;
            if (ShowDebugOutput)
            {
                ConsoleEx.WriteDebug($"Called: {nameof(NtdsAudit)}::{nameof(CheckUsersForWeakPasswords)}");
                stopwatch = new Stopwatch();
                stopwatch.Start();
            }

            foreach (var user in Users)
            {
                if (ntlmHashToPasswordDictionary.ContainsKey(user.NtHash))
                {
                    user.Password = ntlmHashToPasswordDictionary[user.NtHash];
                }
            }

            if (ShowDebugOutput)
            {
                stopwatch.Stop();
                ConsoleEx.WriteDebug($"  Completed in {stopwatch.Elapsed}");
            }
        }

        private void DecryptSecretData(string systemKeyPath, bool includeHistoryHashes)
        {
            Stopwatch stopwatch = null;
            if (ShowDebugOutput)
            {
                ConsoleEx.WriteDebug($"Called: {nameof(NtdsAudit)}::{nameof(DecryptSecretData)}");
                stopwatch = new Stopwatch();
                stopwatch.Start();
            }

            var systemKey = SystemHive.LoadSystemKeyFromHive(systemKeyPath);

            var encryptedPek = _datatable.Single(x => x.PekList != null).PekList;
            var decryptedPekList = NTCrypto.DecryptPekList(systemKey, encryptedPek);

            foreach (var row in _datatable)
            {
                if ((row.UserAccountControlValue & (int)ADS_USER_FLAG.ADS_UF_NORMAL_ACCOUNT) == (int)ADS_USER_FLAG.ADS_UF_NORMAL_ACCOUNT)
                {
                    if (row.EncryptedLmHash != null)
                    {
                        try
                        {
                            row.LmHash = ByteArrayToHexString(NTCrypto.DecryptHashes(decryptedPekList, row.EncryptedLmHash, row.Rid));
                        }
                        catch (Exception ex)
                        {
                            if (ShowDebugOutput)
                            {
                                ConsoleEx.WriteDebug($"Failed to decrypt LM hash for '{row.SamAccountName}' with error: {ex.Message}");
                            }

                            row.LmHash = EMPTY_LM_HASH;
                        }
                    }
                    else
                    {
                        row.LmHash = EMPTY_LM_HASH;
                    }

                    if (row.EncryptedNtHash != null)
                    {
                        try
                        {
                            row.NtHash = ByteArrayToHexString(NTCrypto.DecryptHashes(decryptedPekList, row.EncryptedNtHash, row.Rid));
                        }
                        catch (Exception ex)
                        {
                            if (ShowDebugOutput)
                            {
                                ConsoleEx.WriteDebug($"Failed to decrypt NT hash for '{row.SamAccountName}' with error: {ex.Message}");
                            }

                            row.NtHash = EMPTY_LM_HASH;
                        }
                    }
                    else
                    {
                        row.NtHash = EMPTY_NT_HASH;
                    }

                    if (includeHistoryHashes)
                    {
                        if (row.EncryptedLmHistory != null)
                        {
                            var hashStrings = new List<string>();

                            var decryptedHashes = new byte[0];
                            try
                            {
                                decryptedHashes = NTCrypto.DecryptHashes(decryptedPekList, row.EncryptedLmHistory, row.Rid);
                            }
                            catch (Exception ex)
                            {
                                if (ShowDebugOutput)
                                {
                                    ConsoleEx.WriteDebug($"Failed to decrypt LM history hashes for '{row.SamAccountName}' with error: {ex.Message}");
                                }
                            }

                            // The first hash is the same as the current hash, so skip it
                            for (var i = 16; i < decryptedHashes.Length; i += 16)
                            {
                                // If lm hash is disabled for the account, the lm history will contain junk data, ignore it
                                if (row.LmHash == EMPTY_LM_HASH)
                                {
                                    hashStrings.Add(EMPTY_LM_HASH);
                                }
                                else
                                {
                                    hashStrings.Add(ByteArrayToHexString(decryptedHashes.Skip(i).Take(16).ToArray()));
                                }
                            }

                            row.LmHistory = hashStrings.ToArray();
                        }

                        if (row.EncryptedNtHistory != null)
                        {
                            var hashStrings = new List<string>();

                            var decryptedHashes = new byte[0];
                            try
                            {
                                decryptedHashes = NTCrypto.DecryptHashes(decryptedPekList, row.EncryptedNtHistory, row.Rid);
                            }
                            catch (Exception ex)
                            {
                                if (ShowDebugOutput)
                                {
                                    ConsoleEx.WriteDebug($"Failed to decrypt LM history hashes for '{row.SamAccountName}' with error: {ex.Message}");
                                }
                            }

                            // The first hash is the same as the current hash, so skip it
                            for (var i = 16; i < decryptedHashes.Length; i += 16)
                            {
                                hashStrings.Add(ByteArrayToHexString(decryptedHashes.Skip(i).Take(16).ToArray()));
                            }

                            row.NtHistory = hashStrings.ToArray();
                        }
                    }

                    if (row.SupplementalCredentialsBlob != null)
                    {
                        try
                        {
                            row.SupplementalCredentials = NTCrypto.DecryptSupplementalCredentials(decryptedPekList, row.SupplementalCredentialsBlob);
                        }
                        catch (Exception ex)
                        {
                            if (ShowDebugOutput)
                            {
                                ConsoleEx.WriteDebug($"Failed to decrypt supplemental credentials for '{row.SamAccountName}' with error: {ex.Message}");
                            }
                        }
                    }
                }
            }

            if (ShowDebugOutput)
            {
                stopwatch.Stop();
                ConsoleEx.WriteDebug($"  Completed in {stopwatch.Elapsed}");
            }
        }
    }
}
