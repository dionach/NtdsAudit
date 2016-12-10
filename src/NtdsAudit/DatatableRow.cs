namespace NtdsAudit
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Security.Principal;

    /// <summary>
    /// Provides information extracted from NTDS in relation to a row of the datatable.
    /// </summary>
    [DebuggerDisplay("{Name}")]
    internal class DatatableRow
    {
        /// <summary>
        /// Gets or sets the SupplementalCredentials.
        /// </summary>
        public Dictionary<string, byte[]> SupplementalCredentials { get; internal set; }

        /// <summary>
        /// Gets or sets the 'accountExpires' value.
        /// </summary>
        internal byte[] AccountExpires { get; set; }

        /// <summary>
        /// Gets or sets the 'displayName' value.
        /// </summary>
        internal string DisplayName { get; set; }

        /// <summary>
        /// Gets or sets the Distinguished Name.
        /// </summary>
        internal string Dn { get; set; }

        /// <summary>
        /// Gets or sets the 'DNT_col' value.
        /// </summary>
        internal int? Dnt { get; set; }

        /// <summary>
        /// Gets or sets the 'dBCSPwd' value.
        /// </summary>
        internal byte[] EncryptedLmHash { get; set; }

        /// <summary>
        /// Gets or sets the 'lmPwdHistory' value.
        /// </summary>
        internal byte[] EncryptedLmHistory { get; set; }

        /// <summary>
        /// Gets or sets the 'unicodePwd' value.
        /// </summary>
        internal byte[] EncryptedNtHash { get; set; }

        /// <summary>
        /// Gets or sets the 'ntPwdHistory' value.
        /// </summary>
        internal byte[] EncryptedNtHistory { get; set; }

        /// <summary>
        /// Gets or sets the 'groupType' value.
        /// </summary>
        internal int? GroupType { get; set; }

        /// <summary>
        /// Gets or sets the 'lastLogonTimestamp' value.
        /// </summary>
        internal DateTime? LastLogon { get; set; }

        /// <summary>
        /// Gets or sets the 'pwdLastSet' value.
        /// </summary>
        internal DateTime? LastPasswordChange { get; set; }

        /// <summary>
        /// Gets or sets the decrypted LM hash.
        /// </summary>
        internal string LmHash { get; set; }

        /// <summary>
        /// Gets or sets the decrypted LM history hashes.
        /// </summary>
        internal string[] LmHistory { get; set; }

        /// <summary>
        /// Gets or sets the 'name' value.
        /// </summary>
        internal string Name { get; set; }

        /// <summary>
        /// Gets or sets the decrypted NT hash.
        /// </summary>
        internal string NtHash { get; set; }

        /// <summary>
        /// Gets or sets the decrypted NT history hashes.
        /// </summary>
        internal string[] NtHistory { get; set; }

        /// <summary>
        /// Gets or sets the object category name.
        /// </summary>
        internal string ObjectCategory { get; set; }

        /// <summary>
        /// Gets or sets the 'objectCategory' value.
        /// </summary>
        internal int? ObjectCategoryDnt { get; set; }

        /// <summary>
        /// Gets or sets the 'PDNT_col' value.
        /// </summary>
        internal int? ParentDnt { get; set; }

        /// <summary>
        /// Gets or sets the 'pekList' value.
        /// </summary>
        internal byte[] PekList { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the row respresents a phantom record.
        /// </summary>
        internal bool Phantom { get; set; }

        /// <summary>
        /// Gets or sets the 'primaryGroupID' value.
        /// </summary>
        internal int? PrimaryGroupDnt { get; set; }

        /// <summary>
        /// Gets or sets the 'RDNtyp_col' value.
        /// </summary>
        internal int? RdnType { get; set; }

        /// <summary>
        /// Gets or sets the RID based on the SID.
        /// </summary>
        internal uint Rid { get; set; }

        /// <summary>
        /// Gets or sets the 'sAMAccountName' value.
        /// </summary>
        internal string SamAccountName { get; set; }

        /// <summary>
        /// Gets or sets the 'objectSid' value.
        /// </summary>
        internal SecurityIdentifier Sid { get; set; }

        /// <summary>
        /// Gets or sets the 'supplementalCredentials' value.
        /// </summary>
        internal byte[] SupplementalCredentialsBlob { get; set; }

        /// <summary>
        /// Gets or sets the 'userAccountControl' value.
        /// </summary>
        internal int? UserAccountControlValue { get; set; }
    }
}
