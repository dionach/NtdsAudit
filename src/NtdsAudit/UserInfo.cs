namespace NtdsAudit
{
    using System;
    using System.Diagnostics;
    using System.Security.Principal;

    /// <summary>
    /// Provides information extracted from NTDS in relation to a user account.
    /// </summary>
    [DebuggerDisplay("{Name}")]
    internal class UserInfo
    {
        /// <summary>
        /// Gets or sets the clear text password (passwords stored using reversible encryption).
        /// </summary>
        internal string ClearTextPassword { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the account is disabled.
        /// </summary>
        internal bool Disabled { get; set; }

        /// <summary>
        /// Gets or sets the Distinguished Name.
        /// </summary>
        internal string Dn { get; set; }

        /// <summary>
        /// Gets or sets the Distinguished Name Tag.
        /// </summary>
        internal int Dnt { get; set; }

        /// <summary>
        /// Gets or sets the SID of the doamin the account belongs to.
        /// </summary>
        internal SecurityIdentifier DomainSid { get; set; }

        /// <summary>
        /// Gets or sets the expiration date.
        /// </summary>
        internal DateTime? Expires { get; set; }

        /// <summary>
        /// Gets or sets the last logon date and time.
        /// </summary>
        internal DateTime LastLogon { get; set; }

        /// <summary>
        /// Gets or sets the LM hash.
        /// </summary>
        internal string LmHash { get; set; }

        /// <summary>
        /// Gets or sets the LM history hashes.
        /// </summary>
        internal string[] LmHistory { get; set; }

        /// <summary>
        /// Gets or sets the name.
        /// </summary>
        internal string Name { get; set; }

        /// <summary>
        /// Gets or sets the NT hash.
        /// </summary>
        internal string NtHash { get; set; }

        /// <summary>
        /// Gets or sets the NT history hashes.
        /// </summary>
        internal string[] NtHistory { get; set; }

        /// <summary>
        /// Gets or sets the password.
        /// </summary>
        internal string Password { get; set; }

        /// <summary>
        /// Gets or sets the date time the password was last changed.
        /// </summary>
        internal DateTime PasswordLastChanged { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the password is set to never expire.
        /// </summary>
        internal bool PasswordNeverExpires { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether a password is not required.
        /// </summary>
        internal bool PasswordNotRequired { get; set; }

        /// <summary>
        /// Gets or sets the SIDs of groups of which the account is a member.
        /// </summary>
        internal SecurityIdentifier[] RecursiveGroupSids { get; set; }

        /// <summary>
        /// Gets or sets the Relative ID.
        /// </summary>
        internal uint Rid { get; set; }

        /// <summary>
        /// Gets or sets the sam account name.
        /// </summary>
        internal string SamAccountName { get; set; }
    }
}
