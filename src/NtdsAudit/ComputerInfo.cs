namespace NtdsAudit
{
    using System;
    using System.Diagnostics;
    using System.Security.Principal;

    /// <summary>
    /// Provides information extracted from NTDS in relation to a computer account.
    /// </summary>
    [DebuggerDisplay("{Name}")]
    internal class ComputerInfo
    {
        /// <summary>
        /// Gets or sets a value indicating whether the account is disabled.
        /// </summary>
        internal bool Disabled { get; set; }

        /// <summary>
        /// Gets or sets the Distinguished Name.
        /// </summary>
        internal string Dn { get; set; }

        /// <summary>
        /// Gets or sets the SID of the domain to which the account belongs.
        /// </summary>
        internal SecurityIdentifier DomainSid { get; set; }

        /// <summary>
        /// Gets or sets the last logon date and time.
        /// </summary>
        internal DateTime LastLogon { get; set; }

        /// <summary>
        /// Gets or sets the name.
        /// </summary>
        internal string Name { get; set; }
    }
}
