namespace NtdsAudit
{
    using System.Diagnostics;
    using System.Security.Principal;

    /// <summary>
    /// Provides information extracted from NTDS in relation to a group.
    /// </summary>
    [DebuggerDisplay("{Name}")]
    internal class GroupInfo
    {
        /// <summary>
        /// Gets or sets the Distinguished Name.
        /// </summary>
        internal string Dn { get; set; }

        /// <summary>
        /// Gets or sets the Distinguished Name Tag.
        /// </summary>
        internal int Dnt { get; set; }

        /// <summary>
        /// Gets or sets the SID of the domain the group belongs to.
        /// </summary>
        internal SecurityIdentifier DomainSid { get; set; }

        /// <summary>
        /// Gets or sets the list of DNTs of group members.
        /// </summary>
        internal int[] MembersDnts { get; set; }

        /// <summary>
        /// Gets or sets the name.
        /// </summary>
        internal string Name { get; set; }

        /// <summary>
        /// Gets or sets the recursive list of DNTs of group members.
        /// </summary>
        internal int[] RecursiveMembersDnts { get; set; }

        /// <summary>
        /// Gets or sets the SID.
        /// </summary>
        internal SecurityIdentifier Sid { get; set; }
    }
}
