namespace NtdsAudit
{
    /// <summary>
    /// Provides information extracted from NTDS in relation to a row from the linktable.
    /// </summary>
    internal class LinkTableRow
    {
        /// <summary>
        /// Gets or sets the backlink DNT.
        /// </summary>
        public int BacklinkDnt { get; set; }

        /// <summary>
        /// Gets or sets the link DNT.
        /// </summary>
        public int LinkDnt { get; set; }
    }
}
