namespace NtdsAudit
{
    /// <summary>
    /// Provides information extracted from NTDS in relation to a row from the mSysObjects table.
    /// </summary>
    internal class MSysObjectsRow
    {
        /// <summary>
        /// Gets or sets the attribute ID.
        /// </summary>
        public int AttributeId { get; set; }

        /// <summary>
        /// Gets or sets the column name.
        /// </summary>
        public string ColumnName { get; set; }
    }
}
