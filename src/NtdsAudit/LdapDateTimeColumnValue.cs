namespace Microsoft.Isam.Esent.Interop
{
    using System;

    /// <summary>
    /// A date time column value based on the LDAP epoch.
    /// </summary>
    internal class LdapDateTimeColumnValue : DateTimeColumnValue
    {
        /// <inheritdoc/>
        protected override void GetValueFromBytes(byte[] value, int startIndex, int count, int err)
        {
            if ((JET_wrn)err == JET_wrn.ColumnNull)
            {
                Value = null;
            }
            else
            {
                CheckDataCount(count);
                var ticks = BitConverter.ToInt64(value, startIndex);
                Value = new DateTime(1601, 1, 1).AddTicks(ticks);
            }
        }
    }
}
