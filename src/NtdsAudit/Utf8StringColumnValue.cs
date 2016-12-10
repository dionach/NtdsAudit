namespace Microsoft.Isam.Esent.Interop
{
    using System.Text;

    /// <summary>
    /// A UTF8 string column value.
    /// </summary>
    internal class Utf8StringColumnValue : StringColumnValue
    {
        /// <inheritdoc/>
        protected override void GetValueFromBytes(byte[] value, int startIndex, int count, int err)
        {
            Value = Encoding.UTF8.GetString(value, startIndex, count);
        }
    }
}
