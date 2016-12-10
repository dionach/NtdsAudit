namespace NtdsAudit
{
    using System;
    using System.Text;

    /// <summary>
    /// Provides methods from creating NTLM hashes.
    /// </summary>
    internal static class Ntlm
    {
        /// <summary>
        /// Creates an NTLM hash from a provided string.
        /// </summary>
        /// <param name="password">The string to hash.</param>
        /// <returns>The hash, as a hexidecimal string.</returns>
        public static string ComputeHash(string password)
        {
            using (var md4 = new MD4())
            {
                var unicodePassword = Encoding.Convert(Encoding.ASCII, Encoding.Unicode, Encoding.ASCII.GetBytes(password));
                var hash = md4.ComputeHash(unicodePassword);
                return BitConverter.ToString(hash).Replace("-", string.Empty);
            }
        }
    }
}
