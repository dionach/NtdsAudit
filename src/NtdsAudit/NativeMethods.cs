#pragma warning disable SA1600

namespace NtdsAudit
{
    using System;
    using System.Runtime.InteropServices;

    /// <summary>
    /// Provides PInvoke methods required by the application.
    /// </summary>
    internal static class NativeMethods
    {
        public const int CALGDES = 0x00006601;
        public const int CALGMD5 = 0x00008003;
        public const int CALGRC4 = 0x00006801;
        public const uint CRYPTVERIFYCONTEXT = 0xF0000000;
        public const int CURBLOBVERSION = 2;
        public const int PLAINTEXTKEYBLOB = 0x8;
        public const uint PROVRSAFULL = 1;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptAcquireContext(
            ref IntPtr hProv,
            string pszContainer,
            string pszProvider,
            uint dwProvType,
            uint dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptCreateHash(
            IntPtr hProv,
            uint algId,
            IntPtr hKey,
            uint dwFlags,
            ref IntPtr phHash);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptDecrypt(
            IntPtr hKey,
            IntPtr hHash,
            int final,
            uint dwFlags,
            byte[] pbData,
            ref uint pdwDataLen);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptDeriveKey(
            IntPtr hProv,
            int algid,
            IntPtr hBaseData,
            int flags,
            ref IntPtr phKey);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptDestroyHash(
            IntPtr hHash);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptDestroyKey(
            IntPtr phKey);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptEncrypt(
            IntPtr hKey,
            IntPtr hHash,
            int final,
            uint dwFlags,
            byte[] pbData,
            ref uint pdwDataLen,
            uint dwBufLen);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptHashData(
            IntPtr hHash,
            byte[] pbData,
            uint dataLen,
            uint flags);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptImportKey(
                    IntPtr hProv,
                    byte[] pbKeyData,
                    int dwDataLen,
                    IntPtr hPubKey,
                    int dwFlags,
                    ref IntPtr hKey);

        [DllImport("Advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptReleaseContext(
                    IntPtr hProv,
                    int dwFlags);

        [StructLayout(LayoutKind.Sequential)]
        public struct PUBLICKEYSTRUC
        {
            public byte BType;
            public byte BVersion;
            public short Reserved;
            public int AiKeyAlg;
        }
    }
}

#pragma warning restore SA1600
