namespace NtdsAudit
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using System.Text;
    using static System.FormattableString;

    /// <summary>
    /// Contains methods for decrypting data within an NTDS database, such as user password hashes.
    /// </summary>
    internal static class NTCrypto
    {
        /*
        // 2.2.11.1.1 Encrypting an NT or LM Hash Value with a Specified Key
        // https://msdn.microsoft.com/en-us/library/cc245507.aspx
        // Split the hash value into two blocks, Block1 and Block2. Block1 is the first 8 bytes of the hash (starting from the left); Block2 is the remaining 8 bytes.
        // Each block is encrypted with a different 7-byte key; call them Key1 and Key2.
        // If the specified key is an unsigned integer, see section 2.2.11.1.3 for the way to derive Key1 and Key2.
        // If the specified key is a 16-byte value, see section 2.2.11.1.4 for the way to derive Key1 and Key2.
        // Let EncryptedBlock1 be the result of applying the algorithm in section 2.2.11.1.2 over Block1 with Key1.
        // Let EncryptedBlock2 be the result of applying the algorithm in section 2.2.11.1.2 over Block2 with Key2.
        // The encrypted hash value is the concatenation of EncryptedBlock1 and EncryptedBlock2.

        // 2.2.11.1.2 Encrypting a 64-Bit Block with a 7-Byte Key
        // https://msdn.microsoft.com/en-us/library/cc245508.aspx?f=255&MSPPError=-2147217396
        // Transform the 7-byte key into an 8-byte key as follows:
        // Let InputKey be the 7-byte key, represented as a zero-base-index array.
        // Let OutputKey be an 8-byte key, represented as a zero-base-index array.
        // Let OutputKey be assigned as follows.
        //  OutputKey[0] = InputKey[0] >> 0x01;
        //  OutputKey[1] = ((InputKey[0]&0x01)<<6) | (InputKey[1]>>2);
        //  OutputKey[2] = ((InputKey[1]&0x03)<<5) | (InputKey[2]>>3);
        //  OutputKey[3] = ((InputKey[2]&0x07)<<4) | (InputKey[3]>>4);
        //  OutputKey[4] = ((InputKey[3]&0x0F)<<3) | (InputKey[4]>>5);
        //  OutputKey[5] = ((InputKey[4]&0x1F)<<2) | (InputKey[5]>>6);
        //  OutputKey[6] = ((InputKey[5]&0x3F)<<1) | (InputKey[6]>>7);
        //  OutputKey[7] = InputKey[6] & 0x7F;
        // The 7-byte InputKey is expanded to 8 bytes by inserting a 0-bit after every seventh bit.
        //  for( int i=0; i<8; i++ )
        //  {
        //     OutputKey[i] = (OutputKey[i] << 1) & 0xfe;
        //  }
        //
        // Let the least-significant bit of each byte of OutputKey be a parity bit. That is, if the sum of the preceding seven bits is odd, the eighth bit is 0; otherwise, the eighth bit is 1. The processing starts at the leftmost bit of OutputKey.
        // Use [FIPS81] to encrypt the 64-bit block using OutputKey. If the higher-level operation is decryption instead of encryption, this is the point at which an implementer MUST specify the decryption intent to [FIPS81].

        // 2.2.11.1.3 Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key
        // https://msdn.microsoft.com/en-us/library/cc245509.aspx
        // Let I be the little-endian, unsigned integer.
        // Let I[X] be the Xth byte of I, where I is interpreted as a zero-base-index array of bytes. Note that because I is in little-endian byte order, I[0] is the least significant byte.
        // Key1 is a concatenation of the following values: I[0], I[1], I[2], I[3], I[0], I[1], I[2].
        // Key2 is a concatenation of the following values: I[3], I[0], I[1], I[2], I[3], I[0], I[1].

        // 2.2.11.1.4 Deriving Key1 and Key2 from a 16-Byte Key
        // https://msdn.microsoft.com/en-us/library/cc245510.aspx
        // Let Key1 be the first 7 bytes of the 16-byte key.
        // Let Key2 be the next 7 bytes of the 16-byte value. For example, consider a zero-base-index array of 16 bytes called KeyArray that contains the 16-byte key. Key2 is composed of the bytes KeyArray[7] through KeyArray[13], inclusive.
        // Note A consequence of this derivation is that the fifteenth and sixteenth bytes are ignored.
        */

        private enum EncryptionType : ushort
        {
            PekWithRc4AndSalt = 17,
            PekWithAes = 19,
        }

        private enum PekListFlags : uint
        {
            ClearText = 0,
            Encrypted = 1,
        }

        private enum PekListVersion : uint
        {
            Windows2000 = 2,
            Windows2016 = 3,
        }

        /// <summary>
        /// Decypts hashes from a NTDS column such as dBCSPwd (LM) or unicodePwd (NT)
        /// History hashes use the same format, but with additional 16 byte hashes appended
        /// Data is excepted as follows
        /// |........|................|................|................|
        ///   ^- Header 8 bytes (Algorithm ID (2b), Flags (2b), PEK ID (4b))
        ///            ^- Salt 16 bytes
        ///                             ^- Encrypted hash 16 bytes
        ///                                               ^- Optional additional encrypted 16 byte hashes
        ///
        /// All data after the salt is first decrypted using the PEK. Each 16 byte hash is then decrypted using keys generated from the RID.
        /// </summary>
        /// <param name="pekList">The PEKs.</param>
        /// <param name="encryptedHashBlob">The encrypted 40 byte blob, consisting of header, salt, and hash. Every additional 16 bytes should be an additional hash.</param>
        /// <param name="rid">The RID of the related account.</param>
        /// <returns>The decrypted 16 byte hash. Every additional 16 bytes will be an additional hash.</returns>
        public static byte[] DecryptHashes(Dictionary<uint, byte[]> pekList, byte[] encryptedHashBlob, uint rid)
        {
            var decryptedData = DecryptSecret(pekList, encryptedHashBlob);

            var decryptedHashes = new List<byte>();
            for (var i = 0; i < decryptedData.Length; i += 16)
            {
                (var key1, var key2) = RidToKeys(rid);
                var decryptedHash = DecryptDataWithKeyPair(key1, key2, decryptedData.Skip(i).Take(16).ToArray());
                decryptedHashes.AddRange(decryptedHash);
            }

            return decryptedHashes.ToArray();
        }

        /// <summary>
        /// Decrypts Password Encryption Key (PEK) from NTDS pekList column
        /// Data is excepted as follows
        /// |........|................|....................................................|
        ///   ^- Header 8 bytes (Version (4 bytes), Flags (4 bytes))
        ///            ^- Salt 16 bytes
        ///                             ^- Encrypted PEK, varible length depending on number of keys.
        /// </summary>
        /// <param name="systemKey">The 16 byte system key. This is used to decrypt the PEK.</param>
        /// <param name="encryptedPekListBlob">The encrypted 76 byte Password Encryption Key.</param>
        /// <returns>The clear text 16 byte PEK.</returns>
        public static Dictionary<uint, byte[]> DecryptPekList(byte[] systemKey, byte[] encryptedPekListBlob)
        {
            if (systemKey.Length != 16)
            {
                throw new ArgumentOutOfRangeException(nameof(systemKey));
            }

            var version = BitConverter.ToUInt32(encryptedPekListBlob, 0);
            if (!Enum.IsDefined(typeof(PekListVersion), version))
            {
                throw new ArgumentOutOfRangeException(nameof(encryptedPekListBlob), Invariant($"PEK List version \"{version}\" is not supported."));
            }

            var flags = BitConverter.ToUInt32(encryptedPekListBlob, 4);
            if (!Enum.IsDefined(typeof(PekListFlags), flags))
            {
                throw new ArgumentOutOfRangeException(nameof(encryptedPekListBlob), Invariant($"PEK List flags value \"{version}\" is not supported."));
            }

            var salt = encryptedPekListBlob.Skip(8).Take(16).ToArray();
            var encryptedPekList = encryptedPekListBlob.Skip(24).ToArray();
            byte[] decryptedPekList = null;

            switch ((PekListFlags)flags)
            {
                case PekListFlags.ClearText:
                    decryptedPekList = encryptedPekList;
                    break;

                case PekListFlags.Encrypted:
                    switch ((PekListVersion)version)
                    {
                        case PekListVersion.Windows2000:
                            decryptedPekList = DecryptDataUsingRc4AndSalt(systemKey, salt, encryptedPekList, 1000);
                            break;

                        case PekListVersion.Windows2016:
                            decryptedPekList = DecryptDataUsingAes(systemKey, salt, encryptedPekList).ToArray();
                            break;
                    }

                    break;
            }

            return ParsePekList(decryptedPekList);
        }

        /// <summary>
        /// Data is excepted as follows
        /// |........|................|.....
        ///   ^- Header 8 bytes (Algorithm ID (2b), Flags (2b), PEK ID (4b))
        ///            ^- Salt 16 bytes
        ///                             ^- Encrypted data
        /// </summary>
        /// <param name="pekList">The PEKs.</param>
        /// <param name="encryptedBlob">The encrypted 40 byte blob, consisting of header, salt, and data.</param>
        /// <returns>The decrypted data</returns>
        public static byte[] DecryptSecret(Dictionary<uint, byte[]> pekList, byte[] encryptedBlob)
        {
            var algorithm = BitConverter.ToUInt16(encryptedBlob, 0);
            if (!Enum.IsDefined(typeof(EncryptionType), algorithm))
            {
                throw new ArgumentOutOfRangeException(nameof(encryptedBlob), Invariant($"Algorithm \"{algorithm}\" is not supported."));
            }

            var pekId = BitConverter.ToUInt32(encryptedBlob, 4);
            var pek = pekList[pekId];

            var salt = encryptedBlob.Skip(8).Take(16).ToArray();
            var encryptedData = encryptedBlob.Skip(24).ToArray();

            switch ((EncryptionType)algorithm)
            {
                case EncryptionType.PekWithRc4AndSalt:
                    return DecryptDataUsingRc4AndSalt(pek, salt, encryptedData, 1);

                case EncryptionType.PekWithAes:
                    // When using AES, data is padded and the first 4 bytes contains the actual data length
                    var length = BitConverter.ToUInt32(encryptedData, 0);
                    encryptedData = encryptedData.Skip(4).ToArray();
                    return DecryptDataUsingAes(pek, salt, encryptedData).Take((int)length).ToArray();

                default:
                    throw new ArgumentOutOfRangeException(nameof(encryptedBlob), Invariant($"Encryption type \"{(EncryptionType)algorithm}\" is not supported."));
            }
        }

        /// <summary>
        /// The format of supplementalCredentials is a USER_PROPERTIES structure (https://msdn.microsoft.com/en-us/library/cc245674.aspx).
        /// USER_PROPERTIES structure is as follows (https://msdn.microsoft.com/en-us/library/cc245500.aspx):
        ///
        /// Reserved1 (4 bytes): This value MUST be set to zero and MUST be ignored by the recipient.
        /// Length(4 bytes): This value MUST be set to the length, in bytes, of the entire structure, starting from the Reserved4 field.
        /// Reserved2(2 bytes): This value MUST be set to zero and MUST be ignored by the recipient.
        /// Reserved3(2 bytes): This value MUST be set to zero and MUST be ignored by the recipient.
        /// Reserved4(96 bytes): This value MUST be ignored by the recipient and MAY contain arbitrary values.
        /// PropertySignature(2 bytes): This field MUST be the value 0x50, in little-endian byte order.This is an arbitrary value used to indicate whether the structure is corrupt.That is, if this value is not 0x50 on read, the structure is considered corrupt, processing MUST be aborted, and an error code MUST be returned.
        /// PropertyCount(2 bytes): The number of USER_PROPERTY elements in the UserProperties field.When there are zero USER_PROPERTY elements in the UserProperties field, this field MUST be omitted; the resultant USER_PROPERTIES structure has a constant size of 0x6F bytes.
        /// UserProperties(variable): An array of PropertyCount USER_PROPERTY elements.
        /// Reserved5(1 byte): This value SHOULD be set to zero and MUST be ignored by the recipient.
        ///
        /// USER_PROPERTY structure is as follows (https://msdn.microsoft.com/en-us/library/cc245501.aspx):
        ///
        /// NameLength (2 bytes): The number of bytes, in little-endian byte order, of PropertyName. The property name is located at an offset of zero bytes just following the Reserved field. For more information, see the message processing section for supplementalCredentials (section 3.1.1.8.11).
        /// ValueLength(2 bytes): The number of bytes contained in PropertyValue.
        /// Reserved(2 bytes): This value MUST be ignored by the recipient and MAY be set to arbitrary values on update.
        /// PropertyName(variable): The name of this property as a UTF-16 encoded string.
        /// PropertyValue(variable): The value of this property.The value MUST be hexadecimal-encoded using an 8-bit character size, and the values '0' through '9' inclusive and 'a' through 'f' inclusive(the specification of 'a' through 'f' is case-sensitive).
        /// </summary>
        /// <param name="pekList">The PEK list.</param>
        /// <param name="encryptedSupplementalCredentialsBlob">The encrypted blob.</param>
        /// <returns>Clear text passwords.</returns>
        public static Dictionary<string, byte[]> DecryptSupplementalCredentials(Dictionary<uint, byte[]> pekList, byte[] encryptedSupplementalCredentialsBlob)
        {
            var decryptedBlob = NTCrypto.DecryptSecret(pekList, encryptedSupplementalCredentialsBlob);

            var properties = new Dictionary<string, byte[]>();

            // If there are zero USER_PROPERTY elements, the length will be 0x6F
            if (decryptedBlob.Length == 0x6F)
            {
                return properties;
            }

            var propertiesCount = BitConverter.ToUInt16(decryptedBlob, 110);
            var propertiesBlob = decryptedBlob.Skip(112).Take(decryptedBlob.Length - 113).ToArray();

            using (var reader = new BinaryReader(new MemoryStream(propertiesBlob)))
            {
                for (var i = 0; i < propertiesCount; i++)
                {
                    var nameLength = reader.ReadUInt16();
                    var valueLength = reader.ReadUInt16();
                    reader.ReadUInt16();
                    var propertyNameBlob = reader.ReadBytes(nameLength);
                    var propertyValueBlob = reader.ReadBytes(valueLength);

                    var propertyName = Encoding.Unicode.GetString(propertyNameBlob);
                    var hexEncodedPropertyValue = Encoding.ASCII.GetString(propertyValueBlob);
                    var propertyValue = Enumerable.Range(0, hexEncodedPropertyValue.Length)
                     .Where(x => x % 2 == 0)
                     .Select(x => Convert.ToByte(hexEncodedPropertyValue.Substring(x, 2), 16))
                     .ToArray();

                    properties[propertyName] = propertyValue;
                }
            }

            return properties;
        }

        private static byte[] DecryptDataUsingAes(byte[] key, byte[] salt, byte[] data)
        {
            using (var aes = AesManaged.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.Zeros;
                using (var decryptor = aes.CreateDecryptor(key, salt))
                {
                    using (var cryptoStream = new CryptoStream(new MemoryStream(data, false), decryptor, CryptoStreamMode.Read))
                    using (var outputStream = new MemoryStream(data.Length))
                    {
                        cryptoStream.CopyTo(outputStream);
                        return outputStream.ToArray();
                    }
                }
            }
        }

        private static byte[] DecryptDataUsingRc4AndSalt(byte[] key, byte[] salt, byte[] data, int rounds)
        {
            var hProv = IntPtr.Zero;
            var hHash = IntPtr.Zero;
            var hKey = IntPtr.Zero;

            // Get handle to the crypto provider
            if (!NativeMethods.CryptAcquireContext(ref hProv, null, null, NativeMethods.PROVRSAFULL, NativeMethods.CRYPTVERIFYCONTEXT))
            {
                NativeMethods.CryptReleaseContext(hProv, 0);
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            // Create MD5 hashing function
            if (!NativeMethods.CryptCreateHash(hProv, NativeMethods.CALGMD5, IntPtr.Zero, 0, ref hHash))
            {
                NativeMethods.CryptReleaseContext(hProv, 0);
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            // Hash the key
            if (!NativeMethods.CryptHashData(hHash, key, (uint)key.Length, 0))
            {
                NativeMethods.CryptDestroyHash(hHash);
                NativeMethods.CryptReleaseContext(hProv, 0);
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            // Hash the salt for the specified number of rounds
            for (var i = 0; i < rounds; i++)
            {
                if (!NativeMethods.CryptHashData(hHash, salt, (uint)salt.Length, 0))
                {
                    NativeMethods.CryptDestroyHash(hHash);
                    NativeMethods.CryptReleaseContext(hProv, 0);
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }

            // Derive the RC4 key
            if (!NativeMethods.CryptDeriveKey(hProv, NativeMethods.CALGRC4, hHash, 0, ref hKey))
            {
                NativeMethods.CryptDestroyHash(hHash);
                NativeMethods.CryptReleaseContext(hProv, 0);
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            uint pdwDataLen = (uint)data.Length;

            // Encrypt/Decrypt
            if (!NativeMethods.CryptEncrypt(hKey, IntPtr.Zero, 1, 0, data, ref pdwDataLen, (uint)data.Length))
            {
                NativeMethods.CryptDestroyKey(hKey);
                NativeMethods.CryptDestroyHash(hHash);
                NativeMethods.CryptReleaseContext(hProv, 0);
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            NativeMethods.CryptDestroyKey(hKey);
            NativeMethods.CryptDestroyHash(hHash);
            NativeMethods.CryptReleaseContext(hProv, 0);

            return data;
        }

        /// <summary>
        /// Decrypts data (such as a single password hash) using DES keys derived from the RID.
        /// Data is excepted as follows
        /// |................|
        ///   ^- Encrypted hash 16 bytes
        /// </summary>
        /// <param name="key1">The first DES key used for decryption. For password hashes, this should be generated from the account RID.</param>
        /// <param name="key2">The second DES key used for decryption. For password hashes, this should be generated from the account RID.</param>
        /// <param name="data">The data to decrypt.</param>
        /// <returns>The decrypted data.</returns>
        private static byte[] DecryptDataWithKeyPair(byte[] key1, byte[] key2, byte[] data)
        {
            var data1 = data.Take(data.Length / 2).ToArray();
            var data2 = data.Skip(data.Length / 2).ToArray();
            var hProv = IntPtr.Zero;
            var hKey1 = IntPtr.Zero;
            var hKey2 = IntPtr.Zero;

            var keyHeader = new NativeMethods.PUBLICKEYSTRUC
            {
                BType = NativeMethods.PLAINTEXTKEYBLOB,
                BVersion = NativeMethods.CURBLOBVERSION,
                Reserved = 0,
                AiKeyAlg = NativeMethods.CALGDES,
            };

            var keyHeaderBytes = StructureToByteArray(keyHeader);

            var keyWithHeader1 = keyHeaderBytes.Concat(BitConverter.GetBytes(data1.Length)).Concat(key1).ToArray();
            var keyWithHeader2 = keyHeaderBytes.Concat(BitConverter.GetBytes(data2.Length)).Concat(key2).ToArray();

            // Get handle to the crypto provider
            if (!NativeMethods.CryptAcquireContext(ref hProv, null, null, NativeMethods.PROVRSAFULL, NativeMethods.CRYPTVERIFYCONTEXT))
            {
                NativeMethods.CryptReleaseContext(hProv, 0);
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            // Import key 1
            if (!NativeMethods.CryptImportKey(hProv, keyWithHeader1, keyWithHeader1.Length, IntPtr.Zero, 0, ref hKey1))
            {
                NativeMethods.CryptReleaseContext(hProv, 0);
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            // Import key 2
            if (!NativeMethods.CryptImportKey(hProv, keyWithHeader2, keyWithHeader2.Length, IntPtr.Zero, 0, ref hKey2))
            {
                NativeMethods.CryptDestroyKey(hKey1);
                NativeMethods.CryptReleaseContext(hProv, 0);
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            // Decrypt first part of hash
            uint pdwDataLen1 = (uint)data1.Length;
            if (!NativeMethods.CryptDecrypt(hKey1, IntPtr.Zero, 0, 0, data1, ref pdwDataLen1))
            {
                NativeMethods.CryptDestroyKey(hKey2);
                NativeMethods.CryptDestroyKey(hKey1);
                NativeMethods.CryptReleaseContext(hProv, 0);
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            // Decrypt second part of hash
            uint pdwDataLen2 = (uint)data2.Length;
            if (!NativeMethods.CryptDecrypt(hKey2, IntPtr.Zero, 0, 0, data2, ref pdwDataLen2))
            {
                NativeMethods.CryptDestroyKey(hKey2);
                NativeMethods.CryptDestroyKey(hKey1);
                NativeMethods.CryptReleaseContext(hProv, 0);
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            NativeMethods.CryptDestroyKey(hKey2);
            NativeMethods.CryptDestroyKey(hKey1);
            NativeMethods.CryptReleaseContext(hProv, 0);

            return data1.Concat(data2).ToArray();
        }

        /// <summary>
        /// Data is excepted as follows
        /// |................|........|....|....|{....|................|}
        ///   ^- Signature 16 bytes
        ///                    ^- Last generated 8 bytes
        ///                             ^- Current key 4 bytes
        ///                                  ^- Key count 4 bytes
        ///                                       ^- Key ID 4 bytes (Key and Key ID repeated for key count)
        ///                                             ^- Key 16 bytes (Key and Key ID repeated for key count)
        /// </summary>
        /// <param name="decryptedPekList">The decrypted PEK list.</param>
        /// <returns>The current PEK.</returns>
        private static Dictionary<uint, byte[]> ParsePekList(byte[] decryptedPekList)
        {
            var keys = new Dictionary<uint, byte[]>();
            for (var i = 32; i < decryptedPekList.Length; i += 24)
            {
                var id = BitConverter.ToUInt32(decryptedPekList, i);
                var key = decryptedPekList.Skip(i + 4).Take(16).ToArray();

                keys[id] = key;
            }

            return keys;
        }

#pragma warning disable SA1008

        private static (byte[] key1, byte[] key2) RidToKeys(uint rid)
        {
            var s1 = new char[7];
            var s2 = new char[7];

            s1[0] = (char)(rid & 0xFF);
            s1[1] = (char)((rid >> 8) & 0xFF);
            s1[2] = (char)((rid >> 16) & 0xFF);
            s1[3] = (char)((rid >> 24) & 0xFF);
            s1[4] = s1[0];
            s1[5] = s1[1];
            s1[6] = s1[2];

            s2[0] = (char)((rid >> 24) & 0xFF);
            s2[1] = (char)(rid & 0xFF);
            s2[2] = (char)((rid >> 8) & 0xFF);
            s2[3] = (char)((rid >> 16) & 0xFF);
            s2[4] = s2[0];
            s2[5] = s2[1];
            s2[6] = s2[2];

            return (StrToKey(s1), StrToKey(s2));
        }

#pragma warning restore SA1008

        private static byte[] StrToKey(char[] str)
        {
            var key = new byte[8];

            key[0] = BitConverter.GetBytes(str[0] >> 1)[0];
            key[1] = BitConverter.GetBytes(((str[0] & 0x01) << 6) | (str[1] >> 2))[0];
            key[2] = BitConverter.GetBytes(((str[1] & 0x03) << 5) | (str[2] >> 3))[0];
            key[3] = BitConverter.GetBytes(((str[2] & 0x07) << 4) | (str[3] >> 4))[0];
            key[4] = BitConverter.GetBytes(((str[3] & 0x0F) << 3) | (str[4] >> 5))[0];
            key[5] = BitConverter.GetBytes(((str[4] & 0x1F) << 2) | (str[5] >> 6))[0];
            key[6] = BitConverter.GetBytes(((str[5] & 0x3F) << 1) | (str[6] >> 7))[0];
            key[7] = BitConverter.GetBytes(str[6] & 0x7F)[0];
            for (int i = 0; i < 8; i++)
            {
                key[i] = BitConverter.GetBytes(key[i] << 1)[0];
            }

            return key;
        }

        private static byte[] StructureToByteArray(object obj)
        {
            int len = Marshal.SizeOf(obj);

            byte[] arr = new byte[len];

            IntPtr ptr = Marshal.AllocHGlobal(len);

            Marshal.StructureToPtr(obj, ptr, true);

            Marshal.Copy(ptr, arr, 0, len);

            Marshal.FreeHGlobal(ptr);

            return arr;
        }
    }
}
