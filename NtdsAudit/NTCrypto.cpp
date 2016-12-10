#include "stdafx.h"
#include "NTCrypto.h"

// Decrypts PEK from NTDS pekList column
/* Data is excepted as follows
// |........|................|....................................................|
//   ^- Header 8 bytes (ignored)
//            ^- Salt 16 bytes
//                             ^- Encrypted PEK 52 bytes
//
// Decrypted PEK is written to the 16 byte pbPek buffer
*/
void NTCrypto::DecryptPek(PBYTE pbSystemKey, PBYTE pbPekListData, PBYTE pbPek)
{
	EncryptDecryptWithPek(
		pbSystemKey, 
		16, // Sytem key is 16 bytes
		pbPekListData + 8, // ignore the 8 byte header 
		16, // PEK salt is 16 bytes
		1000, // salt with 1000 rounds
		pbPekListData + 24, // skip header and salt
		52 // PEK is 52 bytes
	);

	// Decrypted PEK is the last 16 bytes of the 52 byte data buffer
	memcpy(pbPek, pbPekListData + 60, 16);

	// Erase the original buffer
	SecureZeroMemory(pbPekListData, 76);
}


// Decypts a single hash from a NTDS column such as dBCSPwd (LM) or unicodePwd (NT)
/* Data is excepted as follows
// |........|................|................|
//   ^- Header 8 bytes (ignored)
//            ^- Salt 16 bytes
//                             ^- Encrypted hash 16 bytes
*/
void NTCrypto::DecryptHash(PBYTE pbKey, DWORD dwRid, PBYTE pbData, DWORD dwDataLength)
{
	// Decrypt data
	DecryptSecretData(pbKey, 16, pbData, 40);

	// Decrypt hash
	DecryptSingleHash(dwRid, pbData + 24);

	// Relocate decrypted hash to beginning of buffer
	memcpy(pbData, pbData + 24, 16);

	// Erase rest of buffer
	SecureZeroMemory(pbData + 16, dwDataLength - 16);
}

// Decypts a password hash history from a NTDS column such as lmPwdHistory or ntPwdHistory
/* Data is excepted as follows
// |........|................|................|................| cont.
//   ^- Header 8 bytes (ignored)
//            ^- Salt 16 bytes
//                             ^- Encrypted hash 16 bytes
//							                    ^- Encrypted hash 16 bytes
*/
void NTCrypto::DecryptHashHistory(PBYTE pbKey, DWORD dwRid, PBYTE pbData, DWORD dwDataLength)
{
	// Decrypt data
	DecryptSecretData(pbKey, 16, pbData, dwDataLength);

	// Decrypt hashes
	for (DWORD i = 24; i < dwDataLength; i += 16)
	{
		DecryptSingleHash(dwRid, pbData + i);
	}

	// Relocate decrypted hashes to beginning of buffer
	memcpy(pbData, pbData + 24, dwDataLength - 24);

	// Erase rest of buffer
	SecureZeroMemory(pbData + (dwDataLength - 24), 24);
}



/* -------------------------------- 
   Private Methods
   -------------------------------- */

// Decrypts (or encrypts) data using RC4. Key is drived from MD5 hash of the key and the salt
void NTCrypto::EncryptDecryptWithPek(PBYTE pbKey, DWORD dwKeyLength, PBYTE pbSalt, DWORD dwSaltLength, DWORD dwSaltRounds, PBYTE pbData, DWORD dwDataLength)
{
	DWORD dwError;
	ULONG_PTR hProv;
	ULONG_PTR hHash;
	ULONG_PTR hKey;

	// Get handle to the crypto provider
	if (!CryptAcquireContext(&hProv,
		NULL,
		NULL,
		PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT))
	{
		dwError = GetLastError();
		std::string error = "CryptAcquireContext failed: " + dwError;
		throw std::exception(error.c_str());
	}

	// Create MD5 hashing function
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		CryptReleaseContext(hProv, 0);
		dwError = GetLastError();
		std::string error = "CryptCreateHash failed: " + dwError;
		throw std::exception(error.c_str());
	}

	// Hash the key
	if (!CryptHashData(hHash, pbKey, dwKeyLength, 0))
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		dwError = GetLastError();
		std::string error = "CryptHashData failed: " + dwError;
		throw std::exception(error.c_str());
	}

	// Hash the salt for the specified number of rounds
	for (DWORD i = 0; i < dwSaltRounds; i++)
	{
		if (!CryptHashData(hHash, pbSalt, dwSaltLength, 0))
		{
			CryptDestroyHash(hHash);
			CryptReleaseContext(hProv, 0);
			dwError = GetLastError();
			std::string error = "CryptHashData failed: " + dwError;
			throw std::exception(error.c_str());
		}
	}

	// Derive the RC4 key
	if (!CryptDeriveKey(hProv, CALG_RC4, hHash, 0, &hKey))
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		dwError = GetLastError();
		std::string error = "CryptDeriveKey failed: " + dwError;
		throw std::exception(error.c_str());
	}

	// Encrypt/Decrypt
	if (!CryptEncrypt(hKey, NULL, TRUE, 0, pbData, &dwDataLength, dwDataLength))
	{
		CryptDestroyKey(hKey);
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		dwError = GetLastError();
		std::string error = "CryptEncrypt failed: " + dwError;
		throw std::exception(error.c_str());
	}

	CryptDestroyKey(hKey);
	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
}

// Decrypts secret data taken from a column in NTDS that has been encrypted with the PEK
/* Data is excepted as follows
// |........|................|...............+|
//   ^- Header 8 bytes (ignored)
//            ^- Salt 16 bytes
//                             ^- Encrypted blob to end of buffer
*/
void NTCrypto::DecryptSecretData(PBYTE pbKey, DWORD dwKeyLength, PBYTE pbData, DWORD dwDataLength)
{
	EncryptDecryptWithPek(
		pbKey, 
		dwKeyLength,
		pbData + 8, // ignore the first 8 bytes to get the salt 
		16, // salt is 16 bytes
		1,
		pbData + 24, // skip the header and salt
		dwDataLength - 24);
}

// Decrypts a single hash using DES keys derived from the RID (after the buffer has already been decrypted with the PEK)
/* Data is excepted as follows
// |................|
//   ^- Encrypted hash 16 bytes
*/
void NTCrypto::DecryptSingleHash(DWORD dwRid, PBYTE pbHash)
{
	DWORD dwError;
	DWORD dwDecryptLength;
	ULONG_PTR hProv;
	HCRYPTKEY hKey1;
	HCRYPTKEY hKey2;

	// Create key structures
	DES_KEY_BLOB key1;
	key1.Hdr.bType = PLAINTEXTKEYBLOB;
	key1.Hdr.bVersion = CUR_BLOB_VERSION;
	key1.Hdr.reserved = 0;
	key1.Hdr.aiKeyAlg = CALG_DES;
	key1.dwKeySize = 8;
	DES_KEY_BLOB key2;
	key2.Hdr.bType = PLAINTEXTKEYBLOB;
	key2.Hdr.bVersion = CUR_BLOB_VERSION;
	key2.Hdr.reserved = 0;
	key2.Hdr.aiKeyAlg = CALG_DES;
	key2.dwKeySize = 8;

	// Get keys from RID
	NTCrypto::RidToKeys(dwRid, key1.rgbKeyData, key2.rgbKeyData);

	// Get handle to the crypto provider
	if (!CryptAcquireContext(&hProv,
		NULL,
		NULL,
		PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT))
	{
		dwError = GetLastError();
		std::string error = "CryptAcquireContext failed: " + dwError;
		throw std::exception(error.c_str());
	}

	// Import key 1
	if (!CryptImportKey(hProv, (BYTE*)&key1, sizeof(key1), 0, 0, &hKey1))
	{
		CryptReleaseContext(hProv, 0);
		dwError = GetLastError();
		std::string error = "CryptImportKey failed: " + dwError;
		throw std::exception(error.c_str());
	}

	// Import key 2
	if (!CryptImportKey(hProv, (BYTE*)&key2, sizeof(key2), 0, 0, &hKey2))
	{
		CryptDestroyKey(hKey1);
		CryptReleaseContext(hProv, 0);
		dwError = GetLastError();
		std::string error = "CryptImportKey failed: " + dwError;
		throw std::exception(error.c_str());
	}

	// Decrypt first part of hash
	dwDecryptLength = 8;
	if (!CryptDecrypt(hKey1, 0, FALSE, 0, pbHash, &dwDecryptLength))
	{
		CryptDestroyKey(hKey2);
		CryptDestroyKey(hKey1);
		CryptReleaseContext(hProv, 0);
		dwError = GetLastError();
		std::string error = "CryptDecrypt failed: " + dwError;
		throw std::exception(error.c_str());
	}

	// Decrypt second part of hash
	dwDecryptLength = 8;
	if (!CryptDecrypt(hKey2, 0, FALSE, 0, pbHash + 8, &dwDecryptLength))
	{
		CryptDestroyKey(hKey2);
		CryptDestroyKey(hKey1);
		CryptReleaseContext(hProv, 0);
		dwError = GetLastError();
		std::string error = "CryptDecrypt failed: " + dwError;
		throw std::exception(error.c_str());
	}

	CryptDestroyKey(hKey2);
	CryptDestroyKey(hKey1);
	CryptReleaseContext(hProv, 0);
}

// Convert RID to DES decrypt keys
void NTCrypto::RidToKeys(DWORD dwRid, PBYTE pbKey1, PBYTE pbKey2)
{
	// https://download.samba.org/pub/samba/pwdump/pwdump.c

	unsigned char s1[7];

	s1[0] = (unsigned char)(dwRid & 0xFF);
	s1[1] = (unsigned char)((dwRid >> 8) & 0xFF);
	s1[2] = (unsigned char)((dwRid >> 16) & 0xFF);
	s1[3] = (unsigned char)((dwRid >> 24) & 0xFF);
	s1[4] = s1[0];
	s1[5] = s1[1];
	s1[6] = s1[2];

	StrToKey(s1, pbKey1);

	unsigned char s2[7];

	s2[0] = (unsigned char)((dwRid >> 24) & 0xFF);
	s2[1] = (unsigned char)(dwRid & 0xFF);
	s2[2] = (unsigned char)((dwRid >> 8) & 0xFF);
	s2[3] = (unsigned char)((dwRid >> 16) & 0xFF);
	s2[4] = s2[0];
	s2[5] = s2[1];
	s2[6] = s2[2];

	StrToKey(s2, pbKey2);
}

// Convert a 7 byte array into an 8 byte des key with odd parity.
void NTCrypto::StrToKey(PBYTE pbStr, PBYTE pbKey)
{
	// https://download.samba.org/pub/samba/pwdump/pwdump.c

	pbKey[0] = pbStr[0] >> 1;
	pbKey[1] = ((pbStr[0] & 0x01) << 6) | (pbStr[1] >> 2);
	pbKey[2] = ((pbStr[1] & 0x03) << 5) | (pbStr[2] >> 3);
	pbKey[3] = ((pbStr[2] & 0x07) << 4) | (pbStr[3] >> 4);
	pbKey[4] = ((pbStr[3] & 0x0F) << 3) | (pbStr[4] >> 5);
	pbKey[5] = ((pbStr[4] & 0x1F) << 2) | (pbStr[5] >> 6);
	pbKey[6] = ((pbStr[5] & 0x3F) << 1) | (pbStr[6] >> 7);
	pbKey[7] = pbStr[6] & 0x7F;
	for (int i = 0; i<8; i++) {
		pbKey[i] = (pbKey[i] << 1);
	}
}