#pragma once
class NTCrypto
{
public:
	void static DecryptPek(PBYTE pbSystemKey, PBYTE pbPekListData, PBYTE pbPek);
	void static DecryptHash(PBYTE pbKey, DWORD dwRid, PBYTE pbData, DWORD dwDataLength);
	void static DecryptHashHistory(PBYTE pbKey, DWORD dwRid, PBYTE pbData, DWORD dwDataLength);
private:
	typedef struct _DES_KEY_BLOB {
		BLOBHEADER Hdr;
		DWORD dwKeySize;
		BYTE rgbKeyData[8];
	} DES_KEY_BLOB;

	void static EncryptDecryptWithPek(PBYTE pbKey, DWORD dwKeyLength, PBYTE pbSalt, DWORD dwSaltLength, DWORD dwSaltRounds, PBYTE pbData, DWORD dwDataLength);
	void static DecryptSecretData(PBYTE pbKey, DWORD dwKeyLength, PBYTE pbData, DWORD dwDataLength);
	void static DecryptSingleHash(DWORD dwRid, PBYTE pbHash);
	void static RidToKeys(DWORD dwRid, PBYTE pbKey1, PBYTE pbKey2);
	void static StrToKey(PBYTE pbStr, PBYTE pbKey);
};

