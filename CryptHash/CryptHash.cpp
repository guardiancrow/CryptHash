//Copyright(c) 2016 guardiancrow

// CryptHash.cpp : コンソール アプリケーションのエントリ ポイントを定義します。
//

#include "stdafx.h"

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "Shlwapi.lib")

BOOL HashIt(volatile LPBYTE *ppHashData, DWORD *pdwHashSize, const BYTE *lpData, const DWORD dwDataSize, ALG_ID algid)
{
	HCRYPTPROV	hProv = NULL;
	HCRYPTHASH	hHash = NULL;
	DWORD		dwHashSize = 0;
	volatile LPBYTE		lpHashData = NULL;

	if (ppHashData == NULL || pdwHashSize == NULL || lpData == NULL || dwDataSize == 0) {
		return FALSE;
	}

	if (algid != CALG_SHA1 && algid != CALG_SHA_256 && algid != CALG_SHA_384 && algid != CALG_SHA_512) {
		return FALSE;
	}

	*ppHashData = NULL;
	*pdwHashSize = 0;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return FALSE;
	}

	if (!CryptCreateHash(hProv, algid, 0, 0, &hHash)) {
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}

	CryptHashData(hHash, lpData, dwDataSize, 0);

	CryptGetHashParam(hHash, HP_HASHVAL, NULL, &dwHashSize, 0);
	lpHashData = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, dwHashSize + 1);
	CryptGetHashParam(hHash, HP_HASHVAL, lpHashData, &dwHashSize, 0);

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);

	*ppHashData = lpHashData;
	*pdwHashSize = dwHashSize;

	return TRUE;
}

BOOL ReadIt(LPBYTE *ppData, DWORD *pdwDataSize, LPTSTR pszFileName)
{
	HANDLE		hFile = NULL;
	LARGE_INTEGER	liFileSize;
	BYTE		*lpData = NULL;
	DWORD		dwReaded = 0;
	BOOL		bFlag = 0;

	if (ppData == NULL || pdwDataSize == NULL || pszFileName == NULL) {
		return FALSE;
	}

	*ppData = NULL;
	*pdwDataSize = 0;

	if (!PathFileExists(pszFileName)) {
		wprintf(L"ERROR: File Not Found. -> %s\n", pszFileName);
		return FALSE;
	}

	if ((hFile = CreateFile(pszFileName, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0)) == INVALID_HANDLE_VALUE) {
		wprintf(L"ERROR: File Cannot Open. -> %s\n", pszFileName);
		return FALSE;
	}

	SecureZeroMemory(&liFileSize, sizeof(LARGE_INTEGER));
	if (!GetFileSizeEx(hFile, &liFileSize)) {
		CloseHandle(hFile);
		hFile = NULL;
		return FALSE;
	}

	lpData = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, liFileSize.LowPart + 1);
	SecureZeroMemory(lpData, sizeof(lpData));
	bFlag = ReadFile(hFile, lpData, liFileSize.LowPart, &dwReaded, NULL);
	if (dwReaded == 0) {
		wprintf(L"ERROR: File Cannot Read. -> %s\n", pszFileName);
		SecureZeroMemory(lpData, sizeof(lpData));
		HeapFree(GetProcessHeap(), 0, lpData);
		lpData = NULL;
		CloseHandle(hFile);
		hFile = NULL;
		return FALSE;
	}
	CloseHandle(hFile);
	hFile = NULL;

	*ppData = lpData;
	*pdwDataSize = dwReaded;

	return TRUE;
}

int wmain(int argc, wchar_t *argv[])
{
	DWORD		dwBufferSize = 0;
	DWORD		dwHashSize = 0;
	volatile LPBYTE		lpHashData = NULL;
	BYTE		*lpData = NULL;
	DWORD		dwReaded = 0;
	TCHAR		*pszBuf = NULL;
	TCHAR		*pszAlgOption = NULL;
	TCHAR		*pszFileName = NULL;
	ALG_ID		alg = 0;

	_wsetlocale(LC_CTYPE, L"");

	pszAlgOption = (TCHAR*)HeapAlloc(GetProcessHeap(), 0, sizeof(TCHAR) * 256 + 1);
	SecureZeroMemory(pszAlgOption, sizeof(pszAlgOption));
	pszFileName = (TCHAR*)HeapAlloc(GetProcessHeap(), 0, sizeof(TCHAR) * MAX_PATH + 1);
	SecureZeroMemory(pszFileName, sizeof(pszFileName));
	if (argc >= 3) {
		wcscpy_s(pszAlgOption, 256, argv[1]);
		wcscpy_s(pszFileName, MAX_PATH, argv[2]);
	}
	else if (argc == 2) {
		wcscpy_s(pszFileName, MAX_PATH, argv[1]);
	}
	else {
		wprintf(L"usage:\nCryptHash [-sha1|-sha256|-sha384|-sha512] filename");
		return 0;
	}
	//wprintf(L"[option] %s %s\n", pszAlgOption, pszFileName);
	if (wcscmp(pszAlgOption, L"-sha1") == 0) {
		alg = CALG_SHA1;
	}
	else if (wcscmp(pszAlgOption, L"-sha256") == 0) {
		alg = CALG_SHA_256;
	}
	else if (wcscmp(pszAlgOption, L"-sha384") == 0) {
		alg = CALG_SHA_384;
	}
	else if (wcscmp(pszAlgOption, L"-sha512") == 0) {
		alg = CALG_SHA_512;
	}
	else {
		wprintf(L"wrong options, use the SHA1 algorithm.\n");
		wcscpy_s(pszAlgOption, 256, L"-sha1");
		alg = CALG_SHA1;
	}

	if (!ReadIt(&lpData, &dwReaded, pszFileName)) {
		SecureZeroMemory(pszAlgOption, sizeof(pszAlgOption));
		HeapFree(GetProcessHeap(), 0, pszAlgOption);
		pszAlgOption = NULL;
		SecureZeroMemory(pszFileName, sizeof(pszFileName));
		HeapFree(GetProcessHeap(), 0, pszFileName);
		pszFileName = NULL;
		return -1;
	}

	if (!HashIt(&lpHashData, &dwHashSize, lpData, dwReaded, alg)) {
		SecureZeroMemory(pszAlgOption, sizeof(pszAlgOption));
		HeapFree(GetProcessHeap(), 0, pszAlgOption);
		pszAlgOption = NULL;
		SecureZeroMemory(pszFileName, sizeof(pszFileName));
		HeapFree(GetProcessHeap(), 0, pszFileName);
		pszFileName = NULL;
		SecureZeroMemory(lpData, sizeof(lpData));
		HeapFree(GetProcessHeap(), 0, lpData);
		lpData = NULL;
		return -1;
	}

	if (CryptBinaryToString(lpHashData, dwHashSize, CRYPT_STRING_HEXRAW, 0, &dwBufferSize)) {
		pszBuf = (TCHAR*)HeapAlloc(GetProcessHeap(), 0, sizeof(TCHAR) * dwBufferSize + 1);
		if (CryptBinaryToString(lpHashData, dwHashSize, CRYPT_STRING_HEXRAW, pszBuf, &dwBufferSize)) {
			wprintf(L"%s | %ls\n%ls", pszAlgOption, pszFileName, pszBuf);
		}

		SecureZeroMemory(pszBuf, sizeof(pszBuf));
		HeapFree(GetProcessHeap(), 0, pszBuf);
		pszBuf = NULL;
	}

	SecureZeroMemory(pszAlgOption, sizeof(pszAlgOption));
	HeapFree(GetProcessHeap(), 0, pszAlgOption);
	pszAlgOption = NULL;
	SecureZeroMemory(pszFileName, sizeof(pszFileName));
	HeapFree(GetProcessHeap(), 0, pszFileName);
	pszFileName = NULL;
	SecureZeroMemory(lpData, sizeof(lpData));
	HeapFree(GetProcessHeap(), 0, lpData);
	lpData = NULL;
	SecureZeroMemory(lpHashData, sizeof(lpHashData));
	HeapFree(GetProcessHeap(), 0, lpHashData);
	lpHashData = NULL;

    return 0;
}

