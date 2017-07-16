#include "stdafx.h"
#include <assert.h>
#include <stdio.h>
#include "PngFileSubjectInterfacePackage.h"
#include "PngDigest.h"

STDAPI DllRegisterServer()
{
	SIP_ADD_NEWPROVIDER provider = { 0 };
	GUID subjectGuid = GUID_PNG_SIP;
	provider.cbStruct = sizeof(SIP_ADD_NEWPROVIDER);
	provider.pgSubject = &subjectGuid;
#ifdef _WIN64
	provider.pwszDLLFileName = L"C:\\Windows\\System32\\pngsip.dll";
#else
	provider.pwszDLLFileName = L"C:\\Windows\\SYSWOW64\\pngsip.dll";
#endif
	provider.pwszGetFuncName = L"PngCryptSIPGetSignedDataMsg";
	provider.pwszPutFuncName = L"PngCryptSIPPutSignedDataMsg";
	provider.pwszCreateFuncName = L"PngCryptSIPCreateIndirectData";
	provider.pwszVerifyFuncName = L"PngCryptSIPVerifyIndirectData";
	provider.pwszRemoveFuncName = L"PngCryptSIPRemoveSignedDataMsg";
	provider.pwszIsFunctionNameFmt2 = L"PngIsFileSupportedName";
	BOOL result = CryptSIPAddProvider(&provider);
	if (result)
	{
		return S_OK;
	}
	else
	{
		return HRESULT_FROM_WIN32(GetLastError());
	}
}

STDAPI DllUnregisterServer()
{
	GUID subjectGuid = GUID_PNG_SIP;
	BOOL result = CryptSIPRemoveProvider(&subjectGuid);
	if (result)
	{
		return S_OK;
	}
	else
	{
		return HRESULT_FROM_WIN32(GetLastError());
	}
}

BOOL WINAPI PngIsFileSupportedName(WCHAR *pwszFileName, GUID *pgSubject)
{
	const WCHAR* ext = L".png";
	size_t len = wcslen(pwszFileName);
	if (len < wcslen(ext))
	{
		return FALSE;
	}
	size_t offset = len - wcslen(ext);
	assert(offset >= 0);
	const WCHAR* substring = &pwszFileName[offset];
	int result = _wcsicmp(substring, ext);
	if (result == 0)
	{
		*pgSubject = GUID_PNG_SIP;
		return TRUE;
	}
	return FALSE;
}

BOOL WINAPI PngCryptSIPGetSignedDataMsg(SIP_SUBJECTINFO *pSubjectInfo, DWORD* pdwEncodingType, DWORD dwIndex,
	DWORD *pcbSignedDataMsg, BYTE *pbSignedDataMsg)
{
	PNGSIP_ERROR_BEGIN;
	if (dwIndex != 0 ||
		pSubjectInfo == NULL ||
		pdwEncodingType == NULL)
	{
		PNGSIP_ERROR_FAIL(ERROR_INVALID_PARAMETER);
	}
	*pdwEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
	DWORD error;
	if (PngGetDigest(pSubjectInfo->hFile, pcbSignedDataMsg, pbSignedDataMsg, &error))
	{
		PNGSIP_ERROR_SUCCESS();
	}
	else
	{
		PNGSIP_ERROR_FAIL(error);
	}
	PNGSIP_ERROR_FINISH_BEGIN_CLEANUP;
	PNGSIP_ERROR_FINISH_END_CLEANUP;
}

BOOL WINAPI PngCryptSIPPutSignedDataMsg(SIP_SUBJECTINFO *pSubjectInfo, DWORD dwEncodingType, DWORD *pdwIndex,
	DWORD cbSignedDataMsg, BYTE *pbSignedDataMsg)
{
	PNGSIP_ERROR_BEGIN;
	if (*pdwIndex != 0 || pSubjectInfo == NULL
		|| pbSignedDataMsg == NULL)
	{
		PNGSIP_ERROR_FAIL(ERROR_INVALID_PARAMETER);
	}
	DWORD error;
	if (PngPutDigest(pSubjectInfo->hFile, cbSignedDataMsg, pbSignedDataMsg, &error))
	{
		PNGSIP_ERROR_SUCCESS();
	}
	else
	{
		PNGSIP_ERROR_FAIL(error);
	}
	PNGSIP_ERROR_FINISH_BEGIN_CLEANUP;
	PNGSIP_ERROR_FINISH_END_CLEANUP;
}

BOOL WINAPI PngCryptSIPCreateIndirectData(SIP_SUBJECTINFO *pSubjectInfo, DWORD *pcbIndirectData,
	SIP_INDIRECT_DATA *pIndirectData)
{
	PNGSIP_ERROR_BEGIN;
	BOOL allocdAlgorithm = FALSE, allocdHashHandle = FALSE;
	if (pSubjectInfo == NULL || pcbIndirectData == NULL)
	{
		PNGSIP_ERROR_FAIL(ERROR_INVALID_PARAMETER);
	}
	// Win32 is asking how much it needs to allocate for pIndirectData
	if (pIndirectData == NULL)
	{
		*pcbIndirectData = sizeof(INTERNAL_SIP_INDIRECT_DATA);
		PNGSIP_ERROR_SUCCESS();
	}
	if (*pcbIndirectData < sizeof(INTERNAL_SIP_INDIRECT_DATA))
	{
		PNGSIP_ERROR_FAIL(ERROR_INSUFFICIENT_BUFFER);
	}
	PCCRYPT_OID_INFO info = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, pSubjectInfo->DigestAlgorithm.pszObjId, CRYPT_HASH_ALG_OID_GROUP_ID);
	if (info == NULL)
	{
		PNGSIP_ERROR_FAIL(ERROR_NOT_SUPPORTED);
	}
	BCRYPT_ALG_HANDLE hAlgorithm = { 0 };
	if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlgorithm, info->pwszCNGAlgid, NULL, 0)))
	{
		PNGSIP_ERROR_FAIL(ERROR_NOT_SUPPORTED);
	}
	allocdAlgorithm = TRUE;
	BCRYPT_HASH_HANDLE hHashHandle = { 0 };
	if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlgorithm, &hHashHandle, NULL, 0, NULL, 0, 0)))
	{
		PNGSIP_ERROR_FAIL(ERROR_NOT_SUPPORTED);
	}
	allocdHashHandle = TRUE;
	DWORD dwHashSize = 0, cbHashSize = sizeof(DWORD);
	if (!BCRYPT_SUCCESS(BCryptGetProperty(hHashHandle, BCRYPT_HASH_LENGTH, (PUCHAR)&dwHashSize, sizeof(DWORD), &cbHashSize, 0)))
	{
		PNGSIP_ERROR_FAIL(ERROR_NOT_SUPPORTED);
	}
	size_t oidLen = strlen(pSubjectInfo->DigestAlgorithm.pszObjId) + sizeof(CHAR);
	if (dwHashSize > MAX_HASH_SIZE || oidLen > MAX_OID_SIZE)
	{
		PNGSIP_ERROR_FAIL(ERROR_INSUFFICIENT_BUFFER);
	}
	//We checked the size earlier above.
	INTERNAL_SIP_INDIRECT_DATA* pInternalIndirectData = (INTERNAL_SIP_INDIRECT_DATA*)pIndirectData;
	memset(pInternalIndirectData, 0, sizeof(INTERNAL_SIP_INDIRECT_DATA));

	DWORD error;
	if (!PngDigestChunks(pSubjectInfo->hFile, hHashHandle, dwHashSize, &pInternalIndirectData->digest[0], &error))
	{
		PNGSIP_ERROR_FAIL(error);
	}

	if (0 != strcpy_s(&pInternalIndirectData->oid[0], oidLen, pSubjectInfo->DigestAlgorithm.pszObjId))
	{
		PNGSIP_ERROR_FAIL(ERROR_INVALID_PARAMETER);
	}
	pInternalIndirectData->indirectData.Digest.cbData = dwHashSize;
	pInternalIndirectData->indirectData.Digest.pbData = &pInternalIndirectData->digest[0];
	pInternalIndirectData->indirectData.DigestAlgorithm.pszObjId = pInternalIndirectData->oid;
	pInternalIndirectData->indirectData.DigestAlgorithm.Parameters.cbData = 0;
	pInternalIndirectData->indirectData.DigestAlgorithm.Parameters.pbData = NULL;
	pInternalIndirectData->indirectData.Data.pszObjId = NULL;
	pInternalIndirectData->indirectData.Data.Value.cbData = 0;
	pInternalIndirectData->indirectData.Data.Value.pbData = NULL;
	PNGSIP_ERROR_SUCCESS();

	PNGSIP_ERROR_FINISH_BEGIN_CLEANUP;
	if (allocdAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	if (allocdHashHandle) BCryptDestroyHash(hHashHandle);
	PNGSIP_ERROR_FINISH_END_CLEANUP;
}

BOOL WINAPI PngCryptSIPVerifyIndirectData(SIP_SUBJECTINFO *pSubjectInfo, SIP_INDIRECT_DATA *pIndirectData)
{
	PNGSIP_ERROR_BEGIN;
	BOOL allocdAlgorithm = FALSE, allocdHashHandle = FALSE;
	if (pSubjectInfo == NULL || pIndirectData == NULL)
	{
		PNGSIP_ERROR_FAIL(ERROR_INVALID_PARAMETER);
	}
	PCCRYPT_OID_INFO info = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, pSubjectInfo->DigestAlgorithm.pszObjId, CRYPT_HASH_ALG_OID_GROUP_ID);
	if (info == NULL)
	{
		PNGSIP_ERROR_FAIL(ERROR_INVALID_PARAMETER);
	}
	BCRYPT_ALG_HANDLE hAlgorithm = { 0 };
	if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlgorithm, info->pwszCNGAlgid, NULL, 0)))
	{
		PNGSIP_ERROR_FAIL(ERROR_NOT_SUPPORTED);
	}
	allocdAlgorithm = TRUE;
	BCRYPT_HASH_HANDLE hHashHandle = { 0 };
	if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlgorithm, &hHashHandle, NULL, 0, NULL, 0, 0)))
	{
		PNGSIP_ERROR_FAIL(ERROR_NOT_SUPPORTED);
	}
	allocdHashHandle = TRUE;
	DWORD dwHashSize = 0, cbHashSize = sizeof(DWORD);
	if (!BCRYPT_SUCCESS(BCryptGetProperty(hHashHandle, BCRYPT_HASH_LENGTH, (PUCHAR)&dwHashSize, sizeof(DWORD), &cbHashSize, 0)))
	{
		PNGSIP_ERROR_FAIL(ERROR_NOT_SUPPORTED);
	}
	if (dwHashSize > MAX_HASH_SIZE || dwHashSize != pIndirectData->Digest.cbData)
	{
		PNGSIP_ERROR_FAIL(ERROR_INVALID_PARAMETER);
	}
	BYTE digestBuffer[MAX_HASH_SIZE];
	DWORD error;
	if (!PngDigestChunks(pSubjectInfo->hFile, hHashHandle, dwHashSize, &digestBuffer[0], &error))
	{
		PNGSIP_ERROR_FAIL(error);
	}
	if (0 == memcmp(&digestBuffer, pIndirectData->Digest.pbData, dwHashSize))
	{
		PNGSIP_ERROR_SUCCESS();
	}
	else
	{
		PNGSIP_ERROR_FAIL(TRUST_E_SUBJECT_NOT_TRUSTED);
	}

	PNGSIP_ERROR_FINISH_BEGIN_CLEANUP;
	if (allocdAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	if (allocdHashHandle) BCryptDestroyHash(hHashHandle);
	PNGSIP_ERROR_FINISH_END_CLEANUP;
}

BOOL WINAPI PngCryptSIPRemoveSignedDataMsg(SIP_SUBJECTINFO *pSubjectInfo, DWORD dwIndex)
{
	return FALSE;
}
