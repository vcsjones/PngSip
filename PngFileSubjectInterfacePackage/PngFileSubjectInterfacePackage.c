#include "stdafx.h"
#include <assert.h>
#include <stdio.h>
#include "PngFileSubjectInterfacePackage.h"

STDAPI DllRegisterServer()
{
	SIP_ADD_NEWPROVIDER provider;
	memset(&provider, 0, sizeof(SIP_ADD_NEWPROVIDER));
	GUID subjectGuid = GUID_PNG_SIP;
	provider.cbStruct = sizeof(SIP_ADD_NEWPROVIDER);
	provider.pgSubject = &subjectGuid;
	provider.pwszDLLFileName = L"C:\\Windows\\System32\\pngsip.dll";
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

BOOL WINAPI PngCryptSIPGetSignedDataMsg(SIP_SUBJECTINFO *pSubjectInfo, DWORD pdwEncodingType, DWORD dwIndex,
	DWORD *pcbSignedDataMsg, BYTE *pbSignedDataMsg)
{
	return FALSE;
}

BOOL WINAPI PngCryptSIPPutSignedDataMsg(SIP_SUBJECTINFO *pSubjectInfo, DWORD dwEncodingType, DWORD *pdwIndex,
	DWORD cbSignedDataMsg, BYTE *pbSignedDataMsg)
{
	return FALSE;
}

BOOL WINAPI PngCryptSIPCreateIndirectData(SIP_SUBJECTINFO *pSubjectInfo, DWORD *pcbIndirectData,
	SIP_INDIRECT_DATA *pIndirectData)
{
	return FALSE;
}

BOOL WINAPI PngCryptSIPVerifyIndirectData(SIP_SUBJECTINFO *pSubjectInfo, SIP_INDIRECT_DATA *pIndirectData)
{
	return FALSE;
}

BOOL WINAPI PngCryptSIPRemoveSignedDataMsg(SIP_SUBJECTINFO *pSubjectInfo, DWORD dwIndex)
{
	return FALSE;
}
