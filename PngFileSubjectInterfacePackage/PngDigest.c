#include "stdafx.h"
#include "PngDigest.h"

#define BUFFER_SIZE 0x10000
#define PNG_HEADER_SIZE 8
#define PNG_CHUNK_HEADER_SIZE 8


HRESULT PNGSIP_CALL PngDigestChunks(HANDLE hFile, HCRYPTPROV hProv,
	CRYPT_ALGORITHM_IDENTIFIER *algorithm, DWORD* digestSize, PBYTE pBuffer)
{
	if (!hProv || !algorithm || hFile == INVALID_HANDLE_VALUE)
	{
		return E_INVALIDARG;
	}

	PCCRYPT_OID_INFO info = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, algorithm->pszObjId, CRYPT_HASH_ALG_OID_GROUP_ID);
	if (info == NULL)
	{
		return NTE_BAD_ALGID;
	}
	HRESULT result = E_UNEXPECTED;
	HCRYPTHASH hHash = { 0 };
	BOOL createHashResult = CryptCreateHash(hProv, info->Algid, 0, 0, &hHash);
	if (!createHashResult)
	{
		return HRESULT_FROM_WIN32(GetLastError());
	}
	DWORD actualHashSize = 0, actualHashSizeBuff = sizeof(DWORD);
	if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&actualHashSize, &actualHashSizeBuff, 0))
	{
		result = HRESULT_FROM_WIN32(GetLastError());;
		goto RET;
	}
	if (actualHashSize > *digestSize)
	{
		result = NTE_BUFFER_TOO_SMALL;
		goto RET;
	}

	if (!HashHeader(hFile, hHash))
	{
		result = HRESULT_FROM_WIN32(GetLastError());
		goto RET;
	}
	for(;;)
	{
		if (!HashChunk(hFile, hHash))
		{
			break;
		}
	}
	DWORD lastError = GetLastError();
	if (lastError != ERROR_SUCCESS)
	{
		result = HRESULT_FROM_WIN32(lastError);
		goto RET;
	}
	if (!CryptGetHashParam(hHash, HP_HASHVAL, pBuffer, digestSize, 0))
	{
		result = HRESULT_FROM_WIN32(lastError);
	}
	result = S_OK;
RET:
	CryptDestroyHash(hHash);
	return result;
}

BOOL HashHeader(HANDLE hFile, HCRYPTHASH hHash)
{
	DWORD bytesRead = 0;
	BYTE buffer[BUFFER_SIZE];
	if (!ReadFile(hFile, &buffer, PNG_HEADER_SIZE, &bytesRead, NULL))
	{
		return FALSE;
	}
	else if (bytesRead != PNG_HEADER_SIZE)
	{
		SetLastError(ERROR_BAD_FORMAT);
		return FALSE;
	}
	else
	{
		return CryptHashData(hHash, &buffer[0], PNG_HEADER_SIZE, 0);
	}
}

BOOL HashChunk(HANDLE hFile, HCRYPTHASH hHash)
{
	DWORD bytesRead = 0;
	BYTE buffer[BUFFER_SIZE];
	if (!ReadFile(hFile, &buffer, PNG_CHUNK_HEADER_SIZE, &bytesRead, NULL))
	{
		goto ERR;
	}
	if (bytesRead == 0)
	{
		SetLastError(0);
		return FALSE;
	}
	else if (bytesRead != PNG_CHUNK_HEADER_SIZE)
	{
		SetLastError(ERROR_BAD_FORMAT);
		goto ERR;
	}

	const unsigned int size = buffer[3] | buffer[2] << 8 | buffer[1] << 16 | buffer[0] << 24;
	const unsigned char* tag = ((char*)&buffer[4]);

	if (strcmp(tag, PNG_SIG_CHUNK_TYPE) == 0)
	{
		//Don't hash signature chunks, skip over them.
		goto SUCCESS;
	}

	if (!CryptHashData(hHash, &buffer[0], PNG_CHUNK_HEADER_SIZE, 0))
	{
		goto ERR;
	}

	for (DWORD i = 0; i < size / BUFFER_SIZE; i++)
	{
		if (!ReadFile(hFile, &buffer, BUFFER_SIZE, &bytesRead, NULL))
		{
			goto ERR;
		}
		if (!CryptHashData(hHash, &buffer[0], bytesRead, 0))
		{
			goto ERR;
		}
	}

	DWORD remainder = (size % BUFFER_SIZE) + 4; //Add 4 to include the CRC
	if (!ReadFile(hFile, &buffer, remainder, &bytesRead, NULL))
	{
		goto ERR;
	}
	if (!CryptHashData(hHash, &buffer[0], bytesRead, 0))
	{
		goto ERR;
	}

SUCCESS:
	SetLastError(0);
	return TRUE;
ERR:
	return FALSE;
}