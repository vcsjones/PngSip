#include "stdafx.h"
#include "PngDigest.h"
#include "crc.h"
#include <intrin.h>

#define BUFFER_SIZE 0x10000
#define PNG_HEADER_SIZE 8
#define PNG_CHUNK_HEADER_SIZE 8




NTSTATUS PNGSIP_CALL PngDigestChunks(HANDLE hFile, BCRYPT_HASH_HANDLE hHashHandle, DWORD digestSize, PBYTE pBuffer)
{
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return STATUS_INVALID_PARAMETER;
	}
	HRESULT result;

	if (!HashHeader(hFile, hHashHandle, &result))
	{
		goto RET;
	}
	for(;;)
	{
		if (!HashChunk(hFile, hHashHandle, &result))
		{
			break;
		}
	}
	if (!BCRYPT_SUCCESS(result))
	{
		goto RET;
	}
	if (!BCRYPT_SUCCESS(result = BCryptFinishHash(hHashHandle, pBuffer, digestSize, 0)))
	{
		goto RET;
	}
	result = 0;
RET:
	return result;
}

BOOL PNGSIP_CALL HashHeader(HANDLE hFile, BCRYPT_HASH_HANDLE hHash, NTSTATUS *result)
{
	DWORD bytesRead = 0;
	BYTE buffer[BUFFER_SIZE];
	if (!ReadFile(hFile, &buffer, PNG_HEADER_SIZE, &bytesRead, NULL))
	{
		*result = GetLastError();
		return FALSE;
	}
	else if (bytesRead != PNG_HEADER_SIZE)
	{
		*result = STATUS_INVALID_PARAMETER;
		return FALSE;
	}
	else
	{
		if (!BCRYPT_SUCCESS(*result = BCryptHashData(hHash, &buffer[0], PNG_HEADER_SIZE, 0)))
		{
			return FALSE;
		}
		*result = ERROR_SUCCESS;
		return TRUE;
	}
}

BOOL PNGSIP_CALL HashChunk(HANDLE hFile, BCRYPT_HASH_HANDLE hHash, NTSTATUS *result)
{
	DWORD bytesRead = 0;
	BYTE buffer[BUFFER_SIZE];
	if (!ReadFile(hFile, &buffer, PNG_CHUNK_HEADER_SIZE, &bytesRead, NULL))
	{
		goto ERR;
	}
	if (bytesRead == 0)
	{
		SetLastError(ERROR_SUCCESS);
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
	if (!BCRYPT_SUCCESS(*result = BCryptHashData(hHash, &buffer[0], PNG_CHUNK_HEADER_SIZE, 0)))
	{
		goto ERR;
	}

	for (DWORD i = 0; i < size / BUFFER_SIZE; i++)
	{
		if (!ReadFile(hFile, &buffer, BUFFER_SIZE, &bytesRead, NULL))
		{
			goto ERR;
		}
		if (!BCRYPT_SUCCESS(*result = BCryptHashData(hHash, &buffer[0], bytesRead, 0)))
		{
			goto ERR;
		}
	}

	DWORD remainder = (size % BUFFER_SIZE) + 4; //Add 4 to include the CRC
	if (!ReadFile(hFile, &buffer, remainder, &bytesRead, NULL))
	{
		goto ERR;
	}
	if (!BCRYPT_SUCCESS(*result = BCryptHashData(hHash, &buffer[0], bytesRead, 0)))
	{
		goto ERR;
	}

SUCCESS:
	*result = ERROR_SUCCESS;
	return TRUE;
ERR:
	return FALSE;
}

BOOL PNGSIP_CALL PngPutDigest(HANDLE hFile, DWORD dwSignatureSize, PBYTE pSignature, NTSTATUS *result)
{
	DWORD status;
	status = SetFilePointer(hFile, -12, NULL, FILE_END);
	if (status == INVALID_SET_FILE_POINTER)
	{
		*result = GetLastError();
		return FALSE;
	}

	DWORD dwBytesWritten;
	DWORD dwSignatureSizeBigEndian = _byteswap_ulong(dwSignatureSize);

	if (!WriteFile(hFile, &dwSignatureSizeBigEndian, sizeof(DWORD), &dwBytesWritten, NULL))
	{
		*result = GetLastError();
		return FALSE;
	}
	if (!WriteFile(hFile, PNG_SIG_CHUNK_TYPE, 4, &dwBytesWritten, NULL))
	{
		*result = GetLastError();
		return FALSE;
	}
	if (!WriteFile(hFile, pSignature, dwSignatureSize, &dwBytesWritten, NULL))
	{
		*result = GetLastError();
		return FALSE;
	}
	unsigned long checksum = crc_init();
	checksum = update_crc(checksum, PNG_SIG_CHUNK_TYPE, 4);
	checksum = update_crc(checksum, pSignature, dwSignatureSize);
	checksum = crc_finish(checksum);
	checksum = _byteswap_ulong(checksum);
	if (!WriteFile(hFile, &checksum, sizeof(DWORD), &dwBytesWritten, NULL))
	{
		*result = GetLastError();
		return FALSE;
	}

	BYTE iendChunk[12] = { 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82 };
	if (!WriteFile(hFile, &iendChunk, 12, &dwBytesWritten, NULL))
	{
		*result = GetLastError();
		return FALSE;
	}
	*result = ERROR_SUCCESS;
	return TRUE;
}