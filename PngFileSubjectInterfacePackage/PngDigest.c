#include "stdafx.h"
#include "PngDigest.h"
#include "crc.h"
#include <intrin.h>

#define BUFFER_SIZE 0x10000
#define PNG_HEADER_SIZE 8
#define PNG_CHUNK_HEADER_SIZE 8




BOOL PNGSIP_CALL PngDigestChunks(HANDLE hFile, BCRYPT_HASH_HANDLE hHashHandle,
	DWORD digestSize, PBYTE pBuffer, DWORD* error)
{
	PNGSIP_ERROR_BEGIN;
	if (hFile == INVALID_HANDLE_VALUE)
	{
		PNGSIP_ERROR_FAIL(ERROR_INVALID_PARAMETER);
	}
	if (SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
		PNGSIP_ERROR_FAIL(ERROR_BAD_FORMAT);
	}
	DWORD result;
	if (!HashHeader(hFile, hHashHandle, &result))
	{
		PNGSIP_ERROR_FAIL(result);
	}
	for(;;)
	{
		if (!HashChunk(hFile, hHashHandle, &result))
		{
			break;
		}
	}
	if (result != ERROR_SUCCESS)
	{
		PNGSIP_ERROR_FAIL(result);
	}
	if (!BCRYPT_SUCCESS(BCryptFinishHash(hHashHandle, pBuffer, digestSize, 0)))
	{
		PNGSIP_ERROR_FAIL(ERROR_INVALID_OPERATION);
	}
	PNGSIP_ERROR_SUCCESS();

	PNGSIP_ERROR_FINISH_BEGIN_CLEANUP_TRANSFER(*error);
	PNGSIP_ERROR_FINISH_END_CLEANUP;
}

BOOL PNGSIP_CALL HashHeader(HANDLE hFile, BCRYPT_HASH_HANDLE hHash, DWORD *error)
{
	PNGSIP_ERROR_BEGIN;
	DWORD bytesRead = 0;
	BYTE buffer[BUFFER_SIZE];
	if (!ReadFile(hFile, &buffer, PNG_HEADER_SIZE, &bytesRead, NULL))
	{
		PNGSIP_ERROR_FAIL_LAST_ERROR();
	}
	if (bytesRead != PNG_HEADER_SIZE)
	{
		PNGSIP_ERROR_FAIL(STATUS_INVALID_PARAMETER);
	}

	if (!BCRYPT_SUCCESS(BCryptHashData(hHash, &buffer[0], PNG_HEADER_SIZE, 0)))
	{
		PNGSIP_ERROR_FAIL(ERROR_INVALID_OPERATION);
	}
	PNGSIP_ERROR_SUCCESS();
	
	PNGSIP_ERROR_FINISH_BEGIN_CLEANUP_TRANSFER(*error);
	PNGSIP_ERROR_FINISH_END_CLEANUP;
}

BOOL PNGSIP_CALL HashChunk(HANDLE hFile, BCRYPT_HASH_HANDLE hHash, DWORD *error)
{
	PNGSIP_ERROR_BEGIN;
	DWORD bytesRead = 0;
	BYTE buffer[BUFFER_SIZE];
	if (!ReadFile(hFile, &buffer, PNG_CHUNK_HEADER_SIZE, &bytesRead, NULL))
	{
		PNGSIP_ERROR_FAIL_LAST_ERROR();
	}
	if (bytesRead == 0)
	{
		// We "fail" here even though everything was successful.
		PNGSIP_ERROR_FAIL(ERROR_SUCCESS);
	}
	if (bytesRead != PNG_CHUNK_HEADER_SIZE)
	{
		PNGSIP_ERROR_FAIL(ERROR_BAD_FORMAT);
	}

	const unsigned int size = buffer[3] | buffer[2] << 8 | buffer[1] << 16 | buffer[0] << 24;
	const unsigned char* tag = ((char*)&buffer[4]);

	if (0 == memcmp(tag, PNG_SIG_CHUNK_TYPE, 4))
	{
		if (INVALID_SET_FILE_POINTER == SetFilePointer(hFile, size + 4, NULL, FILE_CURRENT))
		{
			PNGSIP_ERROR_FAIL(ERROR_INVALID_OPERATION);
		}
		PNGSIP_ERROR_SUCCESS();
	}
	if (!BCRYPT_SUCCESS(BCryptHashData(hHash, &buffer[0], PNG_CHUNK_HEADER_SIZE, 0)))
	{
		PNGSIP_ERROR_FAIL(ERROR_INVALID_OPERATION);
	}

	for (DWORD i = 0; i < size / BUFFER_SIZE; i++)
	{
		if (!ReadFile(hFile, &buffer, BUFFER_SIZE, &bytesRead, NULL))
		{
			PNGSIP_ERROR_FAIL_LAST_ERROR();
		}
		if (!BCRYPT_SUCCESS(BCryptHashData(hHash, &buffer[0], bytesRead, 0)))
		{
			PNGSIP_ERROR_FAIL(ERROR_INVALID_OPERATION);
		}
	}

	DWORD remainder = (size % BUFFER_SIZE) + 4; //Add 4 to include the CRC
	if (!ReadFile(hFile, &buffer, remainder, &bytesRead, NULL))
	{
		PNGSIP_ERROR_FAIL_LAST_ERROR();
	}
	if (!BCRYPT_SUCCESS(BCryptHashData(hHash, &buffer[0], bytesRead, 0)))
	{
		PNGSIP_ERROR_FAIL(ERROR_INVALID_OPERATION);
	}
	PNGSIP_ERROR_SUCCESS();

	PNGSIP_ERROR_FINISH_BEGIN_CLEANUP_TRANSFER(*error);
	PNGSIP_ERROR_FINISH_END_CLEANUP;
}

BOOL PNGSIP_CALL PngPutDigest(HANDLE hFile, DWORD dwSignatureSize, PBYTE pSignature, DWORD* error)
{
	PNGSIP_ERROR_BEGIN;
	if (SetFilePointer(hFile, -12, NULL, FILE_END) == INVALID_SET_FILE_POINTER)
	{
		PNGSIP_ERROR_FAIL(ERROR_BAD_FORMAT);
	}

	DWORD dwBytesWritten;
	DWORD dwSignatureSizeBigEndian = _byteswap_ulong(dwSignatureSize);

	if (!WriteFile(hFile, &dwSignatureSizeBigEndian, sizeof(DWORD), &dwBytesWritten, NULL))
	{
		PNGSIP_ERROR_FAIL_LAST_ERROR();
	}
	if (!WriteFile(hFile, PNG_SIG_CHUNK_TYPE, 4, &dwBytesWritten, NULL))
	{
		PNGSIP_ERROR_FAIL_LAST_ERROR();
	}
	if (!WriteFile(hFile, pSignature, dwSignatureSize, &dwBytesWritten, NULL))
	{
		PNGSIP_ERROR_FAIL_LAST_ERROR();
	}
	unsigned long checksum = crc_init();
	checksum = update_crc(checksum, PNG_SIG_CHUNK_TYPE, 4);
	checksum = update_crc(checksum, pSignature, dwSignatureSize);
	checksum = crc_finish(checksum);
	checksum = _byteswap_ulong(checksum);
	if (!WriteFile(hFile, &checksum, sizeof(DWORD), &dwBytesWritten, NULL))
	{
		PNGSIP_ERROR_FAIL_LAST_ERROR();
	}

	const BYTE iendChunk[12] = { 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82 };
	if (!WriteFile(hFile, &iendChunk, 12, &dwBytesWritten, NULL))
	{
		PNGSIP_ERROR_FAIL_LAST_ERROR();
	}
	PNGSIP_ERROR_SUCCESS();

	PNGSIP_ERROR_FINISH_BEGIN_CLEANUP_TRANSFER(*error);
	PNGSIP_ERROR_FINISH_END_CLEANUP;
}

BOOL PNGSIP_CALL PngGetDigest(HANDLE hFile, DWORD* pcbSignatureSize, PBYTE pSignature, DWORD *error)
{
	PNGSIP_ERROR_BEGIN;
	if (SetFilePointer(hFile, PNG_HEADER_SIZE, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
		PNGSIP_ERROR_FAIL_LAST_ERROR();
	}
	DWORD bytesRead = 0, totalRead = 0;
	BYTE buffer[BUFFER_SIZE];
	for (;;)
	{
		if (!ReadFile(hFile, &buffer[0], PNG_CHUNK_HEADER_SIZE, &bytesRead, NULL))
		{
			PNGSIP_ERROR_FAIL_LAST_ERROR();
		}
		if (bytesRead < PNG_CHUNK_HEADER_SIZE)
		{
			PNGSIP_ERROR_FAIL(ERROR_BAD_FORMAT);
		}
		const unsigned int size = buffer[3] | buffer[2] << 8 | buffer[1] << 16 | buffer[0] << 24;
		const unsigned char* tag = ((char*)&buffer[4]);
		if (memcmp(tag, PNG_SIG_CHUNK_TYPE, 4) != 0)
		{
			if (SetFilePointer(hFile, size + 4, NULL, FILE_CURRENT) == INVALID_SET_FILE_POINTER)
			{
				PNGSIP_ERROR_FAIL(ERROR_BAD_FORMAT);
			}
			continue;
		}
		// Win32 is asking how big of a buffer it needs. Set the size and exit.
		if (pSignature == NULL)
		{
			*pcbSignatureSize = size;
			PNGSIP_ERROR_SUCCESS();
		}
		// It supplied a buffer, but it wasn't big enough.
		else if (*pcbSignatureSize < size)
		{
			PNGSIP_ERROR_FAIL(ERROR_INSUFFICIENT_BUFFER);
		}
		for (DWORD i = 0; i < size / BUFFER_SIZE; i++)
		{
			if (!ReadFile(hFile, &buffer, BUFFER_SIZE, &bytesRead, NULL))
			{
				PNGSIP_ERROR_FAIL_LAST_ERROR();
			}
			memcpy(pSignature + totalRead, &buffer[0], bytesRead);
			totalRead += bytesRead;
		}
		DWORD remainder = size % BUFFER_SIZE;
		if (remainder > 0)
		{
			if (!ReadFile(hFile, &buffer, remainder, &bytesRead, NULL))
			{
				PNGSIP_ERROR_FAIL_LAST_ERROR();
			}
			memcpy(pSignature + totalRead, &buffer[0], bytesRead);
			totalRead += bytesRead;
		}
		*pcbSignatureSize = totalRead;
		PNGSIP_ERROR_SUCCESS();
	}
	PNGSIP_ERROR_FAIL(TRUST_E_SUBJECT_NOT_TRUSTED);

	PNGSIP_ERROR_FINISH_BEGIN_CLEANUP_TRANSFER(*error);
	PNGSIP_ERROR_FINISH_END_CLEANUP;
}