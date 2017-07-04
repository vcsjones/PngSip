#pragma once

#include "stdafx.h"
#include "pngsip.h"
#define PNG_SIG_CHUNK_TYPE "ceRT"

HRESULT PNGSIP_CALL PngDigestChunks(HANDLE hFile, HCRYPTPROV hProv,
	CRYPT_ALGORITHM_IDENTIFIER *algorithm, DWORD *digestSize, PBYTE pBuffer);

BOOL HashHeader(HANDLE hFile, HCRYPTHASH hHash);
BOOL HashChunk(HANDLE hFile, HCRYPTHASH hHash);