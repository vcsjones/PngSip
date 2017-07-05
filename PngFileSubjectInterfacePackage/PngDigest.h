#pragma once

#include "stdafx.h"
#include "pngsip.h"
#define PNG_SIG_CHUNK_TYPE "dsIG"

NTSTATUS PNGSIP_CALL PngDigestChunks(HANDLE hFile, BCRYPT_HASH_HANDLE hHashHandle, DWORD digestSize, PBYTE pBuffer);

BOOL PNGSIP_CALL HashHeader(HANDLE hFile, BCRYPT_HASH_HANDLE hHash, NTSTATUS *result);
BOOL PNGSIP_CALL HashChunk(HANDLE hFile, BCRYPT_HASH_HANDLE hHash, NTSTATUS *result);