#pragma once

#include "stdafx.h"
#include "pngsip.h"
#define PNG_SIG_CHUNK_TYPE "dsIG"
#define PNG_IEND_CHUNK_TYPE "IEND"

BOOL PNGSIP_CALL PngDigestChunks(HANDLE hFile, BCRYPT_HASH_HANDLE hHashHandle, DWORD digestSize, PBYTE pBuffer, DWORD* error);
BOOL PNGSIP_CALL PngPutDigest(HANDLE hFile, DWORD dwSignatureSize, PBYTE pSignature, DWORD* error);
BOOL PNGSIP_CALL PngGetDigest(HANDLE hFile, DWORD* pcbSignatureSize, PBYTE pSignature, DWORD *error);

BOOL PNGSIP_CALL HashHeader(HANDLE hFile, BCRYPT_HASH_HANDLE hHash, DWORD *error);
BOOL PNGSIP_CALL HashChunk(HANDLE hFile, BCRYPT_HASH_HANDLE hHash, DWORD *error);
