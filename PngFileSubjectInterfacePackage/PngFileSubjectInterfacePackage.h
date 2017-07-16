#pragma once

#include "stdafx.h"
#include "pngsip.h"

#define MAX_HASH_SIZE 64
#define MAX_OID_SIZE 128

HRESULT PNGSIP_CALL DllRegisterServer();
HRESULT PNGSIP_CALL DllUnregisterServer();

typedef struct INTERNAL_SIP_INDIRECT_DATA_
{
	SIP_INDIRECT_DATA indirectData;
	BYTE digest[MAX_HASH_SIZE];
	CHAR oid[MAX_OID_SIZE];
} INTERNAL_SIP_INDIRECT_DATA;