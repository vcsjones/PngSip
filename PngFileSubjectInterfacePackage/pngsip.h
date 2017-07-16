#pragma once

#include <initguid.h>

#define PNGSIP_CALL _stdcall

// {DA005D72-4E32-4D5E-94C5-41AECBA650FA}
DEFINE_GUID(GUID_PNG_SIP,
	0xda005d72, 0x4e32, 0x4d5e, 0x94, 0xc5, 0x41, 0xae, 0xcb, 0xa6, 0x50, 0xfa);

#define PNGSIP_ERROR_BEGIN { \
	DWORD _pngSipError; \
	BOOL  _pngSipSuccess = FALSE

#define PNGSIP_ERROR_FAIL(ERR) \
	_pngSipError = ERR; \
	_pngSipSuccess = FALSE; \
	goto PNGSIP_RET

#define PNGSIP_ERROR_FAIL_LAST_ERROR() PNGSIP_ERROR_FAIL(GetLastError())

#define PNGSIP_ERROR_SUCCESS() \
	_pngSipError = ERROR_SUCCESS; \
	_pngSipSuccess = TRUE; \
	goto PNGSIP_RET

#define PNGSIP_ERROR_FINISH_BEGIN_CLEANUP PNGSIP_RET: \
	SetLastError(_pngSipError)

#define PNGSIP_ERROR_FINISH_BEGIN_CLEANUP_TRANSFER(TO) PNGSIP_RET: \
	TO = _pngSipError

#define PNGSIP_ERROR_FINISH_END_CLEANUP return _pngSipSuccess == TRUE; }