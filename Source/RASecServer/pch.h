#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS      // some String constructors will be explicit
#define _AFX_NO_MFC_CONTROLS_IN_DIALOGS         // remove support for MFC controls in dialogs
#define NO_WARN_MBCS_MFC_DEPRECATION

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN            // Exclude rarely-used stuff from Windows headers
#endif

#include <SDKDDKVer.h>

#include <afx.h>
#include <afxwin.h>         // MFC core and standard components

#include <atlcomcli.h>
#include <netfw.h>

#include <RASecCore/Common.h>

#include "SysUserManager.h"

#include "RASecFirewall.h"
#include "RASecDispatcher.h"


namespace RASec
{
	extern const String SENTINEL_ADDRESS;
	extern const String SENTINEL_ACCOUNT_ID;

	extern const String CLIENT_RULE_GROUPING;
	extern const String CLIENT_RULE_NAME;

	extern const String CLIENT_USER_GROUP;
	extern const String CLIENT_ACCESS_LIST;

	extern const String ADMIN_USER_GROUP;
	extern const String ADMIN_ACCESS_LIST;

	extern const String SERVER_DB_FILENAME;		// encrypted
	extern const String ALT_SERVER_DB_FILENAME; // unencrypted
}