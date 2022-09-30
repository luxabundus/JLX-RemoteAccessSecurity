#include "pch.h"
#include "SysUserManager.h"

#include <dsgetdc.h>
#include <lmcons.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <lmapibuf.h>
#pragma comment(lib, "netapi32.lib")


//////////////////////////////////////////////////////////////////////
// class SysUserManager
//

SysUserManager::SysUserManager() :
	m_pszPrimaryDC(NULL)
{
}

SysUserManager::~SysUserManager()
{
	if (m_pszPrimaryDC)
	{
		NetApiBufferFree((LPVOID)m_pszPrimaryDC);
	}
}


bool SysUserManager::createLocalGroup(const String &groupName, const String &comment)
{
	DWORD paramError;
	wstr wsGroupName(groupName);
	wstr wsComment(comment);

	LOCALGROUP_INFO_1 group;
	group.lgrpi1_name = wsGroupName;
	group.lgrpi1_comment = wsComment;

	DWORD error = NetLocalGroupAdd(m_pszPrimaryDC, 1, (LPBYTE)&group, &paramError);
	System::Error(error);
	return error == ERROR_SUCCESS;
}
