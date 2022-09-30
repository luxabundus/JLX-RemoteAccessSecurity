#include "pch.h"
#include "RASecClientDispatcher.h"

#include <JlxCore/TcpStream.h>
#include <JlxCore/TlsProtocol.h>

#include <RASecCore/RASecStream.h>


//////////////////////////////////////////////////////////////////////
// class RASecClientDispatcher
//

BEGIN_HTTP_MAP(RASecClientDispatcher, RASecDispatcher)
	ON_HTTP_REQUEST("PUT", "/rasec/client/access", onRegisterClientAccess)
	ON_HTTP_REQUEST("DELETE", "/rasec/client/access", onUnregisterClientAccess)
END_HTTP_MAP()


RASecClientDispatcher::RASecClientDispatcher(RASecService *service) :
	RASecDispatcher(service)
{

}


bool RASecClientDispatcher::initInstance()
{
	// Create the admin user group.
	SysUserManager userMgr;
	if (!userMgr.createLocalGroup(RASec::CLIENT_USER_GROUP)
		&& (System::Error() != ERROR_ALIAS_EXISTS))
	{
		AppLog::LastError("RASecClientDispatcher::initInstance@CreateClientUser");
		return false;
	}

	// Detect TLS or RASec
	String protocol;

	SysRegistry regCertificates;
	if (regCertificates.open(HKEY_LOCAL_MACHINE, RASec::ROOT_KEY_PATH + "\\Server\\Certificates"))
	{
		protocol = "tls";

		regCertificates.forEachStringValue(
			[](const char *containerPath, const char *) mutable
			{
				if (!TlsProtocol::OpenSystemContainer(containerPath))
				{
					AppLog::LastError("RASecClientDispatcher::initCertificates@OpenCustom(%s)", containerPath);
				}
				return true;
			}
		);
	}
	else
	{
		if (!RASecProtocol::Initialize())
		{
			return false;
		}

		protocol = "rasec";
	}

	// Start the external listener, i.e., accessed directly from Internet.
	long port = RASec::DEFAULT_CLIENT_PORT;
	long isSecure = true;
	String address = "all";

	SysRegistry regSettings;
	if (regSettings.open(HKEY_LOCAL_MACHINE, RASec::ROOT_KEY_PATH + "\\Server\\Listener", true))
	{
		regSettings.getValue("Port", port);
		regSettings.getValue("Secure", isSecure);
		regSettings.getValue("Address", address);
	}

	StringArray addresses;
	if (address.compareNoCase("none") != 0)
	{
		if (address.compareNoCase("all") == 0)
		{
			TcpProtocol::EnumerateLocalAddresses(addresses, true);
		}
		else
		{
			String part;
			size_t start = 0;
			while (!(part = address.tokenize(",", start)).trim().isEmpty())
			{
				addresses.add(part);
			}
		}

		for (auto &&address : addresses)
		{
			startListener(StrPrintF("%s:%s:%d", protocol, address, port));
		}
	}

	return true;
}


bool RASecClientDispatcher::uninstall()
{
	return true;
}


void RASecClientDispatcher::authenticateUser(HttpContext &context, String &accountId, String &deviceId)
{
	String password;
	if (!context.request.getBasicAuth(accountId, password))
	{
		accountId = context.request.queryParams["username"];
		password = context.request.queryParams["password"];
	}

	deviceId = context.request.queryParams["computer"];

	if (accountId.isEmpty() || deviceId.isEmpty() || password.isEmpty())
	{
		throw HttpException(HttpStatus::BAD_REQUEST, "invalid parameters");
	}

	if (!System::AuthenticateUser(accountId, password, nullptr, RASec::CLIENT_ACCESS_LIST))
	{
		throw HttpException(HttpStatus::DENIED);
	}
}


void RASecClientDispatcher::onRegisterClientAccess(HttpContext &context)
{
	String accountId, deviceId;
	authenticateUser(context, accountId, deviceId);

#if defined(NDEBUG)
	String ipAddress = context.request.getForwardedFor();
#else
	String ipAddress = context.request.queryParams["ip"];
	if (ipAddress.isEmpty())
	{
		ipAddress = context.request.getForwardedFor();
	}
#endif

	if (ipAddress.isEmpty())
	{
		ipAddress = context.getStream()->getRemoteAddress();
		if (!ipAddress.isEmpty())
		{
			ipAddress.splitFront(":", nullptr, &ipAddress);
			ipAddress.splitFront(":", &ipAddress, nullptr);
		}
	}

	if (ipAddress.isEmpty())
	{
		throw HttpException(HttpStatus::BAD_REQUEST);
	}

	RASecDbRequest dbRequest;
	dbRequest["accountId"] = accountId;
	dbRequest["deviceId"] = deviceId;
	dbRequest["ipAddress"] = ipAddress;

	SyncSharedLock lock(m_firewall->getUpdateMutex());

	DbResponse dbResponse = dbRequest.execUpdate(
		"RasAccess",
		"where accountId = '@accountId' and deviceId = '@deviceId'");
	dbResponse.throwIfError("RASecClientDispatcher::onRegisterClientAccess@Update");

	if (dbResponse.getRowsAffected() == 0)
	{
		dbRequest["accountId"] = accountId;
		dbRequest["deviceId"] = deviceId;
		dbRequest["ipAddress"] = ipAddress;

		dbResponse = dbRequest.execInsert("RasAccess");
		dbResponse.throwIfError("RASecClientDispatcher::onRegisterClientAccess@Insert");
	}

	m_firewall->updateAccess();
}


void RASecClientDispatcher::onUnregisterClientAccess(HttpContext &context)
{
	String accountId, deviceId;
	authenticateUser(context, accountId, deviceId);

	RASecDbRequest dbRequest;
	dbRequest["accountId"] = accountId;
	dbRequest["deviceId"] = deviceId;

	SyncSharedLock lock(m_firewall->getUpdateMutex());

	DbResponse dbResponse = dbRequest.execDelete(
		"RasAccess",
		"where accountId = '@accountId' and deviceId = '@deviceId'");
	dbResponse.throwIfError("RASecClientDispatcher::onUnregisterClientAccess@Delete");

	m_firewall->updateAccess();
}
