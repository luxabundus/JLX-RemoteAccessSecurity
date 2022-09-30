#include "pch.h"
#include "RASecFirewall.h"
#include "RASecAdminDispatcher.h"
#include "RASecClientDispatcher.h"
#include "RASecVfs.h"
#include "RASecServer.h"

#pragma comment (lib, "iphlpapi")



//////////////////////////////////////////////////////////////////////
// class RASecService
//

static RASecService theService;


RASecService::RASecService() :
	m_isRegistered(false),
	m_firewall(nullptr),
	m_adminDispatcher(nullptr),
	m_clientDispatcher(nullptr)
{
}

RASecService::~RASecService()
{
}


int RASecService::run(int argc, char *argv[], char *envp[])
{
	if ((argc == 2)
		&& (stricmp(argv[1], "-uninstall") == 0))
	{
		return uninstall();
	}
	else
	{
		return WapiService::run(argc, argv, envp);
	}
}

int RASecService::uninstall()
{
	RASecFirewall firewall;
	firewall.uninstall();

	RASecAdminDispatcher admin(this);
	admin.uninstall();

	RASecClientDispatcher client(this);
	client.uninstall();

	return ERROR_SUCCESS;
}


bool RASecService::initInstance()
{
	if (!WapiService::initInstance())
	{
		return false;
	}

	if (!initIdentity())
	{
		return false;
	}

	if (!initDatabase())
	{
		return false;
	}

	m_firewall = new RASecFirewall;
	if (!m_firewall->initInstance())
	{
		return false;
	}

	m_adminDispatcher = new RASecAdminDispatcher(this);
	if (!m_adminDispatcher->initInstance())
	{
		return false;
	}

	m_clientDispatcher = new RASecClientDispatcher(this);
	if (!m_clientDispatcher->initInstance())
	{
		return false;
	}

	return true;
}

bool RASecService::initIdentity()
{
	SysRegistry regCrypto;
	if (regCrypto.open(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography"))
	{
		String registrationKey;

		m_machineId = regCrypto.getStringValue("MachineGuid");
		if (m_machineId.isEmpty())
		{
			AppLog::Error("RASecVfs::Init - Invalid Machine ID");
			return false;
		}
	}

	return true;
}

bool RASecService::initDatabase()
{
	try
	{
// #if defined(_DEBUG)
// 		RASecDbRequest::Init(RASec::ALT_SERVER_DB_FILENAME);
// #else
		RASecVfs::Init(m_machineId);
// #endif
	}
	catch (Exception &x)
	{
		AppLog::Error(x, "RASecService::initDatabase");
		return false;
	}

	RASecDbRequest dbRequest;
	DbResponse dbResponse = dbRequest.exec("select accountName from Control");
	if (dbResponse.failed())
	{
		dbResponse.logError("RASecService::initDatabase");
		return false;
	}

	m_isRegistered = !dbResponse["accountName"].isEmpty();

	return true;
}


void RASecService::exitInstance()
{
	if (m_clientDispatcher)
	{
		m_clientDispatcher->exitInstance();
		delete m_clientDispatcher;
		m_clientDispatcher = nullptr;
	}

	if (m_adminDispatcher)
	{
		m_adminDispatcher->exitInstance();
		delete m_adminDispatcher;
		m_adminDispatcher = nullptr;
	}

	if (m_firewall)
	{
		m_firewall->exitInstance();
		delete m_firewall;
		m_firewall = nullptr;
	}

	WapiService::exitInstance();
}


void RASecService::approveRegistration(const String &accountName)
{
	RASecDbRequest dbRequest;
	dbRequest["accountName"] = accountName;
	dbRequest["appVersion"] = System::GetModuleVersionNumber(false);

	DbResponse dbResponse = dbRequest.execUpdate("Control");
	dbResponse.throwIfError("RASecAdminDispatcher::approveRegistration");

	m_isRegistered = true;
}
