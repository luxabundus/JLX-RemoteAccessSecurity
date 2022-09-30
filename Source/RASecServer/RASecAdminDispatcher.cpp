#include "pch.h"
#include "RASecFirewall.h"
#include "RASecServer.h"
#include "RASecAdminDispatcher.h"


//////////////////////////////////////////////////////////////////////
// class RASecAdminDispatcher
//

BEGIN_HTTP_MAP(RASecAdminDispatcher, HttpDispatcher)
	ON_HTTP_REQUEST("HELP", "/", onQueryHelp)
	ON_HTTP_REQUEST("LIST", "/", onListFilters)
	ON_HTTP_REQUEST("ALLOW", "/", onAllowRule)
	ON_HTTP_REQUEST("BLOCK", "/", onBlockRule)
	ON_HTTP_REQUEST("DROP", "/", onDropRule)
	ON_HTTP_REQUEST("SYNC", "/", onSyncRules)
	ON_HTTP_REQUEST("REGISTER", "/", onRegisterServer)
END_HTTP_MAP()


RASecAdminDispatcher::RASecAdminDispatcher(RASecService *service) :
	RASecDispatcher(service)
{
}

RASecAdminDispatcher::~RASecAdminDispatcher()
{
}


bool RASecAdminDispatcher::initInstance()
{
	// Create the admin user group.
	SysUserManager userMgr;
	if (!userMgr.createLocalGroup("RASecAdmin")
		&& (System::Error() != ERROR_ALIAS_EXISTS))
	{
		AppLog::LastError("RASecAdminDispatcher::initInstance@CreateAdminUser");
		return false;
	}

	// Start the listener.
	return startListener("pipe:localhost:rasec.server.admin");
}


bool RASecAdminDispatcher::uninstall()
{
	return true;
}


void RASecAdminDispatcher::authenticateUser(HttpContext &context)
{
	if (!m_service->isRegistered())
	{
		throw HttpException(HttpStatus::CONFLICT, "unregistered installation");
	}

// 	String username, password;
// 	if (!context.request.getBasicAuth(username, password))
// 	{
// 		context.response.throwBasicAuth("");
// 	}
// 	if (!System::AuthenticateUser(username, password, nullptr, RASec::ADMIN_ACCESS_LIST))
// 	{
// 		throw HttpException(HttpStatus::DENIED);
// 	}
}


void RASecAdminDispatcher::getFilterParams(HttpContext &context, StrPropertyMap &params)
{
	String accountId = context.request.queryParams["user"];
	if (accountId.compareNoCase(RASec::SENTINEL_ACCOUNT_ID) == 0)
	{
		throw HttpException(HttpStatus::BAD_REQUEST);
	}

	String ruleName = context.request.queryParams["rule"];
	String groupName = context.request.queryParams["group"];
	if (ruleName.isEmpty() && groupName.isEmpty())
	{
		throw HttpException(HttpStatus::BAD_REQUEST);
	}

	if (!accountId.isEmpty())
	{
		params["accountId"] = accountId;
	}
	if (!ruleName.isEmpty())
	{
		params["ruleName"] = ruleName;
	}
	if (!groupName.isEmpty())
	{
		params["groupName"] = groupName;
	}
}


void RASecAdminDispatcher::addSentinel(RASecDbRequest &dbRequest, const StrPropertyMap &params, bool force)
{
	DbResponse dbResponse;

	String forced = force ? "1" : "0";

	// Add sentinel filter.
	dbRequest.params = params;
	dbRequest["accountId"] = RASec::SENTINEL_ACCOUNT_ID;
	dbRequest["forced"] = forced;

	dbResponse = dbRequest.execInsert("RasFilter");

	if (dbResponse.isDuplicateRow())
	{
		// If already exists but we're forcing its application,
		// update the sentinel filter.
		if (force)
		{
			dbRequest.params = params;
			dbRequest["accountId"] = RASec::SENTINEL_ACCOUNT_ID;
			dbRequest["forced"] = forced;
			dbResponse = dbRequest.execUpdate(
				"RasFilter",
				"where accountId = '@accountId' "
					"and ifnull(ruleName, '') = '@ruleName' "
					"and ifnull(groupName, '') = '@groupName' ");

			dbResponse.throwIfError("RASecAdminDispatcher::addSentinel@UpdateForcedSentinelFilter");
		}
	}
	else
	{
		dbResponse.throwIfError("RASecAdminDispatcher::addSentinel@InsertSentinelFilter");
	}
}



void RASecAdminDispatcher::onQueryHelp(HttpContext &context)
{
	String help;
	System::GetModuleResource("TXT", "HELP", help);
	context.response.setContent(help);
}


void RASecAdminDispatcher::onListFilters(HttpContext &context)
{
	authenticateUser(context);

	MemStreamPtr result = new MemStream;

	RASecDbRequest dbRequest;
	DbResponse dbResponse;

	dbResponse = dbRequest.exec(
		"select "
			"accountId as 'user', "
			"ruleName as 'rule', "
			"groupName as 'group' "
		"from RasFilter "
		"where accountId <> '<sentinel>' "
		"order by accountId, groupName, ruleName ");
	dbResponse.throwIfError("RASecAdminDispatcher::onListFilters@SelectRules");

	while (dbResponse.fetchNext())
	{
		result->write("\r\n");

		if (!dbResponse["user"].isEmpty())
		{
			result->write(StrPrintF("user=\"%s\"", dbResponse["user"]));
		}
		if (!dbResponse["rule"].isEmpty())
		{
			result->write(StrPrintF("rule=\"%s\"", dbResponse["rule"]));
		}
		if (!dbResponse["group"].isEmpty())
		{
			result->write(StrPrintF("group=\"%s\"", dbResponse["group"]));
		}
	}

	context.response.setContent(result);
}


void RASecAdminDispatcher::onAllowRule(HttpContext &context)
{
	authenticateUser(context);

	StrPropertyMap params;
	getFilterParams(context, params);

	bool force = context.request.queryParams.find("force");

	RASecDbRequest dbRequest;
	DbResponse dbResponse;
	SyncSharedLock lock(m_firewall->getUpdateMutex());

	dbRequest.beginTransaction().throwIfError("RASecAdminDispatcher::onAllowRule@BeginTransaction");

	addSentinel(dbRequest, params, force);

	// Add user filter.
	dbRequest.params = params;
	dbResponse = dbRequest.execInsert("RasFilter");
	if (!dbResponse.isDuplicateRow())
	{
		dbResponse.throwIfError("RASecAdminDispatcher::onAllowRule@InsertUserFilter");
	}

	dbRequest.commitTransaction().throwIfError("RASecAdminDispatcher::onAllowRule@CommitTransaction");

	m_firewall->updateAccess();
}


void RASecAdminDispatcher::onBlockRule(HttpContext &context)
{
	authenticateUser(context);

	StrPropertyMap params;
	getFilterParams(context, params);

	bool force = context.request.queryParams.find("force");

	RASecDbRequest dbRequest;
	DbResponse dbResponse;
	SyncSharedLock lock(m_firewall->getUpdateMutex());

	dbRequest.beginTransaction().throwIfError("RASecAdminDispatcher::onBlockRule@BeginTransaction");

	addSentinel(dbRequest, params, force);

	// Delete all non-sentinel filters.
	dbRequest["accountId"] = params["accountId"];
	dbRequest["ruleName"] = params["ruleName"];
	dbRequest["groupName"] = params["groupName"];

	dbResponse = dbRequest.execDelete(
		"RasFilter",
		"where ifnull(accountId, '') = '@accountId' "
			"and ifnull(ruleName, '') = '@ruleName' "
			"and ifnull(groupName, '') = '@groupName'");
	dbResponse.throwIfError("RASecAdminDispatcher::onBlockRule@DeleteRule");

	dbRequest.commitTransaction().throwIfError("RASecAdminDispatcher::onBlockRule@CommitTransaction");

	m_firewall->updateAccess();
}


void RASecAdminDispatcher::onDropRule(HttpContext &context)
{
	authenticateUser(context);

	StrPropertyMap params;
	getFilterParams(context, params);

	RASecDbRequest dbRequest;
	DbResponse dbResponse;
	SyncSharedLock lock(m_firewall->getUpdateMutex());

	dbRequest.beginTransaction().throwIfError("RASecAdminDispatcher::onDropRule@BeginTransaction");

	// Update filters.
	dbRequest.params = params;
	dbResponse = dbRequest.exec(
		"update RasFilter "
		"set unloaded = 1 "
		"where ifnull(ruleName, '') = '@ruleName' "
			"and ifnull(groupName, '') = '@groupName' ");
	dbResponse.throwIfError("RASecAdminDispatcher::onDropRule@UpdateUnloadedFilters");
	if (dbResponse.getRowsAffected() == 0)
	{
		throw HttpException(HttpStatus::NOT_FOUND);
	}

	// First, update restore entries.
	StringArray conditions;
	if (!params["ruleName"].isEmpty())
	{
		conditions.add(StrPrintF("ruleName = '%s'", RASecDbRequest::FormatEscape(params["ruleName"])));
	}
	if (!params["groupName"].isEmpty())
	{
		conditions.add(StrPrintF("groupName = '%s'", RASecDbRequest::FormatEscape(params["groupName"])));
	}

	dbRequest["conditions"] = StrJoin(conditions, " and ");
	dbResponse = dbRequest.exec(
		"update RasRestore "
		"set unloaded = 1 "
		"where @#conditions ");
	dbResponse.throwIfError("RASecAdminDispatcher::onDropRule@UpdateUnloadedRestores");

	dbRequest.commitTransaction().throwIfError("RASecAdminDispatcher::onDropRule@CommitTransaction");

	m_firewall->updateAccess();
}


void RASecAdminDispatcher::onSyncRules(HttpContext &context)
{
	authenticateUser(context);

	m_firewall->updateAccess();
}


void RASecAdminDispatcher::onRegisterServer(HttpContext &context)
{
	String accountName = context.request.queryParams["account"];
	if (accountName.isEmpty())
	{
		throw HttpException(HttpStatus::BAD_REQUEST);
	}

	String registrationKey = m_service->getRegistrationKey();
	String registrationVersion = System::GetModuleVersionNumber(false);

	String url = StrPrintF(
		"%s/@/server/registration?account=%s&key=%s&version=%s&device=%s",
		RASec::HOME_URL,
		Http::EncodeForm(accountName),
		registrationKey,
		registrationVersion,
		Http::EncodeForm(System::GetComputerName()));

	//
	HttpClient http;
	if (http.send("POST", url).succeeded())
	{
		m_service->approveRegistration(accountName);
		context.response.setContent("installation successfully registered");
	}
	else if (http.getResponseCode() == 0)
	{
		throw HttpException(HttpStatus::SERVICE_UNAVAIL, "cannot connect to registration server");
	}
	else
	{
		throw HttpException(http.response);
	}
}