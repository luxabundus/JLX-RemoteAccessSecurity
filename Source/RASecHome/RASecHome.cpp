#include "pch.h"
#include "RASecHome.h"


//////////////////////////////////////////////////////////////////////
// class RASecHomeService
//

BEGIN_HTTP_MAP(RASecHomeService, WapiService)
	ON_HTTP_REQUEST("POST", "/@/server/registration", onRegisterServer)
	ON_HTTP_REQUEST("POST", "/@/server/validation", onValidateServer)

	ON_HTTP_REQUEST("GET", "/@/account", onGetAccount)
	ON_HTTP_REQUEST("PUT", "/@/account", onCreateAccount)
END_HTTP_MAP()


RASecHomeService RASecHome;


RASecHomeService::RASecHomeService() :
	WapiService("RASec Home Service", "Software\\Joel Luzadas Inc\\Remote Access Security\\Home")
{
}


bool RASecHomeService::initInstance()
{
	if (!WapiService::initInstance())
	{
		return false;
	}

	try
	{
		RASecDbRequest::Init("rasechome.db");
	}
	catch (Exception &x)
	{
		AppLog::Error(x, "RASecHomeService::initInstance@InitDb");
		return false;
	}

	if (!startListener("pipe:localhost:rasec.home"))
	{
		return false;
	}

	return true;
}


String RASecHomeService::validateAccountName(const String &accountName)
{
	if (accountName.isEmpty())
	{
		throw HttpException(HttpStatus::BAD_REQUEST);
	}

	RASecDbRequest dbRequest;
	dbRequest["accountName"] = accountName;

	DbResponse dbResponse = dbRequest.exec(
		"select a.accountId, a.accountStatus "
		"from RasAccount a "
		"where a.accountName = '@accountName' ");
	dbResponse.throwIfError("RASecHomeService::onRegisterServer@QueryAccountName");

	String status = dbResponse["accountStatus"];
	if (status.isEmpty())
	{
		throw HttpException(HttpStatus::NOT_FOUND, "unknown account name");
	}
	else if (status != "active")
	{
		throw HttpException(HttpStatus::DENIED, "inactive account");
	}

	return dbResponse["accountId"];
}


void RASecHomeService::onRegisterServer(HttpContext &context)
{
	RASecDbRequest dbRequest;
	DbResponse dbResponse;

	String accountName = context.request.queryParams["account"];
	String accountId = validateAccountName(accountName);
	String deviceName = context.request.queryParams["device"];
	String registrationKey = context.request.queryParams["key"];
	String registrationVersion = context.request.queryParams["version"];

	String ipAddress = context.request.getForwardedFor();
	if (!ipAddress.isEmpty())
	{
		ipAddress.splitFront(":", nullptr, &ipAddress);
		ipAddress.splitFront(":", &ipAddress, nullptr);
	}

	if (registrationKey.isEmpty() || registrationVersion.isEmpty() || ipAddress.isEmpty())
	{
		throw HttpException(HttpStatus::BAD_REQUEST);
	}
	
	// Query existing registration-key.
	dbRequest["registrationKey"] = registrationKey;
	dbResponse = dbRequest.exec(
		"select "
			"i.registrationId, "
			"i.registrationVersion, "
			"i.registrationStatus, "
			"a.accountId, "
			"a.accountName, "
			"a.accountStatus "
		"from RasRegistration i "
			"inner join RasAccount a "
				"on i.accountId = a.accountId "
		"where i.registrationKey = '@registrationKey' ");
	dbResponse.throwIfError("RASecHomeService::onRegisterServer@QueryRegistrationKey");

	StrPropertyMap registrationInfo;
	if (!dbResponse.fetchNext(registrationInfo))
	{
		// Insert new registration.
		String registrationId = newId();

		dbRequest["accountId"] = accountId;
		dbRequest["deviceName"] = deviceName;
		dbRequest["ipAddress"] = ipAddress;
		dbRequest["registrationId"] = registrationId;
		dbRequest["registrationKey"] = registrationKey;
		dbRequest["registrationVersion"] = registrationVersion;
		dbRequest["registrationStatus"] = "active";
		dbRequest["registrationTime"] = Timestamp::Now().toIsoString();

		dbResponse = dbRequest.execInsert("RasRegistration");
		dbResponse.throwIfError("RASecHomeService::onRegisterServer@InsertNewRegistration");
	}

	// Detect multiple (duplicates).
	else if (!dbResponse.fetchNext())
	{
		// This should never happen.
		throw AppException("RASecHomeService::onRegisterServer@DuplicateRegistrationKey(%s)", registrationKey);
	}
	// Update existing.
	else
	{
		// Detect change in ownership.
		if (accountName != dbResponse["accountName"])
		{
			dbRequest["accountId"] = accountId;
			dbRequest["registrationTime"] = Timestamp::Now().toIsoString();
		}

		// Detect change in app version.
		if (registrationVersion != dbResponse["registrationVersion"])
		{
			dbRequest["registrationVersion"] = dbResponse["registrationVersion"];
		}

		// Detect change in device name.
		if (deviceName != dbResponse["deviceName"])
		{
			dbRequest["deviceName"] = deviceName;
		}

		// Detect change in IP address.
		if (ipAddress != dbResponse["ipAddress"])
		{
			dbRequest["ipAddress"] = ipAddress;
		}

		dbRequest["registrationId"] = dbResponse["registrationId"];
		dbResponse = dbRequest.execUpdate("RasRegistration", "where registrationId = '@registrationId'");
		dbResponse.throwIfError("RASecHomeService::onRegisterServer@UpdateExistingRegistration");
	}
}


void RASecHomeService::onValidateServer(HttpContext &context)
{
	RASecDbRequest dbRequest;
	DbResponse dbResponse;

	String registrationKey = context.request.queryParams["key"];
	String registrationVersion = context.request.queryParams["version"];
	if (registrationKey.isEmpty() && registrationVersion.isEmpty())
	{
		throw HttpException(HttpStatus::BAD_REQUEST);
	}

	// Query existing registration-key.
	dbRequest["registrationKey"] = registrationKey;
	dbResponse = dbRequest.exec(
		"select "
			"i.registrationStatus, "
			"a.accountName "
		"from RasRegistration i "
			"inner join RasAccount a "
				"on i.accountId = a.accountId "
		"where i.registrationKey = '@registrationKey' ");
	dbResponse.throwIfError("RASecHomeService::onValidateServer@QueryRegistrationKey");

	if (dbResponse["registrationStatus"] != "active")
	{
		throw HttpException(HttpStatus::DENIED, "inactive registration");
	}

	Json result;
	result["accountName"] = dbResponse["accountName"];
	context.response.setContent(result);
}



void RASecHomeService::onGetAccount(HttpContext &context)
{

}


void RASecHomeService::onCreateAccount(HttpContext &context)
{
	Json accountInfo;
	context.request.getContent(accountInfo);

	String accountName = accountInfo["accountName"];
	if (accountName.isEmpty())
	{
		throw HttpException(HttpStatus::BAD_REQUEST);
	}

	String maxRegistrations = accountInfo["maxRegistrations"];
	if (maxRegistrations.isEmpty())
	{
		maxRegistrations = "-1";	// unlimited.
	}

	String accountId = newId();

	RASecDbRequest dbRequest;
	dbRequest["accountId"] = accountId;
	dbRequest["accountName"] = accountName;
	dbRequest["accountStatus"] = "active";
	dbRequest["maxRegistrations"] = maxRegistrations;
	dbRequest["creationTime"] = Timestamp::Now().toIsoString();
	dbRequest.normalizeNullFields();

	DbResponse dbResponse = dbRequest.execInsert("RasAccount");
	if (dbResponse.isDuplicateRow())
	{
		throw HttpException(HttpStatus::CONFLICT, "duplicate");
	}
	else
	{
		dbResponse.throwIfError("RASecHomeService::onCreateAccount");
	}

	context.response.setStatus(HttpStatus::CREATED);
}
