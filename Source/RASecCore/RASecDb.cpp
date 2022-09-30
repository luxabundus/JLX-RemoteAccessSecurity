#include "pch.h"
#include "RASecDb.h"

#include <JlxSqlite/Common.h>


//////////////////////////////////////////////////////////////////////
// class RASecDbRequest
//

const String RASecDbRequest::CONNECTION_NAME = "rasec";
DbConnection *RASecDbRequest::sm_dbConnection = nullptr;


RASecDbRequest::RASecDbRequest() :
	DbRequest(sm_dbConnection)
{
}


void RASecDbRequest::Init(const char *fileName, const char *vfsName)
{
	bool isNew = !System::FileExists(fileName);

	sm_dbConnection = Sqlite::ConnectDatabase(CONNECTION_NAME, fileName, vfsName);
	if (!sm_dbConnection)
	{
		throw AppException(-1, "RASecDbRequest::Init - database connection error");
	}

	DbRequest dbRequest(sm_dbConnection);
	DbResponse dbResponse;

#if !defined(_DEBUG)
	// Set exclusive mode.
	dbResponse = dbRequest.exec("PRAGMA main.locking_mode=EXCLUSIVE");
	dbResponse.throwIfError("RASecDbRequest::Init@InitializeExclusiveLocking");
#endif

	if (isNew)
	{
		// Initialize the schema.
		String dbGenesis;
		if (!System::GetModuleResource("SQL", "DBGENESIS", dbGenesis))
		{
			throw AppLastErrorException("RASecDbRequest::Init@LoadDbGenesis");
		}

		dbGenesis = StrFromUnicode(dbGenesis);
		dbResponse = dbRequest.runScript(dbGenesis);
		dbResponse.throwIfError("RASecDbRequest::Init@RunScript");
	}
	else
	{
		dbResponse = dbRequest.exec("select dbVersion from Control");
		dbResponse.throwIfError("RASecDbRequest::Init@GetCurrentDbVersion");

		int curVersion = StrToInt(dbResponse["dbVersion"]);
		dbRequest.applyUpdates(curVersion, "DbUpdate");
	}
}


DbConnection *RASecDbRequest::GetConnection()
{
	return sm_dbConnection;
}
