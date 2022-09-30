#include "pch.h"
#include "RASecDb.h"


static const String DB_FILE_NAME = "rasechome.db";


//////////////////////////////////////////////////////////////////////
// class RASecDbRequest
//

DbConnection *RASecDbRequest::sm_dbConnection = nullptr;


RASecDbRequest::RASecDbRequest() :
	DbRequest(sm_dbConnection)
{
}


bool RASecDbRequest::Init()
{
	bool isNew = !System::FileExists(DB_FILE_NAME);

	sm_dbConnection = Sqlite::ConnectDatabase("rasec", DB_FILE_NAME);
	if (!sm_dbConnection)
	{
		return false;
	}

	DbRequest dbRequest(sm_dbConnection);
	DbResponse dbResponse;

#if !defined(_DEBUG)
	// Set exclusive mode.
	dbResponse = dbRequest.exec("PRAGMA main.locking_mode=EXCLUSIVE");
	if (dbResponse.failed())
	{
		dbResponse.logError("RASecDbRequest::Init@InitializeExclusiveLocking");
		return false;
	}
#endif

	return true;
}
