#pragma once


//////////////////////////////////////////////////////////////////////
// class RASecDbRequest
//

class RASecDbRequest : public DbRequest
{
public:
	RASecDbRequest();

	static const String CONNECTION_NAME;
	static void Init(const char *fileName, const char *vfsName = nullptr);
	static DbConnection *GetConnection();

private:
	static DbConnection *sm_dbConnection;
};

