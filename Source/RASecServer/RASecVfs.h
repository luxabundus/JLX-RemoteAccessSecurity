#pragma once
#include <RASecCore/RASecKey.h>
#include <JlxSqlite/sqlite3.h>


//////////////////////////////////////////////////////////////////////
// class RASecVfs
//

class RASecVfs
{
public:
	static const String NAME;
	static void Init(const UniqueId &machineId);

private:
	static void Convert(
		const String &destPath,
		const String &sourcePath,
		const RASecKey &transformToken);

	static int RASecOpen(
		sqlite3_vfs *pVfs,
		const char *zName,
		sqlite3_file *pFile,
		int flags,
		int *pOutFlags);
	static int RASecRead(
		sqlite3_file *pFile,
		void *zBuf,
		int iAmt,
		sqlite_int64 iOfst);
	static int RASecWrite(
		sqlite3_file *pFile,
		const void *zBuf,
		int iAmt,
		sqlite_int64 iOfst);

	using SqliteXOpen = int(*)(sqlite3_vfs *pVfs, const char *zName, sqlite3_file *pFile, int flags, int *pOutFlags);
	using SqliteXRead =  int (*)(sqlite3_file *pFile, void *zBuf, int iAmt, sqlite_int64 iOfst);
	using SqliteXWrite = int (*)(sqlite3_file *pFile, const void *zBuf, int iAmt, sqlite_int64 iOfst);

	static RASecKey sm_transformKey;
	static sqlite3_vfs sm_rasecVfs;
	static sqlite3_io_methods sm_rasecMethods;
	static SqliteXOpen sm_sqlitePrevOpen;
	static SqliteXRead sm_sqlitePrevRead;
	static SqliteXWrite sm_sqlitePrevWrite;
};

