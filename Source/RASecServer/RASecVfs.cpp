#include "pch.h"
#include "RASecVfs.h"

#include <JlxSqlite/sqlite3.h>
#include <JlxSqlite/Common.h>


//////////////////////////////////////////////////////////////////////
// class RASecVfs
//

const String RASecVfs::NAME = "rasec";
RASecKey RASecVfs::sm_transformKey;
sqlite3_vfs RASecVfs::sm_rasecVfs;
sqlite3_io_methods RASecVfs::sm_rasecMethods;
RASecVfs::SqliteXOpen RASecVfs::sm_sqlitePrevOpen = nullptr;
RASecVfs::SqliteXRead RASecVfs::sm_sqlitePrevRead = nullptr;
RASecVfs::SqliteXWrite RASecVfs::sm_sqlitePrevWrite = nullptr;


void RASecVfs::Init(const UniqueId &machineId)
{
	// Compute the transform key.
	sm_transformKey.createToken(machineId);

	// Do Sqlite stuff.
	sqlite3_vfs *oldVfs = sqlite3_vfs_find("win32");
	memcpy(reinterpret_cast<sqlite3_vfs *>(&sm_rasecVfs), oldVfs, sizeof(sm_rasecVfs));

	if (sm_sqlitePrevOpen == nullptr)
	{
		sm_sqlitePrevOpen = oldVfs->xOpen;
	}

	sm_rasecVfs.xOpen = RASecOpen;
	sm_rasecVfs.zName = NAME;

	int rc = sqlite3_vfs_register(&sm_rasecVfs, false);
	if (rc != SQLITE_OK)
	{
		throw AppException("RASecVfs::Init@RegisterVfs - %d", rc);
	}

	try
	{
		// Check if the file exists.
		if (!System::FileExists(RASec::SERVER_DB_FILENAME))
		{
			// Check for an unencrypted file.
			if (System::FileExists(RASec::ALT_SERVER_DB_FILENAME))
			{
				// Convert to encrypted version.
				Convert(RASec::SERVER_DB_FILENAME, RASec::ALT_SERVER_DB_FILENAME, sm_transformKey);
			}
		}


		RASecDbRequest::Init(RASec::SERVER_DB_FILENAME, RASecVfs::NAME);
	}
	catch (AppException &x)
	{
		if (x.getCode() == SQLITE_NOTADB)
		{
			DbEngine::GetInstance()->unregisterConnectionName(RASecDbRequest::CONNECTION_NAME);

			if (!System::DeleteFile(RASec::SERVER_DB_FILENAME))
			{
				throw AppLastErrorException("RASecVfs::Init@DeleteMalformedDbFile");
			}
			
			RASecDbRequest::Init(RASec::SERVER_DB_FILENAME, RASecVfs::NAME);
		}
		else
		{
			throw;
		}
	}
}



void RASecVfs::Convert(
	const String &destPath,
	const String &sourcePath,
	const RASecKey &transformToken)
{
	ByteBuffer buffer(8192);

	FileStream destFile(destPath, FileStream::modeWrite | FileStream::modeCreate);
	FileStream sourceFile(sourcePath, FileStream::modeRead);

	ssize_t count = 0;
	ssize_t offset = 0;
	ssize_t total = sourceFile.getLength();
	while (offset < total)
	{
		if ((count = sourceFile.read(buffer, buffer.getCapacity())) > 0)
		{
			transformToken.transform(buffer, buffer, count, offset);

			if (destFile.write(buffer, count) != count)
			{
				throw AppLastErrorException("RASecVfs::Convert@WriteDest");
			}

			offset += count;
		}
		else
		{
			throw AppLastErrorException("RASecVfs::Convert@ReadSource");
		}
	}
}




int RASecVfs::RASecOpen(
	sqlite3_vfs *pVfs,
	const char *zName,
	sqlite3_file *pFile,
	int flags,
	int *pOutFlags)
{
	int rc = (*sm_sqlitePrevOpen)(pVfs, zName, pFile, flags, pOutFlags);

	if (rc == SQLITE_OK)
	{
		if (sm_sqlitePrevRead == nullptr)
		{
			const sqlite3_io_methods *prevMethods = pFile->pMethods;
			memcpy(&sm_rasecMethods, prevMethods, sizeof(sm_rasecMethods));

			sm_sqlitePrevRead = prevMethods->xRead;
			sm_rasecMethods.xRead = RASecRead;

			sm_sqlitePrevWrite = prevMethods->xWrite;
			sm_rasecMethods.xWrite = RASecWrite;
		}

		pFile->pMethods = &sm_rasecMethods;
	}

	return rc;
}


int RASecVfs::RASecRead(
	sqlite3_file *pFile,
	void *zBuf,
	int iAmt,
	sqlite_int64 iOfst)
{
	int rc = (*sm_sqlitePrevRead)(pFile, zBuf, iAmt, iOfst);
	if (rc == SQLITE_OK)
	{
		sm_transformKey.transform(zBuf, zBuf, iAmt, iOfst);
	}
	return rc;
}


int RASecVfs::RASecWrite(
	sqlite3_file *pFile,
	const void *zBuf,
	int iAmt,
	sqlite_int64 iOfst)
{
	ByteBuffer buffer(iAmt);
	sm_transformKey.transform(buffer, zBuf, iAmt, iOfst);
	return (*sm_sqlitePrevWrite)(pFile, buffer, iAmt, iOfst);
}
