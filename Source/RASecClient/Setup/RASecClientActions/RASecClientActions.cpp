#include "pch.h"


static void _LogMessage(
	MSIHANDLE hInstall,
	LPCSTR pszFormat,
	...)
{
	static const int BUFFER_SIZE = 4096;

	DWORD nLastError = GetLastError();

	va_list args;
	va_start(args, pszFormat);

	CHAR pszMessage[BUFFER_SIZE];
	vsprintf_s(pszMessage, BUFFER_SIZE, pszFormat, args);

	va_end(args);

	PMSIHANDLE hRecord = ::MsiCreateRecord(2);
	MsiRecordSetString(hRecord, 0, "RASec: [1]");
	MsiRecordSetString(hRecord, 1, pszMessage);
	MsiProcessMessage(hInstall, INSTALLMESSAGE_INFO, hRecord);

	SetLastError(nLastError);
}


UINT __stdcall SuspendMonitor(MSIHANDLE hInstall)
{
	CHAR pszBuffer[MAX_PATH + 1];
	DWORD nSize = sizeof(pszBuffer);
	MsiGetProperty(hInstall, "TARGETDIR", pszBuffer, &nSize);
	ShellExecute(NULL, NULL, RASec::CLIENT_FILE_NAME, "auto stop", pszBuffer, 0);

	return ERROR_SUCCESS;
}


UINT __stdcall ResumeMonitor(MSIHANDLE hInstall)
{
	CHAR pszBuffer[MAX_PATH + 1];
	DWORD nSize = sizeof(pszBuffer);
	MsiGetProperty(hInstall, "TARGETDIR", pszBuffer, &nSize);
	ShellExecute(NULL, NULL, RASec::CLIENT_FILE_NAME, "auto start", pszBuffer, 0);
	return ERROR_SUCCESS;
}

