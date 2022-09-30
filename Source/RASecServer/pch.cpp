#include "pch.h"

namespace RASec
{
	const String SENTINEL_ADDRESS = "1.1.1.1";
	const String SENTINEL_ACCOUNT_ID = "<sentinel>";

	const String CLIENT_RULE_GROUPING = "Remote Access Security";
	const String CLIENT_RULE_NAME = "Remote Access Security";

	const String CLIENT_USER_GROUP = "RASecClient";
	const String CLIENT_ACCESS_LIST = "Administrators," + CLIENT_USER_GROUP;

	const String ADMIN_USER_GROUP = "RASecAdmin";
	const String ADMIN_ACCESS_LIST = "Administrators," + ADMIN_USER_GROUP;

	const String SERVER_DB_FILENAME = "rasec";
	const String ALT_SERVER_DB_FILENAME = "rasec.db";
}


