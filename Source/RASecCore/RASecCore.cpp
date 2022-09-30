#include "pch.h"


namespace RASec
{
	const String COMPANY_NAME = "Joel Luzadas Inc";
	const String PRODUCT_NAME = "Remote Access Security";
	const String ROOT_KEY_PATH = "Software\\" + RASec::COMPANY_NAME + "\\" + RASec::PRODUCT_NAME;

	const String HOME_URL = "https://rasec.luzadas.com";
	const String ALT_HOME_URL = "https://home.remaxity.com";
}


namespace RASec
{
	const char *CLIENT_FILE_NAME = "rasec.exe";
	const char *CLIENT_MONITOR_FILE_NAME = "rasecmon.exe";
	const char *CLIENT_MONITOR_EVENT_NAME = "RASEC_MONITOR";
	const char *CLIENT_MONITOR_RUN_KEY_ENTRY = "Remote Access Security";
}
