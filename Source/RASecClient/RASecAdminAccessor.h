#pragma once


//////////////////////////////////////////////////////////////////////
// class RASecAdminAccessor
//

class RASecAdminAccessor
{
	RASecConsole &m_console;

public:
	RASecAdminAccessor(RASecConsole &console) :
		m_console(console)
	{
	}

	void exec(String command, const StrPropertyMap &params)
	{
		validateAdministrator(params);

		String response = sendServerRequest(command.makeUpper(), params);
		if (!response.isEmpty())
		{
			m_console.print(response);
		}
	}

	void printHelp()
	{
		HttpClient http;
		if (http.send("HELP", RASec::BASE_ADMIN_URL).succeeded())
		{
			String help;
			http.response.getContent(help);
			m_console.print(help);
		}
	}

private:
	bool validateAdministrator(const StrPropertyMap &params)
	{
		return true;
// 		bool isAdmin = IsUserAnAdmin();
// 		if (!isAdmin)
// 		{
// 			String user = params["user"];
// 			if (user.isEmpty)
// 			String password = params["password"];
// 			isAdmin = !(user = m_console.prompt("user: ")).isEmpty()
// 				&& !(password = m_console.prompt("password: ", false)).isEmpty()
// 				&& System::AuthenticateUser(user, password, "Administrators,RASecAdmin");
// 		}
// 		return isAdmin;
	}

	String sendServerRequest(const char *method, const StrPropertyMap &params)
	{
		String query;
		for (auto &&it : params)
		{
			if (query.isEmpty())
			{
				query = StrPrintF("?%s=%s", it->first, Http::EncodeForm(it->second));
			}
			else
			{
				query = StrPrintF("%s&%s=%s", query, it->first, Http::EncodeForm(it->second));
			}
		}

		HttpClient http;
		http.send(method, StrPrintF("%s%s", RASec::BASE_ADMIN_URL, query));

		if (http.response.status == 0)
		{
			throw String("unable to connect");
		}
		if (http.response.status != HttpStatus::OK)
		{
			throw http.response.meaning;
		}

		String response;
		http.response.getContent(response);
		return response;
	}
};

