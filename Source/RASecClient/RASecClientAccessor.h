#pragma once
#include <RASecCore/RASecStream.h>

#define WINDOWS_RUN_KEY "Software\\Microsoft\\Windows\\CurrentVersion\\Run"


//////////////////////////////////////////////////////////////////////
// class RASecClientAccessor
//

class RASecClientAccessor
{
	const int DEFAULT_PORT = 5991;

	struct ServerInfo
	{
		String Server;
		String User;
		String Password;
		String Scheme;
		String TargetName;
	};

	RASecConsole &m_console;

public:
	RASecClientAccessor(RASecConsole &console) :
		m_console(console)
	{
	}
	~RASecClientAccessor()
	{
		::CoUninitialize();
	}

	void requestAccess(String server)
	{
		if (server.isEmpty() && (server = m_console.prompt("server: ")).isEmpty())
		{
			return;
		}

		if (server.compareNoCase("all") == 0)
		{
			accessAll();
		}
		else
		{
			try
			{
				// Get creds.
				ServerInfo serverInfo;
				bool hasSavedCreds = getSavedInfo(server, serverInfo);
				if (!hasSavedCreds)
				{
					// Try prompting user.
					if ((serverInfo.User = m_console.prompt("user: ")).isEmpty()
						|| (serverInfo.Password = m_console.prompt("password: ", false)).isEmpty())
					{
						return;
					}
				}

				sendClientRequest("PUT", serverInfo);

				// Save creds, if necessary.
				if (!hasSavedCreds)
				{
					CREDENTIAL creds;
					ZeroMemory(&creds, sizeof(creds));
					creds.Type = CRED_TYPE_GENERIC;
					creds.TargetName = serverInfo.TargetName.getBuffer();
					creds.CredentialBlob = (LPBYTE)serverInfo.Password.getBuffer();
					creds.CredentialBlobSize = (DWORD)serverInfo.Password.getLength();
					creds.Persist = CRED_PERSIST_LOCAL_MACHINE;
					creds.UserName = serverInfo.User.getBuffer();

					// Add scheme attribute.
					CREDENTIAL_ATTRIBUTE attrib;
					ZeroMemory(&attrib, sizeof(attrib));
					attrib.Keyword = (char *)"rasec_scheme";
					attrib.Value = (LPBYTE)serverInfo.Scheme.getBuffer();
					attrib.ValueSize = (DWORD)serverInfo.Scheme.getLength();

					creds.AttributeCount = 1;
					creds.Attributes = &attrib;

					if (!::CredWrite(&creds, 0))
					{
						throw StrPrintF("unable to save credentials - %s", System::FormatLastError());
					}
				}

				m_console.print("SUCCESS: access approved");
			}
			catch (String &error)
			{
				m_console.printError(error);
			}
		}
	}

	void dropAccess(const String &server)
	{
		try
		{
			ServerInfo serverInfo;
			if (!getSavedInfo(server, serverInfo))
			{
				throw String("unregistered server");
			}

			if (!::CredDelete(serverInfo.TargetName, CRED_TYPE_GENERIC, 0))
			{
				throw StrPrintF("unable to delete credentials - %s", System::FormatLastError());
			}

			sendClientRequest("DELETE", serverInfo);

			m_console.print("SUCCESS: access dropped");
		}
		catch (String &error)
		{
			m_console.printError(error);
		}
	}

	void listAccess()
	{
		// Enumerate credentials
		DWORD nCredCount = 0;
		PCREDENTIAL *ppCreds = NULL;
		if (!::CredEnumerate(NULL, 0, &nCredCount, &ppCreds))
		{
			throw String("Error retrieving credentials");
		}

		bool isFirstLine = true;
		for (DWORD nCredIndex = 0; nCredIndex < nCredCount; nCredIndex++)
		{
			if (isFirstLine)
			{
				m_console.print("");
				isFirstLine = false;
			}

			PCREDENTIAL pCred = ppCreds[nCredIndex];

			if (strncmp(pCred->TargetName, "rasec:", 6) == 0)
			{
				String server = pCred->TargetName + 6;
				String user = pCred->UserName;

				m_console.print("%s user=\"%s\"", server, user);
			}
		}

		::CredFree(ppCreds);
	}

	void printHelp()
	{
		String helpText;
		System::GetModuleResource("TXT", "HELP", helpText);
		m_console.print(helpText);
	}

	void startAuto()
	{
		SyncEvent monitorEvent(RASec::CLIENT_MONITOR_EVENT_NAME, true);
		if (!monitorEvent.wait(0))
		{
			m_console.printError("auto mode already started");
		}
		else
		{
			if (System::RunCommandLine(RASec::CLIENT_MONITOR_FILE_NAME, nullptr))
			{
				m_console.print("Auto mode successfully started");

				SysRegistry regRun;
				if (regRun.create(HKEY_CURRENT_USER, WINDOWS_RUN_KEY))
				{
					regRun.setValue(RASec::CLIENT_MONITOR_RUN_KEY_ENTRY, RASec::CLIENT_MONITOR_FILE_NAME);
				}
			}
			else
			{
				m_console.printError(System::FormatLastError());
			}
		}
	}

	void stopAuto()
	{
		SyncEvent monitorEvent(RASec::CLIENT_MONITOR_EVENT_NAME, true);
		if (monitorEvent.wait(0))
		{
			m_console.printError("auto mode not started");
		}
		else
		{
			monitorEvent.set();

			SysRegistry regRun;
			if (regRun.create(HKEY_CURRENT_USER, WINDOWS_RUN_KEY))
			{
				regRun.deleteValue(RASec::CLIENT_MONITOR_RUN_KEY_ENTRY);
			}

			m_console.print("Auto mode successfully stopped");
		}
	}

	void queryAuto()
	{
		SyncEvent monitorEvent(RASec::CLIENT_MONITOR_EVENT_NAME, true);
		if (monitorEvent.wait(0))
		{
			m_console.print("Auto mode is off");
		}
		else
		{
			m_console.print("Auto mode is on");
		}
	}

private:
	bool getSavedInfo(const String &server, ServerInfo &serverInfo)
	{
		String error;
		PCREDENTIAL pCreds = nullptr;

		serverInfo.Server = server;
		serverInfo.TargetName = "rasec:" + serverInfo.Server;

		if (::CredRead(serverInfo.TargetName, CRED_TYPE_GENERIC, 0, &pCreds))
		{
			if (pCreds->AttributeCount == 1)
			{
				serverInfo.Password = String((char *)pCreds->CredentialBlob, pCreds->CredentialBlobSize);
				serverInfo.User = pCreds->UserName;
				serverInfo.Scheme = String((char *)pCreds->Attributes[0].Value, pCreds->Attributes[0].ValueSize);
				::CredFree(pCreds);
			}
			else
			{
				::CredFree(pCreds);
				throw String("malformed credentials");
			}

			return true;
		}
		else
		{
			return false;
		}
	}

	void accessAll()
	{
		// Enumerate credentials
		DWORD nCredCount = 0;
		PCREDENTIAL *ppCreds = NULL;
		if (!::CredEnumerate(NULL, 0, &nCredCount, &ppCreds))
		{
			throw String("Error retrieving credentials");
		}

		for (DWORD nCredIndex = 0; nCredIndex < nCredCount; nCredIndex++)
		{
			PCREDENTIAL pCred = ppCreds[nCredIndex];

			if (strncmp(pCred->TargetName, "rasec:", 6) == 0)
			{
				ServerInfo serverInfo;
				serverInfo.TargetName = pCred->TargetName;
				serverInfo.TargetName.splitFront(":", nullptr, &serverInfo.Server);

				if (pCred->AttributeCount == 1)
				{
					serverInfo.Password = String((char *)pCred->CredentialBlob, pCred->CredentialBlobSize);
					serverInfo.User = pCred->UserName;
					serverInfo.Scheme = String((char *)pCred->Attributes[0].Value, pCred->Attributes[0].ValueSize);
				}

				try
				{
					sendClientRequest("PUT", serverInfo);
				}
				catch (String &error)
				{
					m_console.printError(error);
				}
			}
		}

		::CredFree(ppCreds);
	}

	void sendClientRequest(const String &method, ServerInfo &serverInfo)
	{
		// Get computer name.
		String computer = System::GetComputerName();
		if (computer.isEmpty())
		{
			throw System::FormatLastError();
		}

		// Build server params.
		String serverAddress = serverInfo.Server;

		String port;
		if (!serverAddress.splitBack(":", nullptr, &port))
		{
			serverAddress += ":" + StrFromInt(DEFAULT_PORT);
		}

		String path = StrPrintF("/rasec/client/access?computer=%s", Http::EncodeForm(computer));

		int status;
		if (serverInfo.Scheme.isEmpty())
		{
			// First, try HTTPS.
			if ((status = sendRequest(method, "https", serverAddress, path, serverInfo)) != HttpStatus::OK)
			{
				status = sendRequest(method, "http", serverAddress, path, serverInfo);
			}
		}
		else
		{
			status = sendRequest(method, serverInfo.Scheme, serverAddress, path, serverInfo);
		}

		// Validate connection.
		if (status == 0)
		{
			throw StrPrintF("unable to connect to %s", serverInfo.Server);
		}
	}

	int sendRequest(const String &method, const String &scheme, String serverAddress, const String &path, ServerInfo &serverInfo)
	{
		String uri;
		if (scheme == "http")
		{
			// Use the RASecProtocol.
			uri = StrPrintF("%s://rasec:%s%s", scheme, serverAddress, path);
		}
		else
		{
			uri = StrPrintF("%s://%s%s", scheme, serverAddress, path);
		}

		HttpClient http;
		http.request.setBasicAuth(serverInfo.User, serverInfo.Password);
		http.send(method, uri);

		// Validate response.
		if (http.response.status && (http.response.status != HttpStatus::OK))
		{
			throw http.response.meaning;
		}

		return http.response.status;
	}
};

