#pragma once
#include "RASecClientAccessor.h"
#include "RASecAdminAccessor.h"


class RASecClientApp : public Application
{
	using CmdFunc = std::function<void()>;
	using CmdFuncMap = StringMap<CmdFunc>;

	CmdFuncMap m_clientCmdFuncs;
	CmdFuncMap m_adminCmdFuncs;

	bool m_isShellMode;
	StringArray m_cmdArgs;

	RASecConsole m_console;
	RASecAdminAccessor m_admin;
	RASecClientAccessor m_client;

public:
	RASecClientApp() :
		m_isShellMode(false),	// Assume single command mode.
		m_admin(m_console),
		m_client(m_console)
	{
	}

	virtual void main()
	{
		if (m_argc == 1)
		{
			m_client.printHelp();
		}

		else
		{
			if (!RASecProtocol::Initialize())
			{
				return;
			}

			// Take initial params from the main command line; skip program name.
			for (int i = 1; i < m_argc; i++)
			{
				m_cmdArgs.add(m_argv[i]);
			}

			initCommands();

			do
			{
				String command = getCmdArg(0);
				if (!command.isEmpty())
				{
					CmdFunc cmdFunc = nullptr;
					if (m_clientCmdFuncs.get(command, cmdFunc))
					{
						try
						{
							cmdFunc();
						}
						catch (String &error)
						{
							m_console.printError(error);
						}
						catch (Exception &x)
						{
							m_console.printError(x.getErrorString());
						}
					}
					else
					{
						m_console.printError("Unknown command - %s", command);
					}
				}
			} while (readNextCommand());
		}
	}

private:
	void initCommands()
	{
		/* Client Commands */
		m_clientCmdFuncs["access"] = [this]() mutable
		{
			m_client.requestAccess(getCmdArg(1));
		};

		m_clientCmdFuncs["leave"] = [this]() mutable
		{
			m_client.dropAccess(getCmdArg(1));
		};

		m_clientCmdFuncs["list"] = [this]() mutable
		{
			m_client.listAccess();
		};

		m_clientCmdFuncs["help"] = [this]() mutable
		{
			m_client.printHelp();
			m_admin.printHelp();
		};

		m_clientCmdFuncs["shell"] = [this]() mutable
		{
			if (m_isShellMode)
			{
				m_console.print("Already in shell mode");
			}
			else
			{
				m_console.print("Entering shell mode. Type Ctrl-C to exit.");
				m_isShellMode = true;
			}
		};

		m_clientCmdFuncs["cls"] = [this]() mutable
		{
			m_console.clear();
		};

		m_clientCmdFuncs["auto"] = [this]() mutable
		{
			String directive = getCmdArg(1);
			if (directive.compareNoCase("stop") == 0)
			{
				m_client.stopAuto();
			}
			else if (directive.isEmpty()
				|| (directive.compareNoCase("start") == 0))
			{
				m_client.startAuto();
			}
			else if (directive = "?")
			{
				m_client.queryAuto();
			}
		};

		m_clientCmdFuncs["admin"] = [this]() mutable
		{
			String command = getCmdArg(1);
			if (!command.isEmpty())
			{
				StrPropertyMap params;
				getNamedParams(params, 2);

				m_admin.exec(command, params);
			}
		};
	}

	bool readNextCommand()
	{
		m_console.print("");

		// Reset parameters
		m_cmdArgs.removeAll();

		if (!m_isShellMode)
		{
			return false;
		}

		String commandLine;
		if (!m_console.prompt("? ", commandLine))
		{
			return false;
		}

		if (!Application::Instance()->waitForExit(0))
		{
			System::ParseCommandLine(commandLine, m_cmdArgs);
			return true;
		}
		else
		{
			return false;
		}
	}

	String getCmdArg(int index)
	{
		String arg;
		if (index < m_cmdArgs.getCount())
		{
			arg = m_cmdArgs[index];
		}
		return arg;
	}

	void getNamedParams(StrPropertyMap &params, int index)
	{
		for (; index < m_cmdArgs.getCount(); index++)
		{
			String nvp = getCmdArg(index);

			String name, value;
			if (!nvp.splitFront("=", &name, &value))
			{
				name = nvp;
			}

			params[name] = value.trim('"');
		}
	}
};

