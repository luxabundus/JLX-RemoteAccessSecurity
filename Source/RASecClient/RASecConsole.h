#pragma once


//////////////////////////////////////////////////////////////////////
// class RASecConsole
//

class RASecConsole
{
	ConsoleStream m_console;

public:
	template <typename... Args>
	void print(const char *format, const Args & ... args)
	{
		m_console.write(StrPrintF(format, args...) + "\n");
	}

	template <typename... Args>
	void printSuccess(const char *format, const Args & ... args)
	{
		print("SUCCESS: %s", StrPrintF(format, args...));
	}

	template <typename... Args>
	void printError(const char *format, const Args & ... args)
	{
		print("ERROR: %s", StrPrintF(format, args...));
	}

	String prompt(const char *prefix, bool echo = true)
	{
		String input;
		prompt(prefix, input, echo);
		return input;
	}

	bool prompt(const char *prefix, String &input, bool echo = true)
	{
		m_console.write(prefix);

		enableEcho(echo);

		bool ok = m_console.read(input) >= 0;

		if (!echo)
		{
			enableEcho(true);
			print("");
		}

		return ok;
	}

	void clear()
	{
		m_console.clear();
	}

	bool syncHandles()
	{
		return m_console.syncHandles();
	}

private:
	void enableEcho(bool enable)
	{
		HANDLE hStdin = ::GetStdHandle(STD_INPUT_HANDLE);

		DWORD mode;
		::GetConsoleMode(hStdin, &mode);

		if (!enable)
		{
			mode &= ~ENABLE_ECHO_INPUT;
		}
		else
		{
			mode |= ENABLE_ECHO_INPUT;
		}

		::SetConsoleMode(hStdin, mode);
	}
};

