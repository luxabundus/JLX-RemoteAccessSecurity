#include "pch.h"
#include "NetworkNotifier.h"


class RASecClientMonitorApp : public Application
{
public:
	RASecClientMonitorApp()
	{
	}

	virtual void main()
	{
		NetworkNotifier notifier;
		if (notifier.connect())
		{
			do {
				System::RunCommandLine("rasec access all", nullptr, INFINITE);
			} while (notifier.waitForEvent());

			notifier.disconnect();
		}
	}

};


RASecClientMonitorApp RASecClientMonitor;


extern "C" int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, int nCmdShow)
{
	return RASecClientMonitor.run(__argc, __argv, _environ);
}
