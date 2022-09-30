#pragma once
#include "SysEventSink.h"
#include <netlistmgr.h>


//////////////////////////////////////////////////////////////////////
// class NetworkNotifier
//

class NetworkNotifier : public EventSinkBase<INetworkEvents, IID_INetworkEvents>
{
	SyncEvent m_notifyEvent;
	SyncEvent m_monitorEvent;
	CComPtr<INetworkListManager> m_spNLM;

public:
	NetworkNotifier() :
		m_monitorEvent(RASec::CLIENT_MONITOR_EVENT_NAME, true)
	{
		AddRef();
	}
	~NetworkNotifier()
	{
	}

	bool connect()
	{
		// Check if already running in another process.
		// Note that our constructor requests a signaled (true) monitor event;
		// so, if we're the first, we should have a signaled event when we get here.
		// In other words, if wait() fails, another process has called monitorEvent.reset().
		bool started = m_monitorEvent.wait(0);
		if (started)
		{
			m_monitorEvent.reset();

			HRESULT hr;
			if (FAILED(hr = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED)))
			{
				throw AppException(hr, "NetworkNotifier::NetworkNotifier@CoInitializeEx");
			}
			if (FAILED(hr = m_spNLM.CoCreateInstance(CLSID_NetworkListManager)))
			{
				throw AppException(hr, "NetworkNotifier::NetworkNotifier@CreateNLMInstance");
			}
			if (FAILED(hr = EventSinkBase::connect(m_spNLM)))
			{
				throw AppException(hr, "NetworkNotifier::NetworkNotifier@ConnectToSource");
			}
		}

		return started;
	}

	bool isAutoRunning()
	{
		return !m_monitorEvent.wait(0);
	}

	bool stop()
	{
		// If the monitor event is already signaled, no process is running auto mode.
		if (m_monitorEvent.wait(0))
		{
			return false;
		}

		m_monitorEvent.set();

		return true;
	}

	bool waitForEvent()
	{
		SyncEvent &appExitEvent = Application::Instance()->getExitEvent();

		SyncEventArray events;
		events.add(m_notifyEvent);
		events.add(m_monitorEvent);
		events.add(appExitEvent);

		int signalIndex = events.wait();
		bool ok = (signalIndex == 0);
		if (ok)
		{
			events.reset();
			events.add(m_monitorEvent);
			events.add(appExitEvent);

			if (ok = (events.wait(false, 100) == WAIT_TIMEOUT))
			{
				m_notifyEvent.reset();
			}
		}

		return ok;
	}

	void signalEvent()
	{
		m_notifyEvent.set();
	}

private:
	virtual HRESULT STDMETHODCALLTYPE NetworkAdded(GUID networkId)
	{
//		signalEvent();
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE NetworkDeleted(GUID networkId)
	{
//		signalEvent();
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE NetworkConnectivityChanged(GUID networkId, NLM_CONNECTIVITY newConnectivity)
	{
		if (newConnectivity != NLM_CONNECTIVITY_DISCONNECTED)
		{
			signalEvent();
		}
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE NetworkPropertyChanged(GUID networkId, NLM_NETWORK_PROPERTY_CHANGE flags)
	{
		signalEvent();
		return S_OK;
	}
};

