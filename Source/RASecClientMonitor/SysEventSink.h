#pragma once


//////////////////////////////////////////////////////////////////////
// class EventSinkConnector
//

class EventSinkConnector
{
	DWORD m_dwCookie;
	IUnknown *m_punkEventSink;
	CComPtr<IConnectionPoint> m_spConnectionPoint;

public:
	EventSinkConnector() :
		m_dwCookie(0),
		m_punkEventSink(nullptr)
	{
	}
	~EventSinkConnector()
	{
	}

	bool isConnected() const
	{
		return m_dwCookie != 0;
	}

	HRESULT disconnect()
	{
		HRESULT hr = E_FAIL;
		if (m_spConnectionPoint && m_dwCookie)
		{
			hr = m_spConnectionPoint->Unadvise(m_dwCookie);
			m_spConnectionPoint = nullptr;
			m_punkEventSink = nullptr;
		}
		return hr;
	}

protected:
	HRESULT connectToNotifier(IUnknown *punkNotifier, REFIID riidEventSink, IUnknown *punkEventSink)
	{
		HRESULT hr;

		CComPtr<IConnectionPointContainer> spConnectionContainer;
		if (FAILED(hr = punkNotifier->QueryInterface(IID_IConnectionPointContainer, (void **)&spConnectionContainer)))
		{
			return hr;
		}

		if (FAILED(hr = spConnectionContainer->FindConnectionPoint(riidEventSink, &m_spConnectionPoint)))
		{
			return hr;
		}

		if (FAILED(hr = m_spConnectionPoint->Advise(punkEventSink, &m_dwCookie)))
		{
			return hr;
		}

		m_punkEventSink = punkEventSink;

		return hr;
	}
};


template <class INotifier, const GUID &NotifierIID>
class EventSinkBase : public EventSinkConnector, public INotifier
{
	std::atomic<ULONG> m_refCount;

public:
	EventSinkBase() : m_refCount(0)
	{
	}

	HRESULT connect(IUnknown *pNotifier)
	{
		return connectToNotifier(pNotifier, NotifierIID, this);
	}

	virtual ULONG STDMETHODCALLTYPE AddRef()
	{
		return ++m_refCount;
	}

	virtual ULONG STDMETHODCALLTYPE Release()
	{
		ULONG refCount = --m_refCount;
		if (refCount == 0)
		{
			delete this;
		}
		return refCount;
	}

	virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, PVOID *ppvObj)
	{
		HRESULT hr = S_OK;

		if ((riid == IID_IUnknown) || (riid == NotifierIID))
		{
			*ppvObj = this;
			AddRef();
		}
		else
		{
			hr = E_NOINTERFACE;
			*ppvObj = NULL;
		}

		return hr;
	}
};


