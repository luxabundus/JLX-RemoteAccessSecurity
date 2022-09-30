#pragma once


//////////////////////////////////////////////////////////////////////////
// class RASecFirewall
//

class RASecFirewall
{
public:
	RASecFirewall();
	~RASecFirewall();

	bool initInstance();
	void exitInstance();

	void updateAccess();
	const SyncMutex &getUpdateMutex() const;

	bool install();
	bool uninstall();

private:
	String buildRestoreKey(const StrPropertyMap &params);

	template <typename... Args>
	static void ThrowIfError(HRESULT hr, const char *format, const Args&... args);
	static String LoadString(CComBSTR &bstrVal);

	class FwRuleAccessor
	{
		CComPtr<INetFwRule> m_spRule;

	public:
		FwRuleAccessor(const CComPtr<INetFwRule> &spRule);

		void select(StrPropertyMap &properties, const String &fieldNames);
		void assign(const StrPropertyMap &fieldValues);

		operator bool() const;

	private:
		using GetterFunc = std::function<void(StrPropertyMap &, INetFwRule *)>;
		static struct Getters : public StringMap<GetterFunc> { Getters(); } sm_getters;

		using SetterFunc = std::function<void(const String &, INetFwRule *)>;
		static struct Setters : public StringMap<SetterFunc> { Setters(); } sm_setters;
	};

	class FwPolicyAccessor
	{
		CComPtr<INetFwPolicy2> m_spPolicy;
		CComPtr<INetFwRules> m_spCollection;

	public:
		FwPolicyAccessor();

		FwRuleAccessor getRule(const String &ruleName);

		void forEachRule(std::function<bool(FwRuleAccessor &)> &&);
		void createRule(const StrPropertyMap &params);
		void deleteRule(const String &ruleName);
	};

	SyncMutex m_updateMutex;
	SyncEvent m_updateEvent;
	std::thread m_updateThread;

	void iterateAccessRules();
};


inline const SyncMutex &RASecFirewall::getUpdateMutex() const
{
	return m_updateMutex;
}


inline String RASecFirewall::buildRestoreKey(const StrPropertyMap &params)
{
	MemStream buffer;
	buffer.write(params["ruleName"]);
	buffer.write(params["groupName"]);
	buffer.write(params["applicationName"]);
	buffer.write(params["serviceName"]);
	buffer.write(params["profiles"]);
	buffer.write(params["protocol"]);
	buffer.write(params["direction"]);
	buffer.write(params["localPorts"]);
	buffer.write(params["localAddresses"]);
	buffer.write(params["remotePorts"]);
	return Crypto::MD5String(buffer.toString().makeLower());
}


template <typename... Args>
inline void RASecFirewall::ThrowIfError(HRESULT hr, const char *format, const Args&... args)
{
	if (FAILED(hr))
	{
		throw AppException(StrPrintF(format, args...));
	}
}

inline String RASecFirewall::LoadString(CComBSTR &bstrVal)
{
	String value;
	if (bstrVal.Length() > 0)
	{
		wchar_t pszVal[1024];
		SHLoadIndirectString(bstrVal, pszVal, ARRAYSIZE(pszVal), NULL);
		value = pszVal;
	}
	return value;
}


inline RASecFirewall::FwRuleAccessor::FwRuleAccessor(const CComPtr<INetFwRule> &spRule) :
	m_spRule(spRule)
{
}

inline void RASecFirewall::FwRuleAccessor::select(StrPropertyMap &properties, const String &fieldNames)
{
	size_t start = 0;
	String fieldName;
	while (!(fieldName = fieldNames.tokenize(",", start).trim()).isEmpty())
	{
		GetterFunc getter;
		if (sm_getters.get(fieldName, getter))
		{
			getter(properties, m_spRule);
		}
	}
}

inline void RASecFirewall::FwRuleAccessor::assign(const StrPropertyMap &fieldValues)
{
	StringArray errors;
	for (auto &&cur : fieldValues)
	{
		SetterFunc setter;
		if (sm_setters.get(cur->first, setter))
		{
			try
			{
				setter(cur->second, m_spRule);
			}
			catch(Exception & x)
			{
				errors.add(x.getErrorString());
			}
		}
	}

	if (!errors.isEmpty())
	{
		throw AppException(StrJoin(errors, "\n"));
	}
}

inline RASecFirewall::FwRuleAccessor::operator bool() const
{
	return m_spRule != nullptr;
}


inline RASecFirewall::FwRuleAccessor::Getters::Getters()
{
	Getters &getters = *this;

	getters["ruleName"] = [this](StrPropertyMap &properties, INetFwRule *pRule) mutable
	{
		CComBSTR bstrValue;
		ThrowIfError(pRule->get_Name(&bstrValue), "GetRuleName");
		properties["ruleName"] = LoadString(bstrValue);
	};
	getters["groupName"] = [this](StrPropertyMap &properties, INetFwRule *pRule) mutable
	{
		CComBSTR bstrValue;
		ThrowIfError(pRule->get_Grouping(&bstrValue), "GetGroupName");
		properties["groupName"] = LoadString(bstrValue);
	};
	getters["applicationName"] = [this](StrPropertyMap &properties, INetFwRule *pRule) mutable
	{
		CComBSTR bstrValue;
		ThrowIfError(pRule->get_ApplicationName(&bstrValue), "GetApplicationName");
		properties["applicationName"] = LoadString(bstrValue);
	};
	getters["serviceName"] = [this](StrPropertyMap &properties, INetFwRule *pRule) mutable
	{
		CComBSTR bstrValue;
		ThrowIfError(pRule->get_ServiceName(&bstrValue), "GetServiceName");
		properties["serviceName"] = LoadString(bstrValue);
	};
	getters["remoteAddresses"] = [this](StrPropertyMap &properties, INetFwRule *pRule) mutable
	{
		CComBSTR bstrValue;
		ThrowIfError(pRule->get_RemoteAddresses(&bstrValue), "GetRemoteAddresses");
		properties["remoteAddresses"] = LoadString(bstrValue);
	};
	getters["remotePorts"] = [this](StrPropertyMap &properties, INetFwRule *pRule) mutable
	{
		CComBSTR bstrValue;
		ThrowIfError(pRule->get_RemotePorts(&bstrValue), "GetRemotePorts");
		properties["remotePorts"] = LoadString(bstrValue);
	};
	getters["localAddresses"] = [this](StrPropertyMap &properties, INetFwRule *pRule) mutable
	{
		CComBSTR bstrValue;
		ThrowIfError(pRule->get_LocalAddresses(&bstrValue), "GetLocalAddresses");
		properties["localAddresses"] = LoadString(bstrValue);
	};
	getters["localPorts"] = [this](StrPropertyMap &properties, INetFwRule *pRule) mutable
	{
		CComBSTR bstrValue;
		ThrowIfError(pRule->get_LocalPorts(&bstrValue), "GetLocalPorts");
		properties["localPorts"] = LoadString(bstrValue);
	};
	getters["profiles"] = [this](StrPropertyMap &properties, INetFwRule *pRule) mutable
	{
		long profiles = 0;
		ThrowIfError(pRule->get_Profiles(&profiles), "GetProfiles");
		properties["profiles"] = StrFromInt(profiles);
	};
	getters["protocol"] = [this](StrPropertyMap &properties, INetFwRule *pRule) mutable
	{
		long protocol = 0;
		ThrowIfError(pRule->get_Protocol(&protocol), "GetProtocol");
		properties["protocol"] = StrFromInt(protocol);
	};
	getters["direction"] = [this](StrPropertyMap &properties, INetFwRule *pRule) mutable
	{
		NET_FW_RULE_DIRECTION direction;
		ThrowIfError(pRule->get_Direction(&direction), "GetDirection");
		properties["direction"] = StrFromInt(direction);
	};
	getters["action"] = [this](StrPropertyMap &properties, INetFwRule *pRule) mutable
	{
		NET_FW_ACTION currentAction;
		ThrowIfError(pRule->get_Action(&currentAction), "GetAction");
		properties["action"] = StrFromInt(currentAction);
	};
	getters["enabled"] = [this](StrPropertyMap &properties, INetFwRule *pRule) mutable
	{
		VARIANT_BOOL bEnabled = VARIANT_FALSE;
		ThrowIfError(pRule->get_Enabled(&bEnabled), "GetEnabled");
		properties["enabled"] = StrFromInt(bEnabled == VARIANT_TRUE);
	};
}

inline RASecFirewall::FwRuleAccessor::Setters::Setters()
{
	Setters &setters = *this;

	setters["ruleName"] = [this](const String &value, INetFwRule *pRule) mutable
	{
		ThrowIfError(pRule->put_Name(CComBSTR(value.getBuffer())), "SetRuleName");
	};
	setters["groupName"] = [this](const String &value, INetFwRule *pRule) mutable
	{
		ThrowIfError(pRule->put_Grouping(CComBSTR(value.getBuffer())), "SetGroupName");
	};
	setters["applicationName"] = [this](const String &value, INetFwRule *pRule) mutable
	{
		ThrowIfError(pRule->put_ApplicationName(CComBSTR(value.getBuffer())), "SetApplicationName");
	};
	setters["remoteAddresses"] = [this](const String &value, INetFwRule *pRule) mutable
	{
		ThrowIfError(pRule->put_RemoteAddresses(CComBSTR(value.getBuffer())), "SetRemoteAddresses");
	};
	setters["profiles"] = [this](const String &value, INetFwRule *pRule) mutable
	{
		long profiles = StrToInt(value);
		ThrowIfError(pRule->put_Profiles(profiles), "SetProfiles");
	};
	setters["action"] = [this](const String &value, INetFwRule *pRule) mutable
	{
		NET_FW_ACTION currentAction = NET_FW_ACTION(StrToInt(value));
		ThrowIfError(pRule->put_Action(currentAction), "SetAction");
	};
	setters["direction"] = [this](const String &value, INetFwRule *pRule) mutable
	{
		NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIRECTION(StrToInt(value));
		ThrowIfError(pRule->put_Direction(direction), "SetDirection");
	};
	setters["enabled"] = [this](const String &value, INetFwRule *pRule) mutable
	{
		VARIANT_BOOL enabled = StrToInt(value) == 0 ? 0 : -1;
		ThrowIfError(pRule->put_Enabled(enabled), "SetEnabled");
	};
}




inline RASecFirewall::FwPolicyAccessor::FwPolicyAccessor()
{
	HRESULT hr;

	// Instantiate firewall policy.
	if (FAILED(hr = m_spPolicy.CoCreateInstance(__uuidof(NetFwPolicy2))))
	{
		throw AppException(hr, "RASecAccount::updateFirewallAccess@InstantiatePolicy");
	}

	// Query firewall rules.
	CComPtr<INetFwRules> spRules;
	if (FAILED(hr = m_spPolicy->get_Rules(&m_spCollection)))
	{
		throw AppException(hr, "RASecAccount::updateFirewallAccess@GetRules");
	}
}

inline RASecFirewall::FwRuleAccessor RASecFirewall::FwPolicyAccessor::getRule(const String &ruleName)
{
	CComPtr<INetFwRule> spRule;
	HRESULT hr = m_spCollection->Item(CComBSTR(ruleName.getBuffer()), &spRule);
	if (hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
	{
		ThrowIfError(hr, "GetItem");
	}
	return spRule;
}

inline void RASecFirewall::FwPolicyAccessor::forEachRule(std::function<bool(FwRuleAccessor &)> &&iterFunc)
{
	IUnknown *punk;
	ThrowIfError(m_spCollection->get__NewEnum(&punk), "GetNewEnumerator");

	CComPtr<IEnumVARIANT> spEnumerator;
	ThrowIfError(punk->QueryInterface(__uuidof(IEnumVARIANT), (void **)&spEnumerator), "QueryVariantEnumerator");

	HRESULT hr;
	ULONG nFetched;
	CComVariant var;
	while ((hr = spEnumerator->Next(1, &var, &nFetched)) != S_FALSE)
	{
		if (FAILED(hr))
		{
			throw AppException(hr, "EnumeratorNextRule");
		}

		// Query rule interface.
		CComPtr<INetFwRule> spRule;
		ThrowIfError(var.ChangeType(VT_DISPATCH), "ChangeType");
		ThrowIfError((V_DISPATCH(&var))->QueryInterface(__uuidof(INetFwRule), reinterpret_cast<void **>(&spRule)), "QueryRuleInterface");

		FwRuleAccessor rule(spRule);
		if (!iterFunc(rule))
		{
			break;
		}
	}
}

inline void RASecFirewall::FwPolicyAccessor::createRule(const StrPropertyMap &params)
{
	CComPtr<INetFwRule> spRule;
	ThrowIfError(spRule.CoCreateInstance(__uuidof(NetFwRule)), "CreateFwRule");

	FwRuleAccessor rule(spRule);
	rule.assign(params);

	ThrowIfError(spRule->put_Direction(NET_FW_RULE_DIR_IN), "CreateFwRule::SetAction");
	ThrowIfError(spRule->put_Enabled(VARIANT_TRUE), "CreateFwRule::SetEnabled");

	ThrowIfError(m_spCollection->Add(spRule), "CreateFwRule::AddRule");
}

inline void RASecFirewall::FwPolicyAccessor::deleteRule(const String &ruleName)
{
	ThrowIfError(m_spCollection->Remove(CComBSTR(ruleName.getBuffer())), "CreateFwRule::AddRule");
}
