#include "pch.h"
#include "RASecFirewall.h"


//////////////////////////////////////////////////////////////////////////
// class RASecFirewall
//

RASecFirewall::FwRuleAccessor::Getters RASecFirewall::FwRuleAccessor::sm_getters;
RASecFirewall::FwRuleAccessor::Setters RASecFirewall::FwRuleAccessor::sm_setters;


RASecFirewall::RASecFirewall()
{
	::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
}

RASecFirewall::~RASecFirewall()
{
	::CoUninitialize();
}


void RASecFirewall::updateAccess()
{
	m_updateEvent.set();
}


bool RASecFirewall::initInstance()
{
	if (!install())
	{
		return false;
	}

	// Start the update thread.
	m_updateEvent.set();

	m_updateThread = std::thread(
		[this]() mutable
		{
			while (m_updateEvent.wait() && !Application::Instance()->waitForExit(0))
			{
				try
				{
					iterateAccessRules();
				}
				catch (Exception &x)
				{
					AppLog::Error("RASecFirewall::iterateAccessRules - %s", x.getErrorString());
				}

				m_updateEvent.reset();
			}
		}
	);

	return m_updateThread.joinable();
}

void RASecFirewall::exitInstance()
{
	if (m_updateThread.joinable())
	{
		m_updateEvent.set();
		m_updateThread.join();
	}
}



bool RASecFirewall::install()
{
	try
	{
		bool exists = false;
		String appFilePath = System::GetModulePath();

		FwPolicyAccessor policy;
		policy.forEachRule([&exists, &appFilePath](FwRuleAccessor &rule) mutable
			{
				StrPropertyMap current;
				rule.select(current, "ruleName,groupName,applicationName");

				if ((current["ruleName"] == RASec::CLIENT_RULE_NAME)
					&& (current["groupName"] == RASec::CLIENT_RULE_GROUPING)
					&& (current["applicationName"].compareNoCase(appFilePath) == 0))
				{
					exists = true;
					return false;
				}
				else
				{
					return true;
				}
			}
		);

		if (!exists)
		{
			StrPropertyMap params;
			params["ruleName"] = RASec::CLIENT_RULE_NAME;
			params["groupName"] = RASec::CLIENT_RULE_GROUPING;
			params["applicationName"] = appFilePath;

			// Insert the allower.
			params["action"] = StrFromInt(NET_FW_ACTION_ALLOW);
			policy.createRule(params);

			// Insert the restrictor.
			params["action"] = StrFromInt(NET_FW_ACTION_BLOCK);
			params["remoteAddresses"] = RASec::SENTINEL_ADDRESS;
			policy.createRule(params);
		}
	}
	catch (Exception &x)
	{
		AppLog::Error("RASecFirewall::install - %s", x.getErrorString());
		return false;
	}

	return true;
}


bool RASecFirewall::uninstall()
{
	try
	{
		FwPolicyAccessor policy;
		policy.deleteRule(RASec::CLIENT_RULE_NAME);
	}
	catch (Exception &x)
	{
		AppLog::Error("RASecFirewall::uninstall - %s", x.getErrorString());
		return false;
	}

	return true;
}


void RASecFirewall::iterateAccessRules()
{
	bool deleteUnloaded = false;
	bool resetForced = false;

	RASecDbRequest dbRequest;
	dbRequest.beginSession();

	FwPolicyAccessor policy;

	SyncLock lock(m_updateMutex);

	policy.forEachRule(
		[this, &dbRequest](FwRuleAccessor &rule) mutable
		{
			StrPropertyMap current;
			rule.select(current, "ruleName,groupName,direction,remoteAddresses");

			static const String INBOUND_DIRECTION = StrFromInt(NET_FW_RULE_DIR_IN);
			if (current["direction"] != INBOUND_DIRECTION)
			{
				return true;
			}

			// Query candidate ip-addresses for this rule.
			dbRequest.params = current;
			DbResponse dbResponse = dbRequest.exec(
				"select distinct "
					"(a.ipAddress || '/255.255.255.255') as ipAddress, "
					"f.forced "
				"from RasFilter f "
					"inner join RasAccess a "
						"on f.accountId is null "
							"or f.accountId = a.accountId "
				"where (f.ruleName is null or f.ruleName = '@ruleName') "
					"and (f.groupName is null or f.groupName = '@groupName') "
				"order by a.ipAddress");
			if (dbResponse.failed())
			{
				dbResponse.logError("RASecFirewall::applyAccessRules@SelectIPAddresses");
				return true;
			}

			// Collect addresses.
			bool forced = false;
			StringArray addressList;
			while (dbResponse.fetchNext())
			{
				addressList.add(dbResponse["ipAddress"]);
				if (dbResponse["forced"] == "1")
				{
					// Enable forced processing for this rule.
					forced = true;
				}
			}

			// Skip this rule if there are no assigned addresses.
			if (!addressList.isEmpty())
			{
				// Build string version of address list.
				String newRemoteAddresses = StrJoin(addressList, ",");

				// Get this rule's current settings.
				rule.select(
					current, 
					"applicationName,serviceName,profiles,protocol,"
						"localAddresses,localPorts,remoteAddresses,remotePorts,"
						"action,enabled");

				// Build the restore key based on the rule's current settings.
				String restoreKey = buildRestoreKey(current);

				// Query update actions for given restore key.
				dbRequest["restoreKey"] = restoreKey;
				dbResponse = dbRequest.exec(
					"select ignored, unloaded, action, enabled, remoteAddresses "
					"from RasRestore "
					"where restoreKey = '@restoreKey' ");
				if (dbResponse.failed())
				{
					dbResponse.logError("RASecFirewall::iterateAccessRules@SelectRestore");
					return true;
				}

				// Not yet registered; try adding a restore entry now.
				if (!dbResponse.fetchNext())
				{
					// Validate the rule's current remote-address setting.
					String currentRemoteAddresses = current["remoteAddresses"];

					// First, check if we're forcing this rule.
					if (!forced
						// By default, we don't manage any rule that has pre-existing 
						// remote-address values, i.e., it must be Any (*).
						&& (currentRemoteAddresses != "*")
						// Check if the rule was managed by a previous registration,
						// i.e., contains a sentinel address.
						&& (currentRemoteAddresses.findFirst(RASec::SENTINEL_ADDRESS) < 0))
					{
						// Skip this rule.
						return true;
					}

					// Insert the restore entry.
					dbRequest.params = current;
					dbRequest["restoreKey"] = restoreKey;
					dbResponse = dbRequest.execInsert("RasRestore");
					if (dbResponse.failed())
					{
						dbResponse.logError("RASecFirewall::iterateAccessRules@InsertRestore");
						return true;
					}
				}

				// Handle an unloaded filter (i.e., via DROP).
				if (dbResponse["unloaded"] == "1")
				{
					try
					{
						// Restore previous settings.
						current["remoteAddresses"] = dbResponse["remoteAddresses"];
						current["action"] = dbResponse["action"];
						current["enabled"] = dbResponse["enabled"];

						rule.assign(current);
					}
					catch (Exception &x)
					{
						AppLog::Error("RASecFirewall::iterateAccessRules@AssignUnloadedRule - %s", x.getErrorString());
					}
				}

				// Skip if this rule is ignored, i.e., mainly for those with errors from previous attempt(s).
				else if (dbResponse["ignored"] != "1")
				{
					// Collect new update parameters.
					StrPropertyMap update;

					// Update addresses only if they've changed.
					if (newRemoteAddresses != current["remoteAddresses"])
					{
						update["remoteAddresses"] = newRemoteAddresses;
					}

					// Update action only if not currently ALLOW.
					static const String ALLOW_ACTION = StrFromInt(NET_FW_ACTION_ALLOW);
					if (current["action"] != ALLOW_ACTION)
					{
						update["action"] = ALLOW_ACTION;
					}

					// Enable the rule if currently disabled.
					if (current["enabled"] != "-1")
					{
						update["enabled"] = "-1";
					}

					// Skip if nothing to update.
					if (!update.isEmpty())
					{
						try
						{
							rule.assign(update);
						}
						catch (Exception &x)
						{
							AppLog::Error(
								"RASecFirewall::iterateAccessRules@Assign(%s)\n%s", 
								current["ruleName"], 
								x.getErrorString());

							// If an error occurred, mark this rule as ignored.
							dbRequest["restoreKey"] = restoreKey;
							dbResponse = dbRequest.exec(
								"update RasRestore "
								"set ignored = 1 "
								"where restoreKey = '@restoreKey'");
							if (dbResponse.failed())
							{
								dbResponse.logError("RASecFirewall::iterateAccessRules@UpdateIgnoredRule");
							}

							// Restore the rule's original settings.
							try
							{
								rule.assign(current);
							}
							catch (Exception &)
							{
								// Silently discard errors from restoration, which would probably
								// be the same as the one above.
							}
						}
					}
				}
			}

			return true;
		}
	);

	// Cleanup "unloaded" and "forced" filters.
	DbResponse dbResponse = dbRequest.exec(
		"select count(*) as count "
		"from RasFilter "
		"where unloaded = 1 or forced = 1");
	if (dbResponse.failed())
	{
		dbResponse.logError("RASecAdminDispatcher::onRemoveRule@QueryUnloadedOrForcedFilters");
	}
	else if (dbResponse["count"] != "0")
	{
		dbResponse = dbRequest.execDelete("RasFilter", "where unloaded = 1");
		if (dbResponse.failed())
		{
			dbResponse.logError("RASecAdminDispatcher::onRemoveRule@DeleteUnloadedRule");
		}

		dbResponse = dbRequest.execDelete("RasRestore", "where unloaded = 1");
		if (dbResponse.failed())
		{
			dbResponse.logError("RASecFirewall::iterateAccessRules@DeleteUnloadedRestore");
		}

		dbRequest["forced"] = "0";
		dbResponse = dbRequest.execUpdate("RasFilter", "where forced = 1");
		if (dbResponse.failed())
		{
			dbResponse.logError("RASecFirewall::iterateAccessRules@ResetForcedFilters");
		}
	}
}
