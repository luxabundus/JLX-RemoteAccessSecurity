#pragma once
#include "RASecClientDispatcher.h"
#include "RASecAdminDispatcher.h"


//////////////////////////////////////////////////////////////////////
// class RASecService
//

class RASecService : public WapiService
{
public:
	RASecService();
	virtual ~RASecService();

	RASecFirewall *getFirewall();

	bool isRegistered();
	void approveRegistration(const String &accountName);
	String getRegistrationKey();

	virtual int run(int argc, char *argv[], char *envp[]);

protected:
	virtual bool initInstance();
	bool initIdentity();
	bool initDatabase();

	virtual void exitInstance();

private:
	UniqueId m_machineId;
	bool m_isRegistered;
	RASecFirewall *m_firewall;
	RASecAdminDispatcher *m_adminDispatcher;
	RASecClientDispatcher *m_clientDispatcher;

private:
	int uninstall();
};


inline RASecFirewall *RASecService::getFirewall()
{
	return m_firewall;
}

inline bool RASecService::isRegistered()
{
	return m_isRegistered;
}

inline String RASecService::getRegistrationKey()
{
	return m_machineId.toString(true);
}
