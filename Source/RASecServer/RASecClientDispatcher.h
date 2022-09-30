#pragma once


//////////////////////////////////////////////////////////////////////
// class RASecClientDispatcher
//

class RASecClientDispatcher : public RASecDispatcher
{
public:
	RASecClientDispatcher(RASecService *service);

	virtual bool initInstance();

	bool uninstall();

protected:
	void authenticateUser(HttpContext &context, String &accountId, String &deviceId);

	DECLARE_HTTP_MAP()

	void onRegisterClientAccess(HttpContext &context);
	void onUnregisterClientAccess(HttpContext &context);
};

