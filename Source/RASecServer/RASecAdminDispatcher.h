#pragma once


//////////////////////////////////////////////////////////////////////
// class RASecAdminDispatcher
//

class RASecAdminDispatcher : public RASecDispatcher
{
public:
	RASecAdminDispatcher(RASecService *service);
	virtual ~RASecAdminDispatcher();

	virtual bool initInstance();

	bool uninstall();

protected:
	void authenticateUser(HttpContext &context);
	void getFilterParams(HttpContext &context, StrPropertyMap &params);
	void addSentinel(RASecDbRequest &dbRequest, const StrPropertyMap &params, bool force);

	DECLARE_HTTP_MAP();

	void onQueryHelp(HttpContext &context);
	void onListFilters(HttpContext &context);
	void onAllowRule(HttpContext &context);
	void onBlockRule(HttpContext &context);
	void onDropRule(HttpContext &context);
	void onSyncRules(HttpContext &context);
	void onRegisterServer(HttpContext &context);
};

