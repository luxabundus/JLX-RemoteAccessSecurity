#pragma once


//////////////////////////////////////////////////////////////////////
// class RASecHomeService
//

class RASecHomeService : public WapiService
{
public:
	RASecHomeService();

protected:
	virtual bool initInstance();

	DECLARE_HTTP_MAP()

	void onRegisterServer(HttpContext &context);
	void onValidateServer(HttpContext &context);

	void onGetAccount(HttpContext &context);
	void onCreateAccount(HttpContext &context);

private:
	String newId();
	String validateAccountName(const String &accountName);
};


inline String RASecHomeService::newId()
{
	return UniqueId::NewString(true);
}

