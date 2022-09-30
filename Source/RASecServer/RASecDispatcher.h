#pragma once


class RASecService;


//////////////////////////////////////////////////////////////////////
// class RASecDispatcher
//

class RASecDispatcher : public HttpDispatcher
{
public:
	RASecDispatcher(RASecService *service);

	virtual bool initInstance();
	virtual void exitInstance();

protected:
	RASecService *m_service;
	RASecFirewall *m_firewall;
};
