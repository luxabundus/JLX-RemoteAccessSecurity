#include "pch.h"
#include "RASecServer.h"
#include "RASecDispatcher.h"


//////////////////////////////////////////////////////////////////////
// class RASecDispatcher
//

RASecDispatcher::RASecDispatcher(RASecService *service) :
	m_service(service),
	m_firewall(service->getFirewall())
{
}


bool RASecDispatcher::initInstance()
{
	return true;
}


void RASecDispatcher::exitInstance()
{
	stopAllListeners();
}
