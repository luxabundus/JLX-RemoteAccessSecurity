#pragma once
#include <JlxCore/TcpStream.h>
#include "RASecKey.h"


//////////////////////////////////////////////////////////////////////
// class RASecStream
//

class RASecStream : public TcpStream
{
	RASecKey m_transportKey;
	size_t m_readOffset;
	size_t m_writeOffset;
	ByteBuffer m_writeBuffer;

public:
	const size_t TRANSPORT_SEED_LENGTH = 16;
	const size_t TRANSPORT_TOKEN_LENGTH = TRANSPORT_SEED_LENGTH * 2;
	const size_t TRANSPORT_KEY_LENGTH = TRANSPORT_TOKEN_LENGTH * 2;

	RASecStream() :
		m_readOffset(0),
		m_writeOffset(0)
	{
	}

	virtual bool isSecure() const;

	virtual bool beginConnect(
		const char *address,
		IoContext *context,
		iofunc_t &&onConnect = nullptr);

	virtual bool beginAuthenticate(
		IoContext *context,
		iofunc_t &&onAuth = nullptr);

	virtual bool beginRead(
		void *buffer,
		size_t size,
		IoContext *context,
		iofunc_t &&onRead = nullptr);
	virtual bool beginWrite(
		const void *buffer,
		size_t size,
		IoContext *context,
		iofunc_t &&onWrite = nullptr);

protected:
	virtual TcpStream *createServerStream();

	RASecKey createTransportToken(
		const RASecKey &seed = UniqueId::New())
	{
		RASecKey alter(seed);
		RASecKey::MASTER.transform(alter);

		RASecKey transport;
		transport.append(seed);
		transport.append(alter);
		return std::move(transport);
	}
	bool validateTransportToken(const RASecKey &sourceToken, size_t offset = 0)
	{
		RASecKey validatorSeed(sourceToken.getData(offset), TRANSPORT_SEED_LENGTH);
		RASecKey validatorToken = createTransportToken(validatorSeed);
		return validatorToken.equals(sourceToken.getData(offset), TRANSPORT_TOKEN_LENGTH);
	}

	void sendClientToken(IoContext *context, IoFuncArg onComplete);
	void validateServerToken(IoContext *context, IoFuncArg &onComplete);

	void validateClientToken(IoContext *context, IoFuncArg onComplete);
	void sendServerToken(IoContext *context, IoFuncArg &onComplete);
};


//////////////////////////////////////////////////////////////////////////
// class RASecProtocol
//

class RASecProtocol : public TcpProtocol
{
public:
	virtual NetStream *createStream();

	static bool Initialize();
};

typedef RefPointer<RASecProtocol> RASecProtocolPtr;


