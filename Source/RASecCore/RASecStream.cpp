#include "pch.h"
#include "RASecStream.h"


bool RASecStream::isSecure() const
{
	return true;
}


bool RASecStream::beginConnect(
	const char *address,
	IoContext *context,
	iofunc_t &&onConnect)
{
	IoFuncArg onComplete(onConnect);

	return __super::beginConnect(
		address, context,
		[this, onComplete](IoContext *context) mutable
		{
			if (context->confirmSuccess(onComplete))
			{
				sendClientToken(context, onComplete);
			}
		}
	);
}

void RASecStream::sendClientToken(IoContext *context, IoFuncArg onComplete)
{
	m_transportKey = createTransportToken();

	if (!TcpStream::beginWrite(m_transportKey, TRANSPORT_TOKEN_LENGTH, context,
		[this, onComplete](IoContext *context) mutable
		{
			if (context->confirmSuccess(onComplete))
			{
				validateServerToken(context, onComplete);
			}
		}
	))
	{
		context->callIoError(System::Error(), onComplete);
	}
}

void RASecStream::validateServerToken(IoContext *context, IoFuncArg &onComplete)
{
	m_transportKey.grow(TRANSPORT_TOKEN_LENGTH);
	if (!TcpStream::beginRead(m_transportKey.getData(TRANSPORT_TOKEN_LENGTH), TRANSPORT_TOKEN_LENGTH, context,
		[this, onComplete](IoContext *context) mutable
		{
			size_t count;
			if (context->confirmSuccess(onComplete, count))
			{
				if (count != TRANSPORT_TOKEN_LENGTH)
				{
					context->callIoError(ERROR_INVALID_DATA, onComplete);
				}
				else if (!validateTransportToken(m_transportKey, TRANSPORT_TOKEN_LENGTH))
				{
					context->callIoError(ERROR_INVALID_DATA, onComplete);
				}
				else
				{
					context->callIoComplete(onComplete);
				}
			}
		}
	))
	{
		context->callIoError(System::Error(), onComplete);
	}
}


bool RASecStream::beginAuthenticate(
	IoContext *context,
	iofunc_t &&onAuth)
{
	IoFuncArg onComplete(onAuth);

	return (TcpStream::beginAuthenticate(context,
		[this, onComplete](IoContext *context) mutable
		{
			if (context->confirmSuccess(onComplete))
			{
				validateClientToken(context, onComplete);
			}
		}
	));
}

void RASecStream::validateClientToken(IoContext *context, IoFuncArg onComplete)
{
	m_transportKey.alloc(TRANSPORT_TOKEN_LENGTH);
	if (!TcpStream::beginRead(m_transportKey, TRANSPORT_TOKEN_LENGTH, context,
		[this, onComplete](IoContext *context) mutable
		{
			size_t count;
			if (context->confirmSuccess(onComplete, count))
			{
				if (count != TRANSPORT_TOKEN_LENGTH)
				{
					context->callIoError(ERROR_INVALID_DATA, onComplete);
				}
				else if (!validateTransportToken(m_transportKey))
				{
					context->callIoError(ERROR_INVALID_DATA, onComplete);
				}
				else
				{
					sendServerToken(context, onComplete);
				}
			}
		}
	))
	{
		context->callIoError(System::Error(), onComplete);
	}
}

void RASecStream::sendServerToken(IoContext *context, IoFuncArg &onComplete)
{
	RASecKey serverToken = createTransportToken();
	m_transportKey.append(serverToken);

	if (!TcpStream::beginWrite(m_transportKey.getData(TRANSPORT_TOKEN_LENGTH), TRANSPORT_TOKEN_LENGTH, context,
		[this, onComplete](IoContext *context) mutable
		{
			size_t count;
			if (context->confirmSuccess(onComplete, count))
			{
				if (count != TRANSPORT_TOKEN_LENGTH)
				{
					context->callIoError(ERROR_INVALID_DATA, onComplete);
				}
				else
				{
					context->callIoComplete(onComplete);
				}
			}
		}
	))
	{
		context->callIoError(System::Error(), onComplete);
	}
}


TcpStream *RASecStream::createServerStream()
{
	return new RASecStream;
}


bool RASecStream::beginRead(
	void *buffer,
	size_t size,
	IoContext *context,
	iofunc_t &&onRead)
{
	IoFuncArg onComplete(onRead);

	return __super::beginRead(
		buffer, size, context,
		[this, cbuf = (char*)buffer, netSelectMode = m_netSelectMode, onComplete](IoContext *context) mutable
		{
			size_t count;
			if (context->confirmSuccess(onComplete, count))
			{
				if (netSelectMode == SELECT_RECEIVED)
				{
					cbuf++;
					count--;
				}

				m_transportKey.transform(cbuf, cbuf, count, m_readOffset);
				m_readOffset += count;
				context->callIoComplete(onComplete);
			}
		}
	);
}


bool RASecStream::beginWrite(
	const void *buffer,
	size_t size,
	IoContext *context,
	iofunc_t &&onWrite)
{
	IoFuncArg onComplete(onWrite);

	m_writeBuffer.alloc(size);
	m_transportKey.transform(m_writeBuffer, buffer, size, m_writeOffset);

	return __super::beginWrite(
		m_writeBuffer, size, context,
		[this, onComplete](IoContext *context) mutable
		{
			m_writeBuffer.free();

			size_t count;
			if (context->confirmSuccess(onComplete, count))
			{
				m_writeOffset += count;
				context->callIoComplete(onComplete);
			}
		}
	);
}



//////////////////////////////////////////////////////////////////////////
// class RASecProtocol
//

NetStream *RASecProtocol::createStream()
{
	return new RASecStream;
}


bool RASecProtocol::Initialize()
{
	return Network::RegisterProtocol("rasec", new RASecProtocol);
}