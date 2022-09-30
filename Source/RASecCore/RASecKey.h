#pragma once


//////////////////////////////////////////////////////////////////////
// class RASecKey
//

class RASecKey
{
	char *m_data;
	size_t m_length;

public:
	/* Master Key */
	static RASecKey MASTER;


	RASecKey() :
		m_data(nullptr),
		m_length(0)
	{
	}
	RASecKey(const RASecKey &key) :
		m_data(nullptr),
		m_length(0)
	{
		copy(key);
	}
	RASecKey(RASecKey &&key) noexcept :
		m_data(key.m_data),
		m_length(key.m_length)
	{
		key.m_data = nullptr;
		key.m_length = 0;
	}
	RASecKey(size_t length) :
		m_data(nullptr),
		m_length(0)
	{
		alloc(length);
	}
	RASecKey(void *data, size_t length) :
		m_data(nullptr),
		m_length(0)
	{
		append(data, length);
	}
	RASecKey(const UniqueId &uid) :
		m_data(nullptr),
		m_length(0)
	{
		copy(&uid, sizeof(uid));
	}
	~RASecKey()
	{
		clear();
	}

	operator void *()
	{
		return m_data;
	}
	operator const void *() const
	{
		return m_data;
	}

	RASecKey &operator = (const RASecKey &key)
	{
		copy(key);
		return *this;
	}
	RASecKey &operator = (RASecKey &&key) noexcept
	{
		delete[] m_data;
		m_data = key.m_data;
		m_length = key.m_length;
		key.m_data = nullptr;
		key.m_length = 0;
		return *this;
	}

	char *getData(size_t offset = 0) const
	{
		assert(offset < m_length);
		return m_data + offset;
	}
	size_t getLength() const
	{
		return m_length;
	}

	bool isEmpty() const
	{
		return m_length == 0;
	}

	bool equals(const RASecKey &other) const
	{
		return equals(other.m_data, other.m_length);
	}
	bool equals(void *otherData, size_t otherLength) const
	{
		if (m_length == otherLength)
		{
			return m_length ? memcmp(m_data, otherData, m_length) == 0 : true;
		}
		else
		{
			return false;
		}
	}

	RASecKey &alloc(size_t length)
	{
		delete[] m_data;
		m_length = length;
		m_data = (m_length > 0) ? new char[m_length] : nullptr;
		return *this;
	}
	RASecKey &grow(size_t length)
	{
		size_t newLength = m_length + length;
		char *newData = new char[newLength];
		if (m_data)
		{
			memcpy(newData, m_data, m_length);
			delete[] m_data;
		}
		m_data = newData;
		m_length = newLength;
		return *this;
	}
	RASecKey &copy(const RASecKey &key)
	{
		return copy(key.m_data, key.m_length);
	}
	RASecKey &copy(const void *data, size_t length)
	{
		clear();

		m_length = length;
		if (m_length)
		{
			m_data = new char[m_length];
			memcpy(m_data, data, m_length);
		}
		return *this;
	}
	RASecKey &append(const void *appendData, size_t appendLength)
	{
		if (appendLength > 0)
		{
			size_t newLength = m_length + appendLength;
			char *newData = new char[newLength];
			memcpy(newData, m_data, m_length);
			memcpy(newData + m_length, appendData, appendLength);

			delete[] m_data;
			m_data = newData;
			m_length = newLength;
		}
		return *this;
	}
	RASecKey &append(const RASecKey &key)
	{
		return append(key.m_data, key.m_length);
	}

	void clear()
	{
		delete[] m_data;
		m_data = nullptr;
		m_length = 0;
	}

	void transform(void *dest, const void *source, size_t length, size_t offset = 0) const
	{
		char *chDest = static_cast<char *>(dest);
		const char *chSource = static_cast<const char *>(source);

		for (size_t index = 0, dataIndex = offset - ((offset / m_length) * m_length);
			index < length; 
			index++, dataIndex++)
		{
			if (dataIndex == m_length)
			{
				dataIndex = 0;
			}

			chDest[index] = chSource[index] ^ m_data[dataIndex];
		}
	}
	void transform(RASecKey &key) const
	{
		transform(key.m_data, key.m_data, key.m_length, 0);
	}

	RASecKey &createToken(const RASecKey &seed, const RASecKey &master = MASTER)
	{
		RASecKey alter(seed);
		master.transform(alter);

		clear();
		append(seed);
		append(alter);
		return *this;
	}
};
