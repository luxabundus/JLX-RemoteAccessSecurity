#pragma once


//////////////////////////////////////////////////////////////////////
// class SysUserManager
//

class SysUserManager
{
public:
	SysUserManager();
	~SysUserManager();

	bool open(const String &domain = nullptr);
	bool createLocalGroup(const String &groupName, const String &comment = nullptr);

private:
	LPWSTR m_pszPrimaryDC;

private:
	class wstr
	{
		wchar_t *m_data;

	public:
		wstr()
		{
			m_data = nullptr;
		}
		wstr(const String &str)
		{
			assign(str);
		}
		~wstr()
		{
			delete[] m_data;
		}

		wchar_t *assign(const String &str)
		{
			int len = (int)str.getLength() + 1;
			m_data = new wchar_t[len];

			::MultiByteToWideChar(
				CP_UTF8,
				0,
				str,
				len,
				m_data,
				len);

			return m_data;
		}

		operator wchar_t *()
		{
			return m_data;
		}

		wstr &operator = (const String &str)
		{
			assign(str);
			return *this;
		}
	};
};

