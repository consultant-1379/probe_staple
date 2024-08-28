#ifndef IPADDRESS_H
#define IPADDRESS_H

#include <staple/Type.h>

/* A IPAddress class that can be used in both ordered and unordered
 * sets and maps without any preprocessor magic. */
class IPAddress
{
public:
	explicit IPAddress(const DoubleWord& ip);
	IPAddress();

	bool operator<(const IPAddress&) const;
	const DoubleWord& getIP() const { return IP; }
	friend std::istream& operator>>(std::istream&, IPAddress&);

private:
	DoubleWord        IP;
};

bool operator==(const IPAddress&, const IPAddress&);
std::ostream& operator<<(std::ostream&, const IPAddress&);
std::istream& operator>>(std::istream&, IPAddress&);

inline std::size_t hash_value(const IPAddress& ip)
{
        return ip.getIP().data;
}

namespace std {
	template <>
		struct hash<IPAddress>
		{
			typedef IPAddress argument_type;
			typedef std::size_t result_type;

			std::size_t operator() (const IPAddress& ip) const
				{
					return hash_value(ip);
				}
		};
}

#endif
