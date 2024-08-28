#include <iostream>
#include <string>
#include <stdio.h>

#include <staple/http/IPAddress.h>

using std::ostream;
using std::istream;
using std::string;

IPAddress::IPAddress(const DoubleWord& ip) : IP(ip)
{ }

IPAddress::IPAddress()
{
	memset(&IP, 0, sizeof(IP));
}

bool IPAddress::operator<(const IPAddress& o) const
{
	return getIP().data < o.getIP().data;
}

bool operator==(const IPAddress& a, const IPAddress& b)
{
	return a.getIP().data == b.getIP().data;
}

// FIXME: Does this work on big-endian machines?
ostream& operator<<(ostream& o, const IPAddress& ip)
{
	o << (unsigned)ip.getIP().byte[3] << "." << (unsigned)ip.getIP().byte[2] << "." << (unsigned)ip.getIP().byte[1] << "." << (unsigned)ip.getIP().byte[0];
	return o;
}

// FIXME: Does this work on big-endian machines?
istream& operator>>(istream& in, IPAddress& ip)
{
	string s;
	in >> s;
	int a, b, c, d;
	int ret = sscanf(s.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d);
	if (ret != 4) {
		in.setstate(istream::failbit);
		return in;
	}

	ip.IP.byte[3] = a;
	ip.IP.byte[2] = b;
	ip.IP.byte[1] = c;
	ip.IP.byte[0] = d;
	return in;
}

