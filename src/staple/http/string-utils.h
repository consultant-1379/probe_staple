#ifndef STRINGUTILS_H
#define STRINGUTILS_H

#include <string>
#include <sstream>
#include <staple/Type.h>

template<typename T>
std::string toString(const T& x)
{
	std::stringstream ss;
	ss << x;
	return ss.str();
}

std::string percent(long long part, long long total);
std::string quoteString(const Byte* begin, const Byte* end);

class URL {
public:
	URL(const std::string& url);

	/* Return true if URL has a schema, otherwise false. */
	bool hasSchema() const { return hasSchema_; }

	/* Return schema if available otherwise an empty string is
	 * returned.
	 */
	std::string getSchema() const { return schema_; }

       /* Return host part of URL. The port number, if available, is
        * considered a part of the host. If no schema is found, the
        * host name is assumed to start at the beginning of the
        * string.
        */
	std::string getHost() const { return host_; }

	/* Return everything after host. */
	std::string getPath() const { return path_; }

private:
	std::string schema_, host_, path_;
	bool hasSchema_;
};

#endif
