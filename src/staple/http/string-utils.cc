#include <strings.h>
#include <stdio.h>
#include <algorithm>

#include "string-utils.h"

using std::string;

string quoteString(const Byte* begin, const Byte* end)
{
	string r;
	for (; begin != end; ++begin) {
		char c = *begin;
		if (isalnum(c) || ispunct(c) || c == ' ')
			r.push_back(c);
		else if (c == '\t')
			r.append("\\t");
		else if (c == '\r')
			r.append("\\r");
		else if (c == '\f')
			r.append("\\f");
		else if (c == '\n')
			r.append("\\n");
		else {
			char buf[8];
			sprintf(buf, "\\x%02x", (unsigned char) c);
			r.append(buf);
		}
	}

	return r;
}

string percent(long long part, long long total)
{
	if (total == 0) {
		return "undefined %";
	} else {
		char buf[16];
		snprintf(buf, sizeof(buf), "%.1f%%", double(part*100)/total);
		return string(buf);
	}
}

URL::URL(const string& url)
{
	// Find end of schema.
	string::const_iterator s = url.begin();
	while (s != url.end() && isalpha(*s))
		++s;

	if (s == url.end() || *s != ':') {
		// No schema found, assume host starts at start of
		// URL.
		hasSchema_ = false;
		s = url.begin();
	} else {
		schema_ = string(url.begin(), s);
		hasSchema_ = true;

		// Find end of schema.
		++s; // Skip ':'
		while (s != url.end() && *s == '/')
			++s;
	}
	string::const_iterator e = s;
	// Find end of host
	while (e != url.end() && *e != '/')
		++e;
	host_ = string(s, e);
	path_ = string(e, url.end());
}
