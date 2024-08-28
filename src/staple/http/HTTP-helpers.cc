#include <algorithm>
#include <ctype.h>

#include "HTTP-helpers.h"
#include "string-utils.h"

using std::vector;
using std::string;

const Byte* skipSpace(const Byte* buf, const Byte* end)
{
	while (buf != end && *buf == ' ')
		buf++;
	return buf;
}

const Byte* findCRLF(const Byte* buf, const Byte* end)
{
	CHECKED_RETURN_INIT(buf, end);
	const Byte crlf[] = {'\r', '\n'};
	CHECKED_RETURN(std::search(buf, end, crlf, crlf+2));
}

/* True, if c can appear in the name of a HTTP header. */
static bool isHeaderChar(Byte c)
{
	return isalnum(c) || c == '-' || c == '_';
}

/* This list must be sorted! */
static const char* parsedHeaders[] = {
	"cache-control",
	"content-encoding",
	"content-length",
	"content-type",
	"host",
	"location",
	"referer",
	"transfer-encoding",
	"user-agent",
};
static const size_t parsedHeadersSize = sizeof(parsedHeaders) / sizeof(parsedHeaders[0]);

/* Hint on the number of headers we typically see. Use in call to
 * vector::reserve below.
 */
static const size_t numHeadersHint = 6;

struct StringLess
{
	bool operator() (const char* s1, const char* s2)
		{
			return strcmp(s1, s2) < 0;
		}
};

static const char* findHeader(const Byte* start, const Byte* end)
{
	/* We don't have any header names longer than 32 in
	 * parsedHeaders.
	 */
	char buf[32];
	if (end - start > (int) sizeof(buf)-1)
		return NULL;
	int i;
	for (i = 0; start+i != end; i++)
		buf[i] = tolower(*(start+i));
	buf[i] = 0;

	StringLess sl;
	const char** h = std::lower_bound(parsedHeaders, parsedHeaders+parsedHeadersSize, buf, sl);
	if (h == parsedHeaders+parsedHeadersSize)
		return NULL;
	else if (!strcmp(*h, buf))
		return *h;
	else
		return NULL;
}

bool isHeaderParsed(const string& name)
{
	const char* s = name.c_str();
	return findHeader((const Byte*) s, (const Byte*) s + name.size());
}

const Byte* parseHeader(const Byte* buf, const Byte* end, HTTPHeaders* headers)
{
	CHECKED_RETURN_INIT(buf, end);
	const Byte* ptr = buf;
	while (ptr != end && isHeaderChar(*ptr))
		ptr++;

	if (ptr == end || *ptr != ':')
		return NULL;

	const char* name = findHeader(buf, ptr);

	assert(*ptr == ':');
	ptr++; // Skip ':'
	const Byte* endCRLF = findCRLF(ptr, end);
	if (endCRLF == end)
		return NULL;
	if (!name)
		CHECKED_RETURN(endCRLF+2);
	ptr = skipSpace(ptr, endCRLF);
	const Byte* e = endCRLF;
	while (e != ptr && *e == ' ')
		e--;

	headers->reserve(numHeadersHint);
	headers->push_back(HTTPHeader(name, string(ptr, e)));
	CHECKED_RETURN(endCRLF+2);
}
