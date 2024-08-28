#include <string.h>
#include <ctype.h>

#include "boost-reimplementation.h"


bool iends_with(const char* s, const char* test)
{
	int sLen = strlen(s);
	int testLen = strlen(test);

	if (sLen < testLen)
		return false;

	const char* sEnd = s + sLen;
	s = sEnd - testLen;

	for (; s != sEnd; s++, test++) {
		if (tolower(*s) != tolower(*test))
			return false;
	}

	return true;
}

bool starts_with(const char* s, const char* test)
{
	for (; *s != '\0' && *test != '\0'; s++, test++) {
		if (*s != *test)
			return false;
	}

	if (*test == '\0')
		return true;
	else
		return false;
}

bool iequals(const char* s1, const char* s2)
{
	return !strcasecmp(s1, s2);
}
