#ifndef HTTP_HELPERS_H
#define HTTP_HELPERS_H

/* This file contains some functions and macros that are used when
 * HTTP is parsed.
 */

#include <assert.h>
#include <vector>
#include <staple/Type.h>
#include <staple/http/log.h>
#include "HTTPMsg.h"

/* The HTTP parsing methods all follow the same pattern. The first two
 * arguments (typically named 'buf' and 'end) represents a range [buf,
 * end). The method parses something in [buf, end) and returns NULL if
 * the parsing failed and some pointer 'ptr' within [buf, end]
 * otherwise. In the latter case the parsing should resume at 'ptr'. A
 * postcondition for these methods is that the return value is either
 * NULL or contained in [buf, end]. The Range struct and the
 * CHECKED_RETURN macro below helps us check this postcondition
 * whenever we return from one of these methods.
 */
struct HTTPRange
{
	HTTPRange(const Byte* s, const Byte* e) : start(s), end(e) { }

	const Byte *start;
	const Byte *end;
};

#define CHECKED_RETURN_INIT(start, end)		\
	assert(start <= end);			\
	HTTPRange range__(start, end);

#define CHECKED_RETURN(x)						\
	do {								\
		const Byte* returnVal = x;				\
		if (returnVal == NULL ||				\
		    (range__.start <= returnVal &&			\
		     returnVal <= range__.end)) {			\
			return returnVal;				\
		} else {						\
			logStderr(__func__, ": range check failed."	\
				  " x: ", (void*) returnVal,		\
				  " start: ", (void*) range__.start,	\
				  " end: " , (void*) range__.end,	\
				  quoteString(range__.start,		\
					      range__.end));		\
			assert(false);					\
		}							\
	} while (0)

const Byte* skipSpace(const Byte* buf, const Byte* end);

/* Find CRLF sequence in [buf, end). Return end if not found and
 * pointer to start of CRLF otherwise. */
const Byte* findCRLF(const Byte* buf, const Byte* end);

/* Only a subset of all headers are parsed by parseHeader. This
 * function return true if a header is parsed and false if it is
 * ignored.
 */
bool isHeaderParsed(const std::string& name);

/* Parse a HTTP header in [buf, end). Return NULL if not possible,
 * otherwise return pointer to area where parsing can resume. If not
 * NULL is returned, a header is added to headers is filled in. */
const Byte* parseHeader(const Byte* buf, const Byte* end, HTTPHeaders* headers);
#endif
