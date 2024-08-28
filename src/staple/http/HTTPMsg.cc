#include <vector>
#include <string>
#include <algorithm>
#include <assert.h>

#include <staple/Staple.h>
#include <staple/http/Counter.h>
#include <staple/http/log.h>
#include "HTTPMsg.h"
#include "HTTP-helpers.h"
#include "string-utils.h"
#include "boost-reimplementation.h"

using std::vector;
using std::string;
using std::find;
using std::ostream;

const long HTTPMsg::MAX_CONTENT_LENGTH;
const std::string HTTPMsg::emptyString;

HTTPMsg::HTTPMsg(Staple& staple, const TCPConnId& id) :
	staple_(staple),
	connId_(id),
	reqChunkedParser_(staple),
	rspChunkedParser_(staple)
{
	COUNTER_INCREASE("HTTPMsg constructed");

	reqMethod = NOT_PARSED;
	reqVersion = HTTP_UNDEF;
	reqParseState = REQ_PARSE_START;
	reqTransferEnc = TE_IDENTITY;
	reqLength = 0;
	reqGotBodyLen = 0;

	rspVersion = HTTP_UNDEF;
	rspParseState = RSP_PARSE_START;
	rspStatusCode = 0;
	rspTransferEnc = TE_IDENTITY;
	rspContentEnc = CE_IDENTITY;
	rspGotBodyLen = 0;
	rspLength = -1;
	rspEndOnConnectionClose = false;

	resyncNeeded_ = false;
	doResync_ = false;
	resynced_ = false;

	bytesNetworkDL_ = 0;
	bytesNetworkUL_ = 0;
}

// For some reason, unclear why, we need this empty
// destructor. Otherwise we get segfaults in the destructor for
// std::string.
HTTPMsg::~HTTPMsg()
{ }

void HTTPMsg::finishTCPSession(bool graceful)
{
	if (graceful &&
	    rspEndOnConnectionClose &&
	    rspParseState == RSP_PARSE_BODY)
		rspParseState = RSP_PARSE_COMPLETE;
}

void HTTPMsg::doResynchronization()
{
	assert(reqParseState == REQ_PARSE_START);
	assert(rspParseState == RSP_PARSE_START);

	LOG_AND_COUNT("HTTPMsg::doResynchronization called");
	doResync_ = true;
}

static bool startswith_case(const Byte* begin, const Byte* end, const char* pattern)
{
	for (; begin != end && *pattern != '\0'; begin++, pattern++) {
		if (tolower(*begin) != tolower(*pattern))
			return false;
	}

	return *pattern == '\0';
}

const Byte* HTTPMsg::parseReqMethod(const Byte* buf, const Byte* end, HTTPMsg::Method* m)
{
	assert(buf <= end);
	if (startswith_case(buf, end, "GET ")) *m = GET;
	else if (startswith_case(buf, end, "POST ")) *m = POST;
	else if (startswith_case(buf, end, "OPTIONS ")) *m = OPTIONS;
	else if (startswith_case(buf, end, "HEAD ")) *m = HEAD;
	else if (startswith_case(buf, end, "PUT ")) *m = PUT;
	else if (startswith_case(buf, end, "DELETE ")) *m = DELETE;
	else if (startswith_case(buf, end, "TRACE ")) *m = TRACE;
	else if (startswith_case(buf, end, "CONNECT ")) *m = CONNECT;
	else if (startswith_case(buf, end, "PROPFIND ")) *m = PROPFIND;
	else if (startswith_case(buf, end, "PROPPATCH ")) *m = PROPPATCH;
	else if (startswith_case(buf, end, "MKCOL ")) *m = MKCOL;
	else if (startswith_case(buf, end, "COPY ")) *m = COPY;
	else if (startswith_case(buf, end, "MOVE ")) *m = MOVE;
	else if (startswith_case(buf, end, "LOCK ")) *m = LOCK;
	else if (startswith_case(buf, end, "UNLOCK ")) *m = UNLOCK;
	else if (startswith_case(buf, end, "BCOPY ")) *m = BCOPY;
	else if (startswith_case(buf, end, "BDELETE ")) *m = BDELETE;
	else if (startswith_case(buf, end, "BMOVE ")) *m = BMOVE;
	else if (startswith_case(buf, end, "BPROPFIND ")) *m = BPROPFIND;
	else if (startswith_case(buf, end, "BPROPPATCH ")) *m = BPROPPATCH;
	else if (startswith_case(buf, end, "NOTIFY ")) *m = NOTIFY;
	else if (startswith_case(buf, end, "SEARCH ")) *m = SEARCH;
	else if (startswith_case(buf, end, "SUBSCRIBE ")) *m = SUBSCRIBE;
	else if (startswith_case(buf, end, "UNSUBSCRIBE ")) *m = UNSUBSCRIBE;
	else return NULL;

	const Byte* ret = find(buf, end, ' ');
	assert(buf < ret);
	assert(ret < end);
	return ret;
}

const Byte* HTTPMsg::parseReqURI(const Byte* buf, const Byte* end)
{
	CHECKED_RETURN_INIT(buf, end);
	buf = skipSpace(buf, end);
	const Byte* URIend = find(buf, end, ' ');
	if (URIend == end) {
		return NULL;
	} else {
		reqURI = string(buf, URIend);
		URL url(reqURI);
		if (url.hasSchema()) {
			requestURL_ = reqURI;
			host = url.getHost();
			reqURI = url.getPath();
		}
		CHECKED_RETURN(URIend);
	}
}

// Parse version. If unknown, we let the parsing continue anyway.
// Precondition: [buf, end) must contain an isspace character after
// the HTTP version identifier (a well-formed request ends with \r\n
// and a well-formed status-line has a ' ' after the version).
static const Byte* parseVersion(const Byte* buf, const Byte* end, HTTPMsg::Version* version)
{
	CHECKED_RETURN_INIT(buf, end);
	buf = skipSpace(buf, end);
	const Byte* versionEnd = buf;

	while (versionEnd != end && !isspace(*versionEnd))
		versionEnd++;

	// No isspace character (such as \r, \n, or ' ') after version
	// tag. This is suspicious, return NULL.
	if (versionEnd == end)
		return NULL;

	if (versionEnd-buf < 8)
		*version = HTTPMsg::HTTP_UNDEF;
	else if (memcmp(buf, "HTTP/1.0", 8) == 0)
		*version = HTTPMsg::HTTP_1_0;
	else if (memcmp(buf, "HTTP/1.1", 8) == 0)
		*version = HTTPMsg::HTTP_1_1;
	else
		*version = HTTPMsg::HTTP_UNDEF;

	CHECKED_RETURN(versionEnd);
}

static HTTPMsg::ContentEncoding parseContentEncoding(const string& enc)
{
	const char* s = enc.c_str();
	if (iequals("identity", s) || enc == "-") return HTTPMsg::CE_IDENTITY;
	else if (iequals("gzip", s) || iequals("x-gzip", s)) return HTTPMsg::CE_GZIP;
	else if (iequals("compress", s)) return HTTPMsg::CE_COMPRESS;
	else if (iequals("deflate", s)) return HTTPMsg::CE_DEFLATE;
	else return HTTPMsg::CE_UNKNOWN;
}

static HTTPMsg::TransferEncoding parseTransferEncoding(const string& enc)
{
	const char* s = enc.c_str();
	if (iequals("identity", s) || enc == "-") return HTTPMsg::TE_IDENTITY;
	else if (iequals("chunked", s)) return HTTPMsg::TE_CHUNKED;
	else if (iequals("gzip", s) || iequals("x-gzip", s)) return HTTPMsg::TE_GZIP;
	else if (iequals("compress", s)) return HTTPMsg::TE_COMPRESS;
	else if (iequals("deflate", s)) return HTTPMsg::TE_DEFLATE;
	else return HTTPMsg::TE_UNKNOWN;
}

int HTTPMsg::parseContentLength(const string& value)
{
	char* end;
	long ret = strtol(value.c_str(), &end, 10);

	// Skip trailing space.
	while (*end == ' ')
		end++;

	if (*end != 0)
		WARN("parseContentLength: Bogus content-length: ", value);

	if (ret < 0) {
		WARN("parseContentLength: negative content-length: ", value,
		     " setting to -1.");
		ret = -1;
	} else if (ret > HTTPMsg::MAX_CONTENT_LENGTH) {
		WARN("parseContentLength: content-length too large: ", value,
		     " capping to ", HTTPMsg::MAX_CONTENT_LENGTH);
		ret = HTTPMsg::MAX_CONTENT_LENGTH;
	}

	return ret;
}

/* Iterate through reqHeaders and parse the ones we are interested in. */
void HTTPMsg::parseReqHeaders()
{
	for (vector<HTTPHeader>::iterator it = reqHeaders.begin();
	     it != reqHeaders.end();
	     it++) {
		const char* s = it->name;
		if (!strcmp("host", s))
			host = it->value;
		else if (!strcmp("referer", s))
			referer = it->value;
		else if (!strcmp("transfer-encoding", s)) {
			reqTransferEnc = parseTransferEncoding(it->value);
			if (reqTransferEnc == TE_UNKNOWN)
				WARN("HTTPMsg::parseReqHeaders: Unknown transfer-encoding: ", it->value);
		} else if (!strcmp("content-length", s))
			reqLength = parseContentLength(it->value);
	}

	/* If the request had a absolute URI HTTPMsg::parseReqURI has
	 * already set requestURL_.
	 */
	if (requestURL_.empty())
		requestURL_ = string("http://") + getHost() + getRequestURI();
}

static const Byte* skip0(const Byte* buf, const Byte* end)
{
	CHECKED_RETURN_INIT(buf, end);
	while (buf != end && *buf == 0)
		buf++;
	CHECKED_RETURN(buf);
}

/*
  Parse a HTTP request in [buf, end). Returns pointer to one past the
  end of parsed data or NULL if it doesn't look like a HTTP
  request. packet.payload should not be used in this function! packet
  can be inspected to look at ACKs and timestamps, but the data should
  come from [buf, end).

  The request may be parsed in several passes. This method should be
  called with new data until NULL is returned or requestParsed()
  returns true.
*/
const Byte* HTTPMsg::parseRequest(const Byte* buf, const Byte* end, const TCPPacket& packet)
{
/*
  Is this a HTTP request?

  From RFC 2616:

        Request       = Request-Line              ; Section 5.1
                        *(( general-header        ; Section 4.5
                         | request-header         ; Section 5.3
                         | entity-header ) CRLF)  ; Section 7.1
                        CRLF
                        [ message-body ]          ; Section 4.3


        Request-Line = Method SP Request-URI SP HTTP-Version CRLF
*/
	CHECKED_RETURN_INIT(buf, end);
	while (true) {
		int len = end-buf;
		switch (reqParseState) {
		case REQ_PARSE_START:

			// We need to special case the len == 0 case to get
			// the proper first packet time.
			if (len == 0) {
				// Need more data.
				CHECKED_RETURN(buf);
			}
			reqFirstPacketTime_ = packet.pL2Packet->time;
			reqParseState = REQ_PARSE_REQ_LINE;
			break;

		case REQ_PARSE_REQ_LINE:
		{
			const Byte* origBuf = buf;
			/* Skip 0 bytes at the start of
			 * requests. Capture drops will cause 0 bytes
			 * to be inserted in the stream and we want to
			 * recover from them (i.e., find the start of
			 * the next request) as fast as possible.
			 */
			buf = skip0(buf, end);
			if (doResync_) {
				if (parseReqMethod(buf, end, &reqMethod)) {
					LOG_AND_COUNT("HTTPMsg::parseRequest: resync done. ",
						      quoteString(origBuf, end),
						      ' ', packet);
					doResync_ = false;
					resynced_ = true;
					reqFirstPacketTime_ = packet.pL2Packet->time;
				} else {
					LOG_AND_COUNT("HTTPMsg::parseRequest: Doing resync, skipping request packet. ",
						      quoteString(buf, end), ' ', packet);
					return end;
				}
			}

			if (findCRLF(buf, end) == end) {
				// For rationale for the 16*1024 see
				// http://stackoverflow.com/questions/2659952/maximum-length-of-http-get-request
				if (len > 16*1024) {
					WARN("HTTPMsg::parseRequest: Not HTTP request? ",
					     quoteString(origBuf, end), ' ', packet);
					return NULL; // Does not look like a HTTP request.
				} else {
					// Need more data.
					CHECKED_RETURN(buf);
				}
			}
			buf = parseReqMethod(buf, end, &reqMethod);
			if (buf == NULL) {
				WARN("HTTPMsg::parseRequest: Failed to parse method: ",
				     quoteString(origBuf, end), ' ', packet);
				return NULL;
			}
			buf = parseReqURI(buf, end);
			if (buf == NULL) {
				WARN("HTTPMsg::parseRequest: Failed to parse URI: ",
				     quoteString(origBuf, end), ' ', packet);
				return NULL;
			}
			buf = parseVersion(buf, end, &reqVersion);
			if (buf == NULL) {
				WARN("HTTPMsg::parseRequest: Failed to parse version: ",
				     quoteString(origBuf, end), ' ', packet);
				return NULL;
			}
			buf = skipSpace(buf, end);
			if (buf == end || findCRLF(buf, end) != buf) {
				WARN("HTTPMsg::parseRequest: Junk after version: ",
				     quoteString(origBuf, end), ' ', packet);
				return NULL;
			}
			assert(buf < end);
			assert(findCRLF(buf, end) == buf);
			buf += 2; // skip CRLF
			assert(buf <= end);

			reqParseState = REQ_PARSE_HEADERS;
		}
		break;

		case REQ_PARSE_HEADERS:
		{
			const Byte* crlf = findCRLF(buf, end);
			if (crlf == end) {
				// FIXME is 16*1024 appropriate? Look in HTTP RFC.
				if (len > 16*1024) {
					// Does not look like a HTTP request.
					WARN("HTTPMsg::parseRequest: Not HTTP request? Headers never end. ",
					     quoteString(buf, end), ' ', packet);
					return NULL;
				} else {
					// Need more data.
					CHECKED_RETURN(buf);
				}
			}

			if (crlf == buf) {
				reqParseState = REQ_PARSE_BODY;
				buf += 2;
			} else {
				const Byte* newBuf = parseHeader(buf, end, &reqHeaders);
				if (newBuf == NULL) {
					WARN("HTTPMsg::parseRequest: Strange header, ignoring. ",
					     quoteString(buf, end), ' ', packet);
					buf = crlf+2;
				} else {
					buf = newBuf;
				}

				// Look for more headers.
				break;
			}

			parseReqHeaders();

			/* From RFC 2616 (HTTP 1.1), Section 4.3:
			 *
			 * The presence of a message-body in a request is
			 * signaled by the inclusion of a Content-Length or
			 * Transfer-Encoding header field in the request's
			 * message-headers. A message-body MUST NOT be
			 * included in a request if the specification of the
			 * request method (section 5.1.1) does not allow
			 * sending an entity-body in requests. A server SHOULD
			 * read and forward a message-body on any request; if
			 * the request method does not include defined
			 * semantics for an entity-body, then the message-body
			 * SHOULD be ignored when handling the request.
			 */
			if (reqTransferEnc != TE_IDENTITY &&
			    reqTransferEnc != TE_CHUNKED) {
				LOG_AND_COUNT("HTTPMsg::parseRequest: Cannot parse body, unsupported transfer-encoding ",
					      reqTransferEnc, " resync needed. ",
					      *this, packet);
				return NULL;
			} else if (reqLength != 0) {
				reqParseState = REQ_PARSE_BODY;
			} else {
				reqParseState = REQ_PARSE_COMPLETE;
			}
		}
		break;

		case REQ_PARSE_BODY:
			if (reqTransferEnc == TE_IDENTITY) {
				if (reqGotBodyLen + len < reqLength) {
					// Got part of response.
					reqGotBodyLen += len;
					CHECKED_RETURN(end);
				} else {
					// Got entire response.
					// Some data may remain unparsed in the packet.
					buf += reqLength - reqGotBodyLen;
					reqGotBodyLen = reqLength;
					reqParseState = REQ_PARSE_COMPLETE;
				}
			} else if (reqTransferEnc == TE_CHUNKED) {
				buf = reqChunkedParser_.parse(buf, end, NULL);
				reqGotBodyLen = reqChunkedParser_.getBodyLength();
				if (reqChunkedParser_.done())
					reqParseState = REQ_PARSE_COMPLETE;
				else
					CHECKED_RETURN(buf);
			} else {
				// We should never reach this,
				assert(false);
			}
			break;

		case REQ_PARSE_COMPLETE:
			// Make sure we don't save the time of empty packets
			// here.
			if (packet.payloadSavedLen > 0)
				reqLastDataExchangePacketTime_ = packet.pL2Packet->time;
			CHECKED_RETURN(buf);
		}
	}

	assert(false);
}

/*
  From RFC 2616:
 Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
*/
const Byte* HTTPMsg::parseRspStatus(const Byte* buf, const Byte* end)
{
	CHECKED_RETURN_INIT(buf, end);
	buf = skipSpace(buf, end);
	buf = parseVersion(buf, end, &rspVersion);

	if (buf == NULL)
		return NULL;

	// Caller makes sure that [buf, end) contains CRLF.
	assert(buf != end);
	buf = skipSpace(buf, end);

	const Byte* digitEnd = buf;
	while (end != digitEnd && isdigit(*digitEnd))
		digitEnd++;

	if (digitEnd == buf || digitEnd == end)
		return NULL;

	char* ret;
	// As digitEnd != end strtol will not look beyond end.
	rspStatusCode = strtol((const char*) buf, &ret, 10);
	const Byte* byteRet = (const Byte*) ret;
	assert(byteRet != buf);
	// Skip Reason-Phrase and CRLF
	const Byte* crlf = findCRLF(byteRet, end);
	assert(byteRet <= crlf);
	assert(crlf < end);
	CHECKED_RETURN(crlf + 2);
}

/* RFC 2045 states that a MIME type has the following form

     content := "Content-Type" ":" type "/" subtype
                *(";" parameter)
                ; Matching of media type and subtype
                ; is ALWAYS case-insensitive.

    type and subtype are sequences of tokens and

     token := 1*<any (US-ASCII) CHAR except SPACE, CTLs,
                 or tspecials>

     tspecials :=  "(" / ")" / "<" / ">" / "@" /
                   "," / ";" / ":" / "\" / <">
                   "/" / "[" / "]" / "?" / "="
                   ; Must be in quoted-string,
                   ; to use within parameter values

*/

static bool isContentTypeToken(char c)
{
	return !(c == '(' ||
		 c == ')' ||
		 c == '<' ||
		 c == '>' ||
		 c == '@' ||
		 c == ',' ||
		 c == ';' ||
		 c == ':' ||
		 c == '\\' ||
		 c == '"' ||
		 c == '/' ||
		 c == '[' ||
		 c == ']' ||
		 c == '?' ||
		 c == '=' ||
		 isspace(c) ||
		 iscntrl(c));
}

/* Take a content-type, remove parameters, and convert it to lower
 * case. */
static string prettifyContentType(const string& contentType)
{
	string ret;
	bool haveSlash = false;
	for (size_t i = 0; i < contentType.size(); i++) {
		char c = contentType[i];
		if (c == '/') {
			if (haveSlash)
				break;
			else
				haveSlash = true;
			ret.push_back(tolower(c));
		} else if (isContentTypeToken(c)) {
			ret.push_back(tolower(c));
		} else {
			break;
		}
	}

	return ret;
}

// Our own simple content-type sniffer which only uses the URI. The
// proper MIME type sniffing from MIMESniffing.cc is used when we have
// parsed the response, see parseResponse below. This code is
// important when the resource is cached and the content based sniffer
// is useless.
string HTTPMsg::sniffContentType(const string& prettyContentType) const
{
	if (!prettyContentType.empty())
		return prettyContentType;

	const char* uri = reqURI.c_str();

	if (iends_with(uri, ".css"))
		return "text/css";
	else if (iends_with(uri, ".js"))
		return "application/javascript";
	else if (iends_with(uri, ".html"))
		return "text/html";
	else if (iends_with(uri, ".htm"))
		return "text/html";
	else if (iends_with(uri, ".gif"))
		return "image/gif";
	else if (iends_with(uri, ".jpg"))
		return "image/jpeg";
	else if (iends_with(uri, ".png"))
		return "image/png";
	else if (iends_with(uri, ".swf"))
		return "application/x-shockwave-flash";
	else
		return "";
}

/* Iterate through rspHeaders and parse the ones we are interested in. */
void HTTPMsg::parseRspHeaders()
{
	for (vector<HTTPHeader>::iterator it = rspHeaders.begin();
	     it != rspHeaders.end();
	     it++) {
		const char* s = it->name;
		if (!strcmp("content-length", s)) {
			rspLength = parseContentLength(it->value);
		} else if (!strcmp("transfer-encoding", s)) {
			rspTransferEnc = parseTransferEncoding(it->value);
			if (rspTransferEnc == TE_UNKNOWN)
				WARN("HTTPMsg::parseRspHeaders: Unknown transfer-encoding: ", it->value);
		} else if (!strcmp("content-encoding", s)) {
			rspContentEnc = parseContentEncoding(it->value);
			if (rspContentEnc == CE_UNKNOWN)
				WARN("HTTPMsg: Unknown content-encoding: ", it->value);
		} else if (!strcmp("content-type", s)) {
			rspContentType = it->value;
			rspPrettyContentType = prettifyContentType(rspContentType);
		} else if (!strcmp("location", s)) {
			rspLocation = it->value;
		}
	}

	rspPrettyContentType = sniffContentType(rspPrettyContentType);
	mimeSniffer.init(rspPrettyContentType.c_str(),
			 starts_with(rspPrettyContentType.c_str(), "image/"));

	// Ignore content-length header if we get transfer-encoding:
	// chunked.
	if (rspTransferEnc == TE_CHUNKED)
		rspLength = -1;
}

const string& HTTPMsg::getReqHeader(const string& name) const
{
	for (HTTPHeaders::const_iterator it = reqHeaders.begin(); it != reqHeaders.end(); ++it) {
		if (iequals(it->name, name.c_str()))
			return it->value;
	}

	if (!isHeaderParsed(name))
		WARN("HTTPMsg::getReqHeader: header not parsed: ", name);
	return emptyString;
}

const std::string& HTTPMsg::getRspHeader(const std::string& name) const
{
	for (HTTPHeaders::const_iterator it = rspHeaders.begin(); it != rspHeaders.end(); ++it) {
		if (iequals(it->name, name.c_str()))
			return it->value;
	}

	if (!isHeaderParsed(name))
		WARN("HTTPMsg::getRspHeader: header not parsed: ", name);
	return emptyString;
}

/*
  Parse a HTTP response in [buf, end). Returns pointer to one past the
  end of parsed data or NULL if it doesn't look like a HTTP response.
  packet.payload should not be used in this function! packet can be
  inspected to look at ACKs and timestamps, but the data should come
  from [buf, end).

  The response may be parsed in several passes. This method should be
  called with new data until NULL is returned or responseParsed()
  returns true.
*/
const Byte* HTTPMsg::parseResponse(const Byte* buf, const Byte* end, const TCPPacket& packet)
{
/*
  Is this a HTTP response?

  From RFC 2616:

       Response      = Status-Line               ; Section 6.1
                       *(( general-header        ; Section 4.5
                        | response-header        ; Section 6.2
                        | entity-header ) CRLF)  ; Section 7.1
                       CRLF
                       [ message-body ]          ; Section 7.2

*/
	int len = end-buf;
	const Byte* newBuf;

	while (true) {
		if (resyncNeeded_)
			assert(rspParseState == RSP_PARSE_BODY);

		CHECKED_RETURN_INIT(buf, end);
		switch (rspParseState) {
		case RSP_PARSE_START:
			// We need to special case the len == 0 case to get
			// the proper first packet time.
			if (len == 0) {
				// Need more data.
				CHECKED_RETURN(buf);
			}

			rspFirstPacketTime_ = packet.pL2Packet->time;
			rspParseState = RSP_PARSE_STATUS_LINE;
			/* Fall through */

		case RSP_PARSE_STATUS_LINE:
			if (len == 0)
				CHECKED_RETURN(buf);

			if (!requestParsed()) {
				WARN("HTTPMsg::parseResponse: Parsing response status-line, but request not parsed ",
				     *this, quoteString(buf, end), packet);
				return NULL;
			}
			if (findCRLF(buf, end) == end) {
				// FIXME is 1024 appropriate? Look in HTTP RFC.
				if (len > 1024) {
					WARN("HTTPMsg::parseResponse: CRLF Not found in status-line. ",
					     quoteString(buf, end), packet);
					return NULL; // Does not look like a HTTP response.
				} else {
					// Need more data.
					CHECKED_RETURN(buf);
				}
			}
			newBuf = parseRspStatus(buf, end);
			if (newBuf == NULL) {
				WARN("HTTPMsg::parseResponse: Failed to parse status-line. ",
				     quoteString(buf, end), packet);
				return NULL;
			}
			buf = newBuf;

			rspParseState = RSP_PARSE_HEADERS;
			/* Fall through */

		case RSP_PARSE_HEADERS:
		{
			len = end-buf;
			const Byte* crlf = findCRLF(buf, end);
			if (crlf == end) {
				// FIXME is 4096 appropriate? Look in HTTP RFC.
				if (len > 4096) {
					// Does not look like a HTTP response.
					WARN("HTTPMsg::parseResponse: CRLF not found in headers. ",
					     quoteString(buf, end), packet);
					return NULL;
				} else {
					// Need more data.
					CHECKED_RETURN(buf);
				}
			}

			if (crlf == buf) {
				rspParseState = RSP_PARSE_BODY;
				buf += 2;
			} else {
				newBuf = parseHeader(buf, end, &rspHeaders);
				if (newBuf == NULL) {
					WARN("HTTPMsg::parseResponse: Strange header, ignoring. ",
					     quoteString(buf, end), packet);
					buf = crlf+2;
				} else {
					buf = newBuf;
				}

				// Look for more headers, break out of
				// switch to while loop.
				break;
			}

			parseRspHeaders();

			/* See RFC 2616 Section 4.4 for info on when a message
			 * body is present and how long it is. */
			if ((100 <= rspStatusCode && rspStatusCode < 200) ||
			    rspStatusCode == 204 || // No content
			    rspStatusCode == 304 || // Not modified
			    reqMethod == HEAD) {
				rspParseState = RSP_PARSE_COMPLETE;
				rspLength = 0;
			} else if (rspTransferEnc != TE_IDENTITY &&
				   rspTransferEnc != TE_CHUNKED) {
				LOG_AND_COUNT("HTTPMsg::parseResponse: Cannot parse body, unsupported transfer-encoding ",
					      rspTransferEnc, " resync needed. ",
				    *this, packet);
				resyncNeeded_ = true;
				rspParseState = RSP_PARSE_BODY;
			} else if (rspLength != -1) {
				rspParseState = RSP_PARSE_BODY;
			} else if (rspContentType == "multipart/byteranges") {
				// FIXME
				WARN("HTTPMsg::parseResponse: Cannot parse body with content-type multipart/byteranges resync needed",
				    *this, packet);
				resyncNeeded_ = true;
				rspParseState = RSP_PARSE_BODY;
			} else {
				// Body ends on connection close.
				rspParseState = RSP_PARSE_BODY;
				rspEndOnConnectionClose = true;
			}
		}
		break;

		case RSP_PARSE_BODY:
			len = end-buf;
			if (resyncNeeded_) {
				rspGotBodyLen += len;
				CHECKED_RETURN(end);
			}

			if (rspTransferEnc == TE_IDENTITY) {
				const Byte* dataEnd;
				if (rspLength != -1) {
					if (rspGotBodyLen + len < rspLength) {
						// Got part of response.
						rspGotBodyLen += len;
						dataEnd = end;
					} else {
						// Got entire response.
						// Some data may remain unparsed in the packet.
						dataEnd = buf + (rspLength - rspGotBodyLen);
						rspGotBodyLen = rspLength;
						rspParseState = RSP_PARSE_COMPLETE;
					}
				} else {
					// Body ends on connection close.
					rspGotBodyLen += len;
					dataEnd = end;
				}

				if (mimeSniffer.isValid() &&
				    rspBody.size() < mimeSniffer.dataSize()) {
					int l = std::min(static_cast<size_t>(dataEnd - buf),
							 mimeSniffer.dataSize() - rspBody.size());
					rspBody.insert(rspBody.end(), buf, buf+l);
				}
				buf = dataEnd;
			} else if (rspTransferEnc == TE_CHUNKED) {
				vector<Byte>* v = NULL;
				if (mimeSniffer.isValid() &&
				    rspBody.size() < mimeSniffer.dataSize())
					v = &rspBody;
				buf = rspChunkedParser_.parse(buf, end, v);
				rspGotBodyLen = rspChunkedParser_.getBodyLength();
				if (rspChunkedParser_.done())
					rspParseState = RSP_PARSE_COMPLETE;
			} else {
				// We should never reach this,
				// resyncNeeded_ should be true if the
				// transfer-encoding isn't supported.
				assert(false);
			}

			// This is not perfect. We won't do any
			// sniffing on small objects (less that
			// mimeSniffer.dataSize()) that was sent
			// without a Content-Length header.
			if (!rspBody.empty() &&
			    // As we don't decode content-encodings we
			    // shouldn't do content sniffing on
			    // encoded content. If we would do this
			    // text/plain compressed with gzip would
			    // be sniffed to application/x-gzip which
			    // we don't want.
			    rspContentEnc == CE_IDENTITY &&
			    (rspBody.size() >= mimeSniffer.dataSize() ||
			     rspParseState == RSP_PARSE_COMPLETE)) {
				const char* sniffed = mimeSniffer.sniff(reinterpret_cast<char*>(&rspBody[0]),
									rspBody.size());
				if (sniffed && rspPrettyContentType != sniffed) {
					COUNTER_INCREASE("HTTPMsg::parseResponse: sniffed MIME type != advertised MIME type");
					log(staple_, "Sniffed mime type: ", sniffed,
					    " old type: ", rspPrettyContentType, ' ',
					    packet);
					rspPrettyContentType = sniffed;
				}
			}

			CHECKED_RETURN(buf);
			break;

		case RSP_PARSE_COMPLETE:
			CHECKED_RETURN(buf);
		}
	}
}

/* Process one packet.
 *
 * packet - Packet to parse.
 *
 * offset - Consider start of payload to be
 * packet.payload+offset. offset may be larger than
 * packet.payloadSavedLen, but not larger than packet.TCPPLLen.
 *
 * request - true if this is a request packet, false otherwise.
 *
 * success - *success is set to true if parsing was
 * successful, otherwise set to false.
 *
 * Returns length of unparsed data (so the next HTTPMsg starts
 * there). The return value is relative to packet.TCPPLLen, so if
 * packet.TCPPLLen is 100 and we parse the first 90 bytes of the
 * payload then 10 will be returned.
 * 
 * This function should be called until
 * responseParsed()/requestParsed() returns true.
 */
int HTTPMsg::processPacket(const TCPPacket& packet, int offset, bool request, bool* success)
{
	COUNTER_INCREASE("HTTPMsg::processPacket called");

	vector<Byte>& buf = request ? reqBuf : rspBuf;
	const Byte* end;
	int unparsed;
	bool done;

	assert(0 <= offset);
	assert(offset <= packet.TCPPLLen);

	*success = true;

	// If we are doing a resynchronization, skip all data in DL direction.
	if (doResync_ && !request) {
		const Byte* payload = packet.payload + offset;
		const Byte* payloadEnd = packet.payload + packet.payloadSavedLen;
		LOG_AND_COUNT("HTTPMsg::processPacket: Doing resync, skipping response packet.",
			      quoteString(payload, payloadEnd), packet);
		buf.clear();
		return 0;
	}

	bool fastPath = true;
	if (!buf.empty())
		fastPath = false;
	if (packet.payloadSavedLen < packet.TCPPLLen)
		fastPath = false;

	if (fastPath) {
		const Byte* payload = packet.payload+offset;
		const Byte* payloadEnd = packet.payload+packet.payloadSavedLen;
		COUNTER_INCREASE("HTTPMsg::processPacket: empty buffer optimization");
		// An optimization. If our buffer is empty (and the
		// other fast path conditions apply), then we pass the
		// payload buffer directly to parseRequest/parseResponse.
		if (request)
			end = parseRequest(payload, payloadEnd, packet);
		else
			end = parseResponse(payload, payloadEnd, packet);
		if (!(end == NULL || (payload <= end && end <= payloadEnd))) {
			error(staple_, "HTTPMsg::processPacket:"
			      " request: ", request,
			      " payload: ", quoteString(payload, payloadEnd),
			      " offset: ", offset,
			      " packet: ", packet,
			      ' ', *this);
			error(staple_, "HTTPMsg::processPacket: end: ", (void*) end);
			assert(false);
		}

		if (end == NULL) {
			// Some parsing problem occurred.
			*success = false;
			return 0;
		}

		if (request)
			done = requestParsed();
		else
			done = responseParsed();

		if (done) {
			unparsed = payloadEnd - end;
		} else {
			// We are not done, copy the remaining part
			// into buf and return 0.
			unparsed = 0;
			if (end != payloadEnd)
				buf.insert(buf.end(), end, payloadEnd);
		}
	} else {
		// Slow path. We need to copy the payload data into buf.
		if (offset < packet.payloadSavedLen) {
			Byte* payloadEnd = packet.payload+packet.payloadSavedLen;
			buf.insert(buf.end(), packet.payload + offset, payloadEnd);
		}

		if (packet.payloadSavedLen < packet.TCPPLLen) {
			// Fill missing bytes at end of packet with 0.
			int len;
			if (offset < packet.payloadSavedLen)
				len = packet.TCPPLLen - packet.payloadSavedLen;
			else
				len = packet.TCPPLLen - offset;
			buf.insert(buf.end(), len, 0);
		}

		if (request)
			end = parseRequest(&buf[0], &buf[0]+buf.size(), packet);
		else
			end = parseResponse(&buf[0], &buf[0]+buf.size(), packet);

		if (!(end == NULL || (&buf[0] <= end && end <= &buf[0]+buf.size()))) {
			error(staple_, "HTTPMsg::processPacket:"
			      " request: ", request,
			      " payload: ", quoteString(&buf[0], &buf[0]+buf.size()),
			      " offset: ", offset,
			      " packet: ", packet,
			      ' ', *this);
			error(staple_, "HTTPMsg::processPacket: end: ", (void*) end);
			assert(false);
		}

		if (end == NULL) {
			// Some parsing problem occurred.
			*success = false;
			return 0;
		}

		if (request)
			done = requestParsed();
		else
			done = responseParsed();

		if (done)
			unparsed = &buf[0]+buf.size() - end;
		else
			unparsed = 0;

		// Remove already parsed data. We would like to write just
		// 'end' in the second argument, but that isn't possible due
		// to typing issues.
		buf.erase(buf.begin(), buf.begin() + (end - &buf[0])); 
	}

	assert(0 <= unparsed);
	return unparsed;
}

int HTTPMsg::processReqPacket(const TCPPacket& packet, int offset, bool* success)
{
	// See comment above declaration of resyncNeeded_ for
	// an explanation to this assertion.
	assert(!resyncNeeded_);
	int ret = processPacket(packet, offset, true, success);
	if (!*success)
		resyncNeeded_ = true;

	if (!doResync_) {
		if (*success)
			bytesNetworkUL_ += packet.TCPPLLen - ret;
		else
			bytesNetworkUL_ += packet.TCPPLLen;
	}

	return ret;
}

int HTTPMsg::processRspPacket(const TCPPacket& packet, int offset, bool* success)
{
	// Make sure we don't save the time of empty packets
	// here.
	if (packet.payloadSavedLen > 0)
		rspLastDataExchangePacketTime_ = packet.pL2Packet->time;

	int ret = processPacket(packet, offset, false, success);
	if (!*success)
		resyncNeeded_ = true;

	if (!doResync_) {
		if (*success)
			bytesNetworkDL_ += packet.TCPPLLen - ret;
		else
			bytesNetworkDL_ += packet.TCPPLLen;
	}

	return ret;
}

/* Be careful to not return a completely non-sensical time when the
 * response hasn't been parsed.
 */
Timeval HTTPMsg::getRspStartTime() const
{
	if (rspFirstPacketTime_ < reqFirstPacketTime_)
		return reqFirstPacketTime_;
	else
		return rspFirstPacketTime_;
}

/* Be careful to not return a completely non-sensical time when we
 * haven't got the entire response.
 */
Timeval HTTPMsg::getRspEndTime() const
{
	if (!responseHeaderParsed())
		return getRspStartTime();
	else if (rspLastDataExchangePacketTime_ < getRspStartTime())
		return getRspStartTime();
	else
		return rspLastDataExchangePacketTime_;
}

void HTTPMsg::print(ostream& o, bool printAddress) const
{
	o << "HTTPMsg";
	if (printAddress)
		o << ' ' << this;
	o << ' ' << connId_;
	o << " Req:"
	  << (resyncNeeded_ ? " resync needed" : "")
	  << (doResync_ ? " doing resync" : "")
	  << (resynced_ ? " resynced" : "");
	if (reqParseState != HTTPMsg::REQ_PARSE_COMPLETE)
		o << " state: " << reqParseState;
	if (reqMethod != HTTPMsg::GET)
		o << " method: " << reqMethod;
	o << " URL: " << host << ' ' << reqURI
	  << " Rsp:";
	if (rspParseState != HTTPMsg::RSP_PARSE_COMPLETE)
		o << " state: " << rspParseState;
	if (rspStatusCode != 200)
		o << " code: " << rspStatusCode;
	
	o << " len: " << rspLength;
	if (rspGotBodyLen != rspLength)
		o << " (got " << rspGotBodyLen << ")";
}

void HTTPMsg::printTestOutput(ostream& o) const
{
	print(o, false);
}

ostream& operator<<(ostream& o, const HTTPMsg& m)
{
	m.print(o, true);
	return o;
}

static const char* methodToString(HTTPMsg::Method m)
{
	switch (m) {
	// Method not yet parsed.
	case HTTPMsg::NOT_PARSED: return "(not parsed)";
	// Standard HTTP (RFC 2616)
	case HTTPMsg::OPTIONS: return "OPTIONS";
	case HTTPMsg::GET: return "GET";
	case HTTPMsg::HEAD: return "HEAD";
	case HTTPMsg::POST: return "POST";
	case HTTPMsg::PUT: return "PUT";
	case HTTPMsg::DELETE: return "DELETE";
	case HTTPMsg::TRACE: return "TRACE";
	case HTTPMsg::CONNECT: return "CONNECT";
	// Distributed authoring (WebDAV) extensions (RFC 2518)
	case HTTPMsg::PROPFIND: return "PROPFIND";
	case HTTPMsg::PROPPATCH: return "PROPPATCH";
	case HTTPMsg::MKCOL: return "MKCOL";
	case HTTPMsg::COPY: return "COPY";
	case HTTPMsg::MOVE: return "MOVE";
	case HTTPMsg::LOCK: return "LOCK";
	case HTTPMsg::UNLOCK: return "UNLOCK";
	// Microsoft WebDAV extenseions
	case HTTPMsg::BCOPY: return "BCOPY";
	case HTTPMsg::BDELETE: return "BDELETE";
	case HTTPMsg::BMOVE: return "BMOVE";
	case HTTPMsg::BPROPFIND: return "BPROPFIND";
	case HTTPMsg::BPROPPATCH: return "BPROPPATCH";
	case HTTPMsg::NOTIFY: return "NOTIFY";
	case HTTPMsg::SEARCH: return "SEARCH";
	case HTTPMsg::SUBSCRIBE: return "SUBSCRIBE";
	case HTTPMsg::UNSUBSCRIBE: return "UNSUBSCRIBE";
	default: return "(unknown)";
	}
}

std::ostream& operator<<(std::ostream& o, HTTPMsg::Method m)
{
	return o << methodToString(m);
}

std::istream& operator>>(std::istream& in, HTTPMsg::Method& m)
{
	string s;
	in >> s;
	s.push_back(' ');
	const Byte* str = reinterpret_cast<const Byte*>(s.c_str());
	if (HTTPMsg::parseReqMethod(str, str+s.size(), &m) == NULL)
		m = HTTPMsg::NOT_PARSED;
	return in;
}

static const char* transferEncToString(enum HTTPMsg::TransferEncoding t)
{
	switch (t) {
	case HTTPMsg::TE_IDENTITY: return "identity";
	case HTTPMsg::TE_CHUNKED: return "chunked";
	case HTTPMsg::TE_GZIP: return "gzip";
	case HTTPMsg::TE_COMPRESS: return "compress";
	case HTTPMsg::TE_DEFLATE: return "deflate";
	case HTTPMsg::TE_UNKNOWN: return "unknown";
	default: assert(false);
	}
}

std::ostream& operator<<(std::ostream& o, HTTPMsg::TransferEncoding t)
{
	return o << transferEncToString(t);
}

static const char* contentEncToString(enum HTTPMsg::ContentEncoding t)
{
	switch (t) {
	case HTTPMsg::CE_IDENTITY: return "identity";
	case HTTPMsg::CE_GZIP: return "gzip";
	case HTTPMsg::CE_COMPRESS: return "compress";
	case HTTPMsg::CE_DEFLATE: return "deflate";
	case HTTPMsg::CE_UNKNOWN: return "unknown";
	default: assert(false);
	}
}

std::ostream& operator<<(std::ostream& o, HTTPMsg::ContentEncoding ce)
{
	return o << contentEncToString(ce);
}

std::istream& operator>>(std::istream& o, HTTPMsg::ContentEncoding& ce)
{
	string s;
	o >> s;
	ce = parseContentEncoding(s);
	return o;
}

static const char* versionToString(HTTPMsg::Version v)
{
	switch (v) {
	case HTTPMsg::HTTP_1_0: return "HTTP/1.0";
	case HTTPMsg::HTTP_1_1: return "HTTP/1.1";
	case HTTPMsg::HTTP_UNDEF: return "(unknown)";
	default: assert(false);
	}
}

std::ostream& operator<<(std::ostream& o, HTTPMsg::Version v)
{
	return o << versionToString(v);
}

const char* statusCodeToString(int code)
{
	// From Section 10 of RFC 2616 (HTTP)
	switch (code) {
		// Informational 1xx ... 10.1
	case 100: return "Continue";
	case 101: return "Switching";
		// Successful 2xx ... 10.2
	case 200: return "OK";
	case 201: return "Created";
	case 202: return "Accepted";
	case 203: return "Non-Authoritative Information";
	case 204: return "No Content";
	case 205: return "Reset Content";
	case 206: return "Partial Content";
		// Redirection 3xx ... 10.3
	case 300: return "Multiple Choices";
	case 301: return "Moved Permanently";
	case 302: return "Found";
	case 303: return "See Other";
	case 304: return "Not Modified";
	case 305: return "Use Proxy";
	case 306: return "(Unused)";
	case 307: return "Temporary Redirect";
		// Client Error 4xx ... 10.4
	case 400: return "Bad Request";
	case 401: return "Unauthorized";
	case 402: return "Payment Required";
	case 403: return "Forbidden";
	case 404: return "Not Found";
	case 405: return "Method Not Allowed";
	case 406: return "Not Acceptable";
	case 407: return "Proxy Authentication Required";
	case 408: return "Request Timeout";
	case 409: return "Conflict";
	case 410: return "Gone";
	case 411: return "Length Required";
	case 412: return "Precondition Failed";
	case 413: return "Request Entity Too Large";
	case 414: return "Request-URI Too Long";
	case 415: return "Unsupported Media Type";
	case 416: return "Requested Range Not Satisfiable";
	case 417: return "Expectation Failed";
		// Server Error 5xx ... 10.5
	case 500: return "Internal Server Error";
	case 501: return "Not Implemented";
	case 502: return "Bad Gateway";
	case 503: return "Service Unavailable";
	case 504: return "Gateway Timeout";
	case 505: return "HTTP Version Not Supported";
	default:
		if (100 <= code && code < 200) return "unknown informational";
		else if (200 <= code && code < 300) return "unknown successful";
		else if (300 <= code && code < 400) return "unknown redirection";
		else if (400 <= code && code < 500) return "unknown client error";
		else if (500 <= code && code < 600) return "unknown server error";
		else return "unknown";
	}
}

/* The stuff we print here must match what is generated by
 * test/genexpected.sh ip.src, tcp.srcport, ip.dst, tcp.dstport have
 * already been written.
 */
void HTTPMsg::printRspTestOutput(std::ostream& o) const
{
	// Sometimes useful for debugging
	// o << getRspEndTime().tv_sec << '.' << getRspEndTime().tv_usec << '\t';
	o /* << reqMethod */ << '\t';
	o /* << reqHost   */ << '\t';
	o /* << reqURI    */ << '\t';
	o << rspStatusCode << '\t';
	if (rspTransferEnc != TE_IDENTITY)
		o << rspTransferEnc << '\t';
	else
		o << '\t';
	o << rspGotBodyLen;
}

void HTTPMsg::printReqTestOutput(std::ostream& o) const
{
	// Sometimes useful for debugging
	// o << getReqStartTime().tv_sec << '.' << getReqStartTime().tv_usec << '\t';
	o << reqMethod << '\t';
	o << host << '\t';
	o << reqURI << '\t';
	o /* << rspStatusCode  */ << '\t';
	o /* << rspTransferEnc */ << '\t';
	if (reqLength > 0)
		o  << reqLength;
}
