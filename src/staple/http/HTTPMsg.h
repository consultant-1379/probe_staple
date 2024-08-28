#ifndef HTTPMSG_H
#define HTTPMSG_H

#include <vector>
#include <string>

#include <staple/Type.h>
#include <staple/TCPConn.h>
#include <staple/http/Timeval.h>
#include "MIMESniffing.h"
#include "ChunkedParser.h"

class TCPPacket;
class Staple;

const char* statusCodeToString(int code);

// An HTTP header. Examples include User-Agent, Cache-Control, etc.
struct HTTPHeader
{
	HTTPHeader(const char* n, const std::string& v) : name(n), value(v)
		{ }

	const char* name;
	std::string value;
};
typedef std::vector<HTTPHeader> HTTPHeaders;

// HTTP message class. A message consists of a request and a response.
class HTTPMsg {
public:
	typedef enum {HTTP_1_0,
		      HTTP_1_1,
		      HTTP_UNDEF} Version;

	typedef enum {
		// Method not yet parsed.
		NOT_PARSED,
		// Standard HTTP (RFC 2616)
		OPTIONS,
		GET,
		HEAD,
		POST,
		PUT,
		DELETE,
		TRACE,
		CONNECT,
		// Distributed authoring (WebDAV) extensions (RFC 2518)
		PROPFIND,
		PROPPATCH,
		MKCOL,
		COPY,
		MOVE,
		LOCK,
		UNLOCK,
		// Microsoft WebDAV extenseions
		BCOPY,
		BDELETE,
		BMOVE,
		BPROPFIND,
		BPROPPATCH,
		NOTIFY,
		SEARCH,
		SUBSCRIBE,
		UNSUBSCRIBE
	} Method;

	// See RFC 2616 Section 3.6.
	enum TransferEncoding {TE_IDENTITY, TE_CHUNKED, TE_GZIP, TE_COMPRESS, TE_DEFLATE, TE_UNKNOWN};
	// See RFC 2616 Section 3.5.
	enum ContentEncoding {CE_IDENTITY, CE_GZIP, CE_COMPRESS, CE_DEFLATE, CE_UNKNOWN};

	/* The 'staple' argument is only used for logging. */
	HTTPMsg(Staple& staple, const TCPConnId&);
	~HTTPMsg();

	// Do resynchronization in this message. We will skip packets
	// until we see a request at the start of a packet. If called,
	// it must be called immediately after the constructor. See
	// also resyncNeeded_ below.
	void doResynchronization();

	bool tryingToResync() const
	{
		return doResync_;
	}
	
	/* Parse packet as a HTTP message starting at offset
	 * 'offset'. Return NULL if this doesn't seem to belong to an
	 * HTTP session. If non-NULL is returned this is one byte
	 * after the end of this message (within the packet). This
	 * part will belong to the next HTTPMsg.
	 *
	 * If NULL is returned neither processReqPacket nor
	 * processRspPacket should ever be called again on this
	 * object.
	 */
	int processReqPacket(const TCPPacket& packet, int offset, bool* success);
	int processRspPacket(const TCPPacket& packet, int offset, bool* success);

	// The maximum length of a body (both request and response
	// body). If a content-length header is parsed with a value
	// larger than this, it is capped to this value. We have this
	// limit to avoid overflow in arithmetic we do on the
	// lengths. We are also not really interested in these huge
	// blobs.
	static const long MAX_CONTENT_LENGTH = 100*1000*1000;

	// Return true if the request and response, respectively, is
	// completely parsed.
	bool requestParsed() const
	{
		return reqParseState == REQ_PARSE_COMPLETE;
	}

	bool responseParsed() const
	{
		return rspParseState == RSP_PARSE_COMPLETE;
	}

	// Return true if the response header (but not necessarily the
	// body) is completely parsed.
	bool responseHeaderParsed() const
	{
		switch (rspParseState) {
		case RSP_PARSE_COMPLETE:
		case RSP_PARSE_BODY:
			return true;
		default:
			return false;
		}
	}

	const std::string& getRequestURL() const
	{
		return requestURL_;
	}

	bool resyncNeeded() const { return resyncNeeded_; }

	/* Call this if the TCP connection this HTTPMsg went on was
	 * closed. Set graceful to true if the connection was closed
	 * in a graceful manner (i.e., the ordinary FIN sequence),
	 * otherwise set it to false (close by RST or timeout).
	 */
	void finishTCPSession(bool graceful);

	const Timeval& getReqStartTime() const { return reqFirstPacketTime_; }
	Timeval getRspStartTime() const;
	Timeval getRspEndTime() const;

	const std::string& getHost() const { return host; }
	const std::string& getRequestURI() const { return reqURI; }
	const std::string& getContentType() const { return rspPrettyContentType; }
	const std::string& getRealContentType() const { return rspContentType; }
	const std::string& getLocation() const { return rspLocation; }
	ContentEncoding getContentEncoding() const { return rspContentEnc; }
	const std::string& getReferer() const { return referer; }
	const std::string& getReqHeader(const std::string& name) const;
	const std::string& getRspHeader(const std::string& name) const;

	Method getReqMethod() const { return reqMethod; }
	const std::string& getReqURI() const { return reqURI; }
	Version getReqVersion() const { return reqVersion; }

	const HTTPHeaders& getReqHeaders() const { return reqHeaders; }

	int getRspStatusCode() const { return rspStatusCode; }
	const HTTPHeaders& getRspHeaders() const { return rspHeaders; }

	// Print the HTTPMsg in a way that is useful for debugging.
	friend std::ostream& operator<<(std::ostream& o, const HTTPMsg& m);

	// These two is used by the HTTPMsgTester
	void printRspTestOutput(std::ostream&) const;
	void printReqTestOutput(std::ostream&) const;

	// Used by the HTTPPageViewTester
	void printTestOutput(std::ostream& o) const;

	// Number of bytes sent over the network in downlink/uplink
	// direction for this message. Both headers and (possibly
	// compressed/encoded) bodies are included.
	int getBytesNetworkDL() const { return bytesNetworkDL_; }
	int getBytesNetworkUL() const { return bytesNetworkUL_; }

	const TCPConnId& getTCPConnId() const { return connId_; }

private:
	Staple& staple_;

	enum ReqParseState {REQ_PARSE_START, REQ_PARSE_REQ_LINE, REQ_PARSE_HEADERS, REQ_PARSE_BODY, REQ_PARSE_COMPLETE};
	enum RspParseState {RSP_PARSE_START, RSP_PARSE_STATUS_LINE, RSP_PARSE_HEADERS, RSP_PARSE_BODY, RSP_PARSE_COMPLETE};

	// Empty string constant used in getReqHeader and
	// getRspHeader.
	static const std::string emptyString;

	TCPConnId connId_;

        /* If true, we either failed to identify the end of a response
	 * (this happens if we see a transfer-encoding that we don't
	 * understand) or some parse error occurred. We need to use
	 * heuristics to find the start of the next request. We assume
	 * that the connection is not pipelined, i.e., we assume that
	 * new requests are sent after the response has been received
	 * for the previous request.
	 *
	 * If true, processReqPacket should never be called on this
	 * object again. Instead a new HTTPMsg should be constructed
	 * and doResynchronization should be called on that
	 * object. Any new packets should be handled by the new
	 * object.
	 *
	 * Set to true by processReqPacket and processRspPacket on
	 * parse error.
	 */
	bool resyncNeeded_;

        /* True if we are doing a resynchronization in this HTTPMsg.
	 *
	 * If true, parseRequest will look for a request in the
	 * beginning of each packet.
	 *
	 * If true, processPacket will drop all data in DL direction.
	 */
	bool doResync_;

	/* True if we have done a resynchronization in this HTTPMsg.
	 */
	bool resynced_;

	// Request
	Version     reqVersion;                // HTTP version (HTTP_UNDEF if not present)
	Method      reqMethod;                 // Request method (GET, POST, etc.)
	std::string reqURI;                    // Request URI
	bool        reqURIComplete;            // True, if the entire request URI was present in the packet
	std::string host;                      // Host
	std::string referer;
	std::string requestURL_;
	enum ReqParseState reqParseState;
	enum TransferEncoding reqTransferEnc;
	long reqLength; // Content length of request body
	int reqGotBodyLen; // Length of response body we have received so far.
	ChunkedParser reqChunkedParser_;

	HTTPHeaders reqHeaders;
	int reqNextSeqNo; // Expected seq no of next request packet.
	bool reqComplete; // True, if we have the entire request.

	// FIXME should this be std::deque instead? It is a quite big
	// change, introduce typedef std::deque<Byte>::const_iterator
	// BufIt, change lots of const Byte* to BufIt.
	//
        // Pros: more efficient removal from front.
	//
        // Cons: The current zero-copy optimization when we don't have
        // anything in the buffer wont work anymore. (This should be
        // the common case.)
	std::vector<Byte> reqBuf;

	// These two can be used to measure server processing time.

	/* Time of the first TCP packet belonging to the request
	 * (connection open included)
	 */
	Timeval reqFirstPacketTime_;

        /* Time of the last data exchange TCP packet belonging to the
	 * request.
	 */
	Timeval reqLastDataExchangePacketTime_;


	// Response
	HTTPHeaders rspHeaders; // The HTTP headers in the response.
	Version     rspVersion;                // HTTP version (HTTP_UNDEF if not present)
	unsigned short rspStatusCode;             // Response status code
	long rspLength; // Content length, -1 if unknown.
	enum TransferEncoding rspTransferEnc;
	enum ContentEncoding rspContentEnc;
	std::string rspContentType, rspPrettyContentType;
	std::string rspLocation;

	enum RspParseState rspParseState;
	int rspGotBodyLen; // Length of response body we have received so far.
	ChunkedParser rspChunkedParser_;

        // True if the response end on connection close (no
        // content-length header and not transfer-encoding: chunked)
	bool rspEndOnConnectionClose;

	int respNextSeqNo; // Expected seq no of next response packet.
	bool respComplete; // True, if we have the entire response.

        // FIXME should maybe be std::deque. See reqBuf above for pros/cons.
	std::vector<Byte> rspBuf;

        /* Time of the first TCP packet belonging to the response
	 */
	Timeval rspFirstPacketTime_;

        /* Time of the ACK of the last data exchange TCP packet
	 * belonging to the response
	 */
	/* FIXME not yet implemented. Maybe some parts from TCPConn.h
	 * can be used? (At least in the
	 * response-ends-on-connection-close case.)
	 */
	// struct timeval rspLastAckPacketTime_;   

	// This is easier to get at, but maybe not as useful.
	Timeval rspLastDataExchangePacketTime_;

	MIMESniffer mimeSniffer;

	// This is used for MIME sniffing with mimeSniffer. We only
	// store the first few bytes of the response here (typically
	// 512 bytes).
	std::vector<Byte> rspBody;

	int bytesNetworkDL_, bytesNetworkUL_;

	int processPacket(const TCPPacket& packet, int offset, bool request, bool* success);

	const Byte* parseRequest(const Byte* buf, const Byte* end, const TCPPacket& packet);
	static const Byte* parseReqMethod(const Byte* buf, const Byte* end, Method*);
	const Byte* parseReqURI(const Byte* buf, const Byte* end);
	void parseReqHeaders();

	const Byte* parseResponse(const Byte* buf, const Byte* end, const TCPPacket& packet);
	const Byte* parseRspStatus(const Byte* buf, const Byte* end);
	void parseRspHeaders();
	void print(std::ostream& o, bool printAddress) const;
	int parseContentLength(const std::string& value);

	std::string sniffContentType(const std::string& prettyContentType) const;
	friend std::istream& operator>>(std::istream& in, HTTPMsg::Method& m);
};

std::ostream& operator<<(std::ostream& o, const HTTPMsg& m);
std::ostream& operator<<(std::ostream& o, HTTPMsg::Method m);
std::istream& operator>>(std::istream& in, HTTPMsg::Method& m);
std::ostream& operator<<(std::ostream& o, HTTPMsg::TransferEncoding te);
std::ostream& operator<<(std::ostream& o, HTTPMsg::ContentEncoding ce);
std::istream& operator>>(std::istream& in, HTTPMsg::ContentEncoding& ce);
std::ostream& operator<<(std::ostream& o, HTTPMsg::Version v);

#endif
