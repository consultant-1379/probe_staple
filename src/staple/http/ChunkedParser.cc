#include <assert.h>
#include <stdlib.h>

#include <staple/Staple.h>
#include "ChunkedParser.h"
#include "HTTP-helpers.h"
#include "HTTPMsg.h"
#include "string-utils.h"

using std::vector;

/*

From RFC 2616 (HTTP)

Section 3.6.1, "Chunked Transfer Coding":

       Chunked-Body   = *chunk
                        last-chunk
                        trailer
                        CRLF
       chunk          = chunk-size [ chunk-extension ] CRLF
                        chunk-data CRLF
       chunk-size     = 1*HEX
       last-chunk     = 1*("0") [ chunk-extension ] CRLF
       chunk-extension= *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
       chunk-ext-name = token
       chunk-ext-val  = token | quoted-string
       chunk-data     = chunk-size(OCTET)
       trailer        = *(entity-header CRLF)

Section 19.4.6, "Introduction of Transfer-Encoding", in the same RFC
has an algorithm for parsing transfer-encoding: chunked in
pseudo-code. We don't follow it exactly in the implementation below,
but they are quite similar.

HTTP/1.1 introduces the Transfer-Encoding header field (section
14.41). Proxies/gateways MUST remove any transfer-coding prior to
forwarding a message via a MIME-compliant protocol.

A process for decoding the "chunked" transfer-coding (section 3.6) can
be represented in pseudo-code as:

       length := 0
       read chunk-size, chunk-extension (if any) and CRLF
       while (chunk-size > 0) {
          read chunk-data and CRLF
          append chunk-data to entity-body
          length := length + chunk-size
          read chunk-size and CRLF
       }
       read entity-header
       while (entity-header not empty) {
          append entity-header to existing header fields
          read entity-header
       }
       Content-Length := length
       Remove "chunked" from Transfer-Encoding
*/

ChunkedParser::ChunkedParser(Staple& staple) : staple_(staple)
{
	state_ = START;
	curChunkSize_ = 0;
	receivedBytesOfCurChunk_ = 0;
	totalLen_ = 0;
}

bool ChunkedParser::done() const
{
	return state_ == END;
}


// Parse chunk-size.
// chunk-size     = 1*HEX
// Precondition: [buf, end) contains a non-isxdigit character after chunk-size.
const Byte* ChunkedParser::parseChunkSize(const Byte* buf, const Byte* end, long* size)
{
	buf = skipSpace(buf, end);
	CHECKED_RETURN_INIT(buf, end);
	const Byte* sizeEnd = buf;
	while (sizeEnd != end && isxdigit(*sizeEnd))
		sizeEnd++;

	if (sizeEnd == buf || sizeEnd == end)
		return NULL;

	const Byte* ret;
	*size = strtol((const char*) buf, (char**) &ret, 16);
	if (*size < 0)
		return NULL;
	else if (*size > HTTPMsg::MAX_CONTENT_LENGTH)
		return NULL;

	if (ret == buf)
		return NULL;

	CHECKED_RETURN(ret);
}

const Byte* ChunkedParser::parse(const Byte* buf, const Byte* end, vector<Byte>* body)
{
	CHECKED_RETURN_INIT(buf, end);
	const Byte* newBuf;
	while (true) {
		int len = end - buf;
		if (!len)
			CHECKED_RETURN(buf);

		switch (state_) {
		case START:
		{
			// chunk          = chunk-size [ chunk-extension ] CRLF
			//                  chunk-data CRLF
			// last-chunk     = 1*("0") [ chunk-extension ] CRLF

			// This state parses the chunk-size, chunk-extension and CRLF.
			const Byte* crlf = findCRLF(buf, end);
			if (crlf == end) {
				if (len > 1024) {
					WARN("ChunkedParser::parse: No CRLF found. ", quoteString(buf, end));
					return NULL;
				} else {
					// Need more data.
					CHECKED_RETURN(buf);
				}
			}
			
			newBuf = parseChunkSize(buf, crlf+2, &curChunkSize_);
			if (newBuf == NULL) {
				WARN("ChunkedParser::parse: Failed to parse size. ", quoteString(buf, end));
				return NULL;
			}
			// Skip chunk-extension
			buf = crlf+2;
			receivedBytesOfCurChunk_ = 0;

			if (curChunkSize_ == 0)
				state_ = TRAILER;
			else
				state_ = CHUNK;
			break;
		}
		case CHUNK:
			// This state parses the chunk-data
			if (receivedBytesOfCurChunk_ + len < curChunkSize_) {
				// Got part of chunk.
				if (body)
					body->insert(body->end(), buf, buf+len);

				receivedBytesOfCurChunk_ += len;
				totalLen_ += len;
				buf = end;
			} else {
				// Got entire chunk.
				// Some data may remain unparsed in the packet.
				int partLen = curChunkSize_ - receivedBytesOfCurChunk_;
				if (body)
					body->insert(body->end(), buf, buf+partLen);

				buf = buf + partLen;
				totalLen_ += partLen;
				receivedBytesOfCurChunk_ = curChunkSize_;
				state_ = CHUNK_CRLF;
			}

			break;

		case CHUNK_CRLF:
			// This state parses the CRLF after the chunk-data
			if (len < 2) {
				// Need more data.
				CHECKED_RETURN(buf);
			} else if (findCRLF(buf, end) == buf) {
				buf += 2;
				state_ = START;
			} else {
				WARN("ChunkedParser::parse: No CRLF after chunk data. ",
				     quoteString(buf, end));
				return NULL;
			}
			break;

		case TRAILER:
		{
			// Parse trailer
			// trailer        = *(entity-header CRLF)
			const Byte* crlf = findCRLF(buf, end);
			if (crlf == end) {
				// FIXME is 4096 appropriate? Look in HTTP RFC.
				if (len > 4096) {
					// Does not look like a HTTP response.
					WARN("ChunkedParser::parse: CRLF not found in headers. ",
					     quoteString(buf, end));
					return NULL;
				} else {
					// Need more data.
					CHECKED_RETURN(buf);
				}
			}

			if (crlf == buf) {
				state_ = END;
				buf += 2;
			} else {
				newBuf = parseHeader(buf, end, &headers_);
				if (newBuf == NULL) {
					WARN("ChunkedParser::parse: Strange header, ignoring. ",
					     quoteString(buf, end));
					buf = crlf+2;
				} else {
					buf = newBuf;
				}

				// Look for more headers.
			}
			break;
		}

		case END:
			CHECKED_RETURN(buf);
		}
	}
}
