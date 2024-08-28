#ifndef CHUNKEDPARSER_H
#define CHUNKEDPARSER_H

#include <vector>

#include <staple/Type.h>
#include <staple/http/globals.h>

class HTTPHeader;
class Staple;

/* Class to parse entity body encoded with transfer-encoding:
 * chunked.
 */
class ChunkedParser
{
public:
	ChunkedParser(Staple&);

	// Parse the data in [buf, end). If 'body' is not NULL, then
	// the decoded data is appended to '*body'.
	const Byte* parse(const Byte* buf, const Byte* end, std::vector<Byte>* body);
	bool done() const;

	// Get length of body parsed so far.
	long getBodyLength() const { return totalLen_; }
	const std::vector<HTTPHeader>& getHeaders() const { return headers_; }

private:
	// We allow copying of ChunkedParser to allow copying of HTTPMsg.

	enum ParseState {START, CHUNK, CHUNK_CRLF, TRAILER, END};
	const Byte* parseChunkSize(const Byte* buf, const Byte* end, long* size);

	Staple& staple_;
	ParseState state_;
	long curChunkSize_, receivedBytesOfCurChunk_, totalLen_;
	std::vector<HTTPHeader> headers_;
};

#endif
