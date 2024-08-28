#ifndef MESSAGEINFO_H
#define MESSAGEINFO_H

#include <vector>
#include <string>
#include <ostream>

#include <staple/TCPConn.h>
#include <staple/http/Timeval.h>
#include "HTTPMsg.h"

class Resource;
class HTTPMsg;
class DataReaderTab;
class DataWriterTab;

class MessageInfo
{
private:
	static void createRecur(std::vector<MessageInfo>* res,
				const Resource* r,
				int pageId,
				int depth);

public:
	MessageInfo(const HTTPMsg& msg, int pageId, int depth);
	MessageInfo() { }

	void read(DataReaderTab&);
	void write(DataWriterTab&) const;

	static std::vector<MessageInfo> create(const Resource&, int pageId);
	static void writeColumns(std::ostream&);

	/* ID of current page.
	 *
	 * All messages belonging to one page will be consecutive in
	 * the log file.
	 *
	 * NOTE: We may end up with duplicated IDs if the program is
	 * restarted. This should be taken care of by looking at the
	 * start times or by using the fact that all messages
	 * belonging to the same page are consecutive in the log
	 * files.
	 */
	int pageId;

        /* Depth this message is on in the tree of resources making up
	 * the page we are in.
	 */
	int depth;

	Timeval start;
	std::string serverHost;
	TCPConnId connId;
	double accessTime;
	double duration;
	int bytesNetworkUL;
	int bytesNetworkDL;

	static const int MAX_URI_LENGTH = 100;
	std::string uri;
	std::string referer;
	int statusCode;
	bool completeResponse;
	std::string contentType;
	std::string userAgent;
	HTTPMsg::Method method;
	std::string reqCacheControl;
	std::string rspCacheControl;
	HTTPMsg::ContentEncoding contentEncoding;
};

#endif
