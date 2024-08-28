#include <sstream>

#include <staple/http/HTTPEngine.h>
#include "Resource.h"
#include "MessageInfo.h"
#include "DataRWTab.h"
#include "PageInfo.h"
#include "string-utils.h"

using std::vector;
using std::string;
using std::ostream;
using std::endl;
using std::stringstream;

void MessageInfo::createRecur(std::vector<MessageInfo>* res, const Resource* r, int pageId, int depth)
{
	MessageInfo mi(*r->getMain(), pageId, depth);
	res->push_back(mi);
	const vector<Resource*>& subs = r->getParts();
	for (vector<Resource*>::const_iterator it = subs.begin(); it != subs.end(); ++it)
		createRecur(res, *it, pageId, depth+1);
}

vector<MessageInfo> MessageInfo::create(const Resource& r, int pageId)
{
	vector<MessageInfo> v;
	createRecur(&v, &r, pageId, 0);
	return v;
}

MessageInfo::MessageInfo(const HTTPMsg& msg, int pId, int d)
{
	start = msg.getReqStartTime();
	pageId = pId;
	depth = d;
	serverHost = msg.getHost();
	connId = msg.getTCPConnId();
	accessTime = msg.getRspStartTime().diff(msg.getReqStartTime());
	duration = msg.getRspEndTime().diff(msg.getReqStartTime());
	bytesNetworkUL = msg.getBytesNetworkUL();
	bytesNetworkDL = msg.getBytesNetworkDL();
	method = msg.getReqMethod();
	uri = msg.getRequestURI();
	statusCode = msg.getRspStatusCode();
	completeResponse = msg.responseParsed();
	contentType = msg.getContentType();
	referer = msg.getReferer();
	userAgent = msg.getReqHeader("User-Agent");
	reqCacheControl = msg.getReqHeader("Cache-Control");
	rspCacheControl = msg.getRspHeader("Cache-Control");
	contentEncoding = msg.getContentEncoding();
}

void MessageInfo::writeColumns(ostream& o)
{
	o << "start time,\n"
	  << "pageID (All resources belonging to the same page have the same pageID. The same page ID is used in the webpage log files),\n"
	  << "depth (The depth at which this resource is at in the tree of resources that makes up the page.),\n"
	  << "server host,\n"
	  << "server IP,\n"
	  << "server port,\n"
	  << "client IP,\n"
	  << "client port,\n"
	  << "access time (time from the first request packet to the first response packet),\n"
	  << "download time (time from the first request packet to the last response packet),\n"
	  << "bytes network UL,\n"
	  << "bytes network DL,\n"
	  << "method (method used in the HTTP request),\n"
	  << "first " << PageInfo::MAX_URI_LENGTH << " bytes of request URL,\n"
	  << "response status code (0 if the status code was not successfully parsed),\n"
	  << "complete response (1 if the response were fully and successfully downloaded, i.e., we saw the whole response and the response status code was 2xx or 3xx, otherwise 0),\n"
	  << "Content-Type (based on Content-Type HTTP header and/or sniffed from response data),\n"
	  << "first " << PageInfo::MAX_URI_LENGTH << " bytes of referer,\n"
	  << "User-Agent HTTP header,\n"
	  << "request Cache-Control HTTP header,\n"
	  << "response Cache-Control HTTP header,\n"
	  << "Content-Encoding HTTP header,\n"
	  << endl;
}

void MessageInfo::read(DataReaderTab& dr)
{
	start = Timeval(dr.readDouble());
	pageId = dr.readInt();
	depth = dr.readInt();
	serverHost = dr.readString();
	setServerIP(&connId, dr.readIPAddress());
	setServerPort(&connId, dr.readInt());
	setClientIP(&connId, dr.readIPAddress());
	setClientPort(&connId, dr.readInt());
	accessTime = dr.readDouble();
	duration = dr.readDouble();
	bytesNetworkUL = dr.readInt();
	bytesNetworkDL = dr.readInt();
	method = dr.readMethod();
	uri = dr.readString();
	statusCode = dr.readInt();
	completeResponse = dr.readInt();
	contentType = dr.readString();
	referer = dr.readString();
	userAgent = dr.readString();
	reqCacheControl = dr.readString();
	rspCacheControl = dr.readString();
	stringstream ss(dr.readString());
	ss >> contentEncoding;
	dr.endRecord();
}

void MessageInfo::write(DataWriterTab& dw) const
{
	dw.write(start.toDouble());
	dw.write(pageId);
	dw.write(depth);
	dw.write(serverHost);
	dw.write(getServerIP(connId));
	dw.write(getServerPort(connId));
	dw.write(getClientIP(connId));
	dw.write(getClientPort(connId));
	dw.write(accessTime);
	dw.write(duration);
	dw.write(bytesNetworkUL);
	dw.write(bytesNetworkDL);
	dw.write(method);
	dw.write(shortenURL(serverHost, uri), PageInfo::MAX_URI_LENGTH);
	dw.write(statusCode);
	dw.write((int) completeResponse);
	dw.write(contentType);
#if MBBA_OUTPUT
	/* Save some disk space */
	dw.write("");
	dw.write("");
	dw.write("");
	dw.write("");
#else
	dw.write(referer, PageInfo::MAX_URI_LENGTH);
	dw.write(userAgent);
	dw.write(reqCacheControl);
	dw.write(rspCacheControl);
#endif
	dw.write(toString(contentEncoding));
	dw.endRecord();
}
