#include <staple/http/HTTPEngine.h>
#include "PageInfo.h"
#include "DataRWTab.h"
#include "Resource.h"
#include "boost-reimplementation.h"

using std::string;
using std::ostream;
using std::endl;

class CachedCountVisitor : public ResourceVisitor
{
public:
	int count_;

	CachedCountVisitor() { count_ = 0; }

	void visit(const Resource* r, int)
		{
			// 304 is "Not Modified"
			if (r->getMain()->getRspStatusCode() == 304)
				count_++;
		}
};

PageInfo::PageInfo(const Resource& r) :
	start(r.getStartTime()),
	serverHost(r.getMain()->getHost()),
	clientIP(getClientIP(r.getMain()->getTCPConnId())),
	duration(r.downloadTime()),
	numResources(r.numResources()),
	bytesNetworkUL(r.getBytesNetworkUL()),
	bytesNetworkDL(r.getBytesNetworkDL())
{
	CachedCountVisitor ccv;
	r.visit(&ccv, 0);
	numCachedResources = ccv.count_;

	HTTPMsg* m = r.getMain();
	uri = m->getReqURI();
	referer = m->getReferer();
	userAgent = m->getReqHeader("User-Agent");
	completeResponse = r.completeResponse();
	accessTime = m->getRspStartTime().diff(m->getReqStartTime());
}

string shortenURL(const string& host, const string& url)
{
/* The MBBA project wants shortened URLs. */
#if MBBA_OUTPUT
	if (iends_with(host.c_str(), "youtube.com") && starts_with(url.c_str(), "/videoplayback")) {
		// Special case youtube videos to support MBBA S-KPIs.
		return string("/videoplayback");
	} else {
		// Extract file extension for other hosts.
		int i, size = url.size();
		for (i = size-1; i >= 0 && i >= size-10; i--) {
			if (url[i] == '.')
				return string(url.begin()+i+1, url.end());
		}

		return string();
	}
#else
	return url;
#endif
}

void PageInfo::writeColumns(ostream& out)
{
	out << "start time,\n"
		"server host,\n"
		"client IP,\n"
		"download time (time from first request packet to last response packet),\n"
		"number of resources,\n"
		"number of cached resources (number of resources with response status code 304, Not Modified),\n"
		"bytes network UL,\n"
		"bytes network DL,\n"
		"first " << MAX_URI_LENGTH << " bytes of request URL,\n"
		"first " << MAX_URI_LENGTH << " bytes of referer,\n"
		"User-Agent HTTP header,\n"
		"pageID (this is the same page ID that is used in the webreq log files),\n"
		"complete response (1 if all responses were fully and successfully downloaded, i.e., we saw the whole response and the response status code was 2xx or 3xx, otherwise 0),\n"
		"access time (time from the first request packet to the first response packet),\n"
	    << endl;
}

void PageInfo::write(DataWriterTab& dw, int pageID)
{
	dw.write(start.toDouble());
	dw.write(serverHost);
	dw.write(clientIP);
	dw.write(duration);
	dw.write(numResources);
	dw.write(numCachedResources);
	dw.write(bytesNetworkUL);
	dw.write(bytesNetworkDL);

	dw.write(shortenURL(serverHost, uri), MAX_URI_LENGTH);
#if MBBA_OUTPUT
	dw.write("");
	dw.write("");
#else
	dw.write(referer, MAX_URI_LENGTH);
	dw.write(userAgent);
#endif
	dw.write(pageID);
	dw.write((int) completeResponse);
	dw.write(accessTime);
//	dw.write(numHosts);
	dw.endRecord();
}

PageInfo PageInfo::read(DataReaderTab& dr, int* pageID)
{
	PageInfo pm;

	pm.start = Timeval(dr.readDouble());
	pm.serverHost = dr.readString();
	pm.clientIP = dr.readIPAddress();
	pm.duration = dr.readDouble();
	pm.numResources = dr.readInt();
	pm.numCachedResources = dr.readInt();
	pm.bytesNetworkUL = dr.readInt();
	pm.bytesNetworkDL = dr.readInt();
	pm.uri = dr.readString();
	dr.readString(); // referer
	dr.readString(); // user-agent
	int pid = dr.readInt(); // page ID
	if (pageID)
		*pageID = pid;
	pm.completeResponse = dr.readInt();
	pm.accessTime = dr.readDouble();
	dr.endRecord();
	return pm;
}
