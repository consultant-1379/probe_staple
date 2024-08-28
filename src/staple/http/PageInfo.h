#ifndef PAGEINFO_H
#define PAGEINFO_H

#include <string>
#include <ostream>

#include <staple/http/IPAddress.h>
#include <staple/http/Timeval.h>

class Resource;
class DataWriterTab;
class DataReaderTab;

std::string shortenURL(const std::string& host, const std::string& url);

class PageInfo
{
public:
	explicit PageInfo(const Resource&);
	PageInfo() { }

	Timeval start;
	std::string serverHost;
	IPAddress clientIP;
	double duration;
	int numResources;
	int bytesNetworkUL;
	int bytesNetworkDL;
	int numCachedResources;

	static const int MAX_URI_LENGTH = 100;

	/* Only the first MAX_URI_LENGTH bytes of the uri and referer
	 * are written to log files
	 */
	std::string uri;
	std::string referer;
	std::string userAgent;
	bool completeResponse;
	double accessTime;

	static void writeColumns(std::ostream& out);
	void write(DataWriterTab& dw, int pageID);
	static PageInfo read(DataReaderTab&, int* pageID = NULL);
};

#endif
