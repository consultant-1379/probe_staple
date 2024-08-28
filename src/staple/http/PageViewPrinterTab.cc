#include <errno.h>
#include <string.h>

#include <vector>

#include <staple/Staple.h>
#include <staple/http/HTTPEngine.h>
#include <staple/http/log.h>

#include "PageViewPrinterTab.h"
#include "HTTPMsg.h"
#include "HTTPUser.h"
#include "PageInfo.h"
#include "LogFile.h"
#include "DataRWTab.h"
#include "HTTPConnection.h"
#include "Resource.h"
#include "boost-reimplementation.h"
#include "MessageInfo.h"

using std::string;
using std::vector;

PageViewPrinterTab::PageViewPrinterTab(const Staple& staple) :
	pageID_(0),
	staple_(staple)
{ }

PageViewPrinterTab::~PageViewPrinterTab()
{ }

/* For the MBBA we only log some requests. This is done to reduce disk
 * space usage and still support the MBBA S-KPIs.
 */
static bool shouldLogRequest(const MessageInfo& mi)
{
#if MBBA_OUTPUT
	const char* uri = mi.uri.c_str();
	if (iends_with(mi.serverHost.c_str(), "youtube.com") && starts_with(uri, "/videoplayback")) {
		return true;
	} else {
		return iends_with(uri, ".zip") ||
			iends_with(uri, ".pdf");
	}
#else
	return true;
#endif
}

void PageViewPrinterTab::writeRequests(const Resource* r)
{
	if (dwRequest_.getLogFile()) {
		vector<MessageInfo> msgInfos(MessageInfo::create(*r, pageID_));
		for (vector<MessageInfo>::iterator it = msgInfos.begin(); it != msgInfos.end(); ++it) {
			if (shouldLogRequest(*it))
				it->write(dwRequest_);
		}
	}
}

void PageViewPrinterTab::setPageLog(LogFile* lf)
{
	dwPage_.setLogFile(lf);
}

void PageViewPrinterTab::setRequestLog(LogFile* lf)
{
	dwRequest_.setLogFile(lf);
}

LogFile* PageViewPrinterTab::getPageLog()
{
	return dwPage_.getLogFile();
}

LogFile* PageViewPrinterTab::getRequestLog()
{
	return dwRequest_.getLogFile();
}

void PageViewPrinterTab::printPageView(const Resource* r)
{
	if (dwPage_.getLogFile()) {
		PageInfo pi(*r);
		pi.write(dwPage_, pageID_);
	}

	writeRequests(r);
	pageID_++;
}

void PageViewPrinterTab::printLonelyResource(const Resource* r)
{
	writeRequests(r);
	pageID_++;
}
