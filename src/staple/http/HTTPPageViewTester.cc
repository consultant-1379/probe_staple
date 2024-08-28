#include <errno.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <stdlib.h>

#include <staple/http/HTTPEngine.h>
#include "HTTPPageViewTester.h"
#include "Resource.h"
#include "HTTPMsg.h"
#include "HTTPUser.h"

using std::vector;
using std::cerr;
using std::endl;
using std::ostream;
using std::fstream;
using std::ios_base;

HTTPPageViewTester::HTTPPageViewTester()
{
	file_ = getenv("HTTP_PAGEVIEW_TEST");
	if (file_) {
		fout_.open(file_, ios_base::out|ios_base::trunc);
		if (!fout_.is_open()) {
			cerr << "HTTPPageViewTester: Failed to open test output file: "
			     << "'" << file_ << "': " << strerror(errno) << '\n';
		}
	}
}

HTTPPageViewTester::~HTTPPageViewTester()
{
	for (vector<Resource*>::iterator it = pageViews_.begin(); it != pageViews_.end(); ++it)
		delete *it;

	fout_.close();
}

class PrintVisitor : public ResourceVisitor
{
public:
	PrintVisitor(ostream& o, Timeval start) :
		out_(o), start_(start)
		{ }

	void print(HTTPMsg* msg, int depth)
		{
			while (depth--)
				out_ << "    ";
			out_ << "    sub: ";
			char buf[64];
			snprintf(buf, sizeof(buf), "(start: %.3f end: %.3f) ",
				 msg->getReqStartTime().diff(start_),
				 msg->getRspEndTime().diff(start_));
			out_ << buf;
			msg->printTestOutput(out_);
			out_ << '\n';
		}

	void visit(const Resource* r, int depth)
		{ print(r->getMain(), depth); }
private:
	ostream& out_;
	Timeval start_;
};

void HTTPPageViewTester::printResource(const Resource* r)
{
	const HTTPMsg* main = r->getMain();
	const vector<Resource*>& subs = r->getParts();
	Timeval start(main->getReqStartTime());
	char buf[32];
	snprintf(buf, sizeof(buf), "%.3f", r->downloadTime());
	fout_ << "Total time: " << buf << ' '
	      << start;
	snprintf(buf, sizeof(buf), "%.3f", main->getRspEndTime().diff(start));
	fout_ << " (main duration: " << buf << " s)"
	      << " client IP: " << getClientIP(main->getTCPConnId())
	      << " referer: " << main->getReferer()
	      << " subresources: " << r->numResources()-1
	      << " content-type: " << main->getContentType()
	      << ' ';
	main->printTestOutput(fout_);
	fout_ << " user-agent: " << main->getReqHeader("User-Agent")
	      << '\n';

	PrintVisitor pv(fout_, start);
	for (vector<Resource*>::const_iterator it = subs.begin(); it != subs.end(); ++it)
		(*it)->visit(&pv, 0);

	fout_ << endl;
}

void HTTPPageViewTester::addPageView(const Resource* r)
{
	if (!fout_.is_open())
		return;

	printResource(r);
}

void HTTPPageViewTester::addLonelyResource(const Resource* r)
{
	if (!fout_.is_open())
		return;

	fout_ << "lonely ";
	printResource(r);
}
