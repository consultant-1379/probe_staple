#include <assert.h>
#include <iostream>
#include <limits>
#include <sys/time.h>

#include <staple/Packet.h>
#include <staple/TCPConn.h>
#include <staple/http/log.h>
#include <staple/http/Timeval.h>

#include "HTTPMsg.h"
#include "Resource.h"
#include "PageViewPrinter.h"
#include "HTTPPageViewTester.h"

using std::ostream;

Resource::Resource(HTTPMsg* msg) : owner_(NULL), main_(msg), endTime_(main_->getRspEndTime())
{ }

Resource::~Resource()
{
	delete main_;
	for (ResourceList::iterator it = parts_.begin(); it != parts_.end(); ++it)
		delete *it;
}

void Resource::setOwner(Resource* r)
{
	assert(!owner_);
	assert(this != r);
	owner_ = r;
}

const Resource* Resource::getRootOwner() const
{
	if (getOwner() == NULL)
		return this;
	else
		return getOwner()->getRootOwner();
}

void Resource::printSummary(ostream& o) const
{
	printSummaryImpl(o, 0);
}

Resource* Resource::clone() const
{
	Resource* r = new Resource(new HTTPMsg(*main_));
	for (ResourceList::const_iterator it = parts_.begin(); it != parts_.end(); ++it) {
		Resource* sub = *it;
		if (!r->add(sub->clone()))
			assert(false);
	}
	return r;
}

static void printIndent(ostream& o, int indent)
{
	while(indent--)
		o << ' ';
}

void Resource::updateEndTime(const Timeval& end)
{
	if (endTime_ < end) {
		endTime_ = end;
		if (getOwner())
			getOwner()->updateEndTime(endTime_);
	}
}

bool Resource::add(Resource* r)
{
	assert(!r->getOwner());
	if (getRootOwner() == r)
		return false;

	r->setOwner(this);
	parts_.push_back(r);
	updateEndTime(r->getEndTime());
	return true;
}

double Resource::downloadTime() const
{
	Timeval start(main_->getReqStartTime());
	Timeval end(getEndTime());
	return end.diff(start);
}

int Resource::getBytesNetworkDL() const
{
	int bytes = getMain()->getBytesNetworkDL();
	for (ResourceList::const_iterator it = parts_.begin(); it != parts_.end(); ++it) {
		Resource* sub = *it;
		bytes += sub->getBytesNetworkDL();
	}

	return bytes;
}

int Resource::getBytesNetworkUL() const
{
	int bytes = getMain()->getBytesNetworkUL();
	for (ResourceList::const_iterator it = parts_.begin(); it != parts_.end(); ++it) {
		Resource* sub = *it;
		bytes += sub->getBytesNetworkUL();
	}

	return bytes;
}

Timeval Resource::getStartTime() const
{
	return main_->getReqStartTime();
}

void Resource::printSummaryImpl(ostream& o, int indent) const
{
	Timeval start(main_->getReqStartTime());
	printIndent(o, indent);
	if (parts_.empty()) {
		o << "(start: " << main_->getReqStartTime().diff(start)
		  << " end: " << main_->getRspEndTime().diff(start) << ") "
		  << *main_
		  << '\n';
	} else {
		o << "Total time: " << downloadTime()
		  << ' ' << start
		  << " (main duration: " << main_->getRspEndTime().diff(start) << ") "
		  << " referer: " << main_->getReferer() << ' '
		  << "subresources: " << parts_.size() << ' '
		  << *main_
		  << '\n';
		for (ResourceList::const_iterator it = parts_.begin(); it != parts_.end(); ++it) {
			Resource* sub = *it;
			sub->printSummaryImpl(o, indent+1);
		}
	}
}

int Resource::numResources() const
{
	int ret = 1;
	for (ResourceList::const_iterator it = parts_.begin(); it != parts_.end(); ++it) {
		Resource* sub = *it;
		ret += sub->numResources();
	}
	return ret;
}

bool Resource::completeResponse() const
{
	if (!getMain()->responseParsed())
		return false;

	int s = getMain()->getRspStatusCode();
	if (!((200 <= s && s < 300) || // 2xx is Successful
	      (300 <= s && s < 400)))  // 3xx is Redirection
		return false;

	for (ResourceList::const_iterator it = parts_.begin(); it != parts_.end(); ++it) {
		Resource* sub = *it;
		if (!sub->completeResponse())
			return false;
	}

	return true;
}

void Resource::visit(ResourceVisitor* rv, int depth) const
{
	rv->visit(this, depth);
	for (ResourceList::const_iterator it = parts_.begin(); it != parts_.end(); ++it) {
		Resource* sub = *it;
		sub->visit(rv, depth+1);
	}
}
