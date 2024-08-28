#ifndef HTTPUSER_H
#define HTTPUSER_H

#include <map>
#include <string>
#include <list>
#include <set>

#include <staple/TCPConn.h>
#include <staple/http/globals.h>
#include <staple/http/IPAddress.h>
#include <staple/http/Timeval.h>

class HTTPMsg;
class HTTPPageViewTester;
class HTTPMsgTester;
class PageViewPrinter;
class Timeval;
class HTTPUser;
class Resource;
class HTTPConnection;
class TCPPacket;
class Staple;

/* Keep track of the page views that originates from one user. We
 * assume that distinct source IP addresses belongs to distinct
 * users. There is therefore a one-to-one mapping between source IP
 * addresses and HTTPUser objects. In a network where we see
 * connections originating from a proxy the proxy will have one
 * HTTPUser object.
 */
class HTTPUser
{
public:
	HTTPUser(Staple& staple, const IPAddress&, PageViewPrinter*, HTTPPageViewTester*, HTTPMsgTester*);
	~HTTPUser();

	void processPacket(const TCPPacket& packet);
	void finishAllTCPSessions();
	void finishTCPSession(const TCPConnId& id);
	Timeval getLastActivity() const
	{ return lastAct_; }
	bool hasConnections() const
	{ return !connections_.empty(); }

	/* Ownership of 'msg' transfered to HTTPUser.
	 */
	void associateWithPageView(HTTPMsg* msg);

	/* Print summary of open connections and non-consumed page
	 * views.
	 */
	void printSummary(std::ostream&) const;

	const IPAddress& getClientIP() const { return srcIP_; }

	/* After this many seconds a Resource is closed. The resource
	 * is then consumed and no more resources can be added to it.
	 */
	const static double TIMEOUT = 60;

	struct Stats {
		Stats();

		unsigned long pagesSeen;
		unsigned long tcpNum;
		unsigned long reqNum;
		unsigned long rspNum;
	};

	const Stats& getStats() const { return stats_; }

private:
	DISALLOW_COPY_AND_ASSIGN(HTTPUser);

	Stats stats_;
	Staple& staple_;
	typedef std::unordered_map<TCPConnId, HTTPConnection*> ConnMap;
	ConnMap connections_;
	Timeval lastAct_;

	/* Sometimes it seems that image downloads are started before
	 * the HTML download that contains the image! See dayviews.com
	 * in web.dump for an example. I'm not sure why we see this,
	 * maybe the browser speculatively downloads these based on
	 * historic information on what's needed. Or maybe there is
	 * problem with the timestamps (more likely). Or maybe the
	 * packets gets reordered somewhere.
	 *
	 * We use the following constant as an upper bound on the
	 * number of seconds the subresource download can be started
	 * before the main resource download.
	 */
	const static double MAIN_SUB_BOUND = 0.5;

	/* If we don't see any activity on page, then we close it
	 * after this many seconds. (The actual implementation is a
	 * bit different, we will always wait TIMEOUT seconds before
	 * closing and consuming a page, but we will not add new
	 * resources that was started more than INACTIVITY_TIMEOUT
	 * seconds after the end of the last resource we already
	 * have.
	 */
	const static double INACTIVITY_TIMEOUT = 1;

	/* text/html resources with less than RESOURCES_IN_FRAME
	 * subresources will be considered as frames.
	 */
	const static unsigned int RESOURCES_IN_FRAME = 6;

	Resource* createResource(HTTPMsg* msg);
	Resource* createAggregateResource(HTTPMsg* msg);

	/* Add 'sub' as a subresource in 'r'. Ownership of 'sub' is
	 * transferred to 'r'. Return value indicates success or
	 * not. If false is returned the resource was not added and
	 * ownership is not transferred. See also
	 * Resource::add.
	 */
	bool addSubResourceImpl(Resource* r, Resource* sub);

	/* Same as addSubResourceImpl but try to add frames from
	 * possibleFrame_ as well.
	 */
	bool addSubResource(Resource* r, Resource* sub);

	// Consume a resource. It is removed from pageMap_ sent to the
	// tester, a summary is printed with Resource::printSummary,
	// and finally deleted (so ownership of 'r' transfered).
	void consumeResource(Resource* r);

	// Remove r and all resources owned by r from pageMap_ and
	// redirectSources_.
	void closeResource(Resource* r);

	// Consume resources from pages_, earlySubs_, and
	// possibleFrames_ that have timed out.
	void checkTimeout(const Timeval& curTime);

	// Map URL of main resource to Resource. This data structure
	// doesn't own its contents. When an entry is removed the
	// Resource should _not_ be deleted!

	// FIXME Use unordered_map instead?
	typedef std::map<std::string, Resource*> PageMap;
	PageMap pageMap_;

	typedef std::list<Resource*> ResourceList;
	typedef std::set<Resource*> ResourceSet;

	/* This list holds resources with status code 3xx that has a
	 * Location header. This list does _not_ own the resources
	 * contained in it.
	 */
	ResourceSet redirectSources_;

	/* Look in redirectSources_ to see if there is a suitable
	 * redirection that matches 'target'. That is, look for a
	 * Resource 'r' in redirectSources_ such that r->getLocation()
	 * equals the request URL of 'target'.
	 *
	 * If a suitable 'r' is found, 'target' is added as a
	 * subresource to 'r' and the function returns
	 * true. Otherwise, false is returned.
	 */
	bool addRedirectionTarget(Resource* target);

	void pagesAdd(Resource* r);
	void possibleFramesAdd(Resource* r);
	void earlySubsAdd(Resource* r);

	void updateFirstStoredTime(const Resource* r);
	PageMap::iterator pageMapFind(const std::string& referer);

	/* The minimum of all start times of the resources stored in
	 * pages_, possibleFrames_, and earlySubs_. By keeping track
	 * of the minimum start time checkTimeout is often very
	 * efficient (in the fast path there is only one comparision
	 * of two Timevals, we don't have to traverse the pages_,
	 * possibleFrames_, and earlySubs_ lists at all).
	 */
	 Timeval firstStoredTime_;

	// The three lists below, pages_, earlySubs_, and
	// possibleFrames_ own the resources they contain. When a
	// resource is removed from these lists either it has to be
	// deleted or the ownership should be transfered to someone
	// else. New resources are added at the back, old ones are
	// removed when they time out, see checkTimeout.

	// FIXME These should probably be maps from referer to
	// list<Resource*>, or something like that.

	// Resources of main content-type with empty referer are
	// push_back on this list. These are typically text/html
	// pages which are not frames.
	ResourceList pages_;

	// Sometimes we see a request for a subresource _before_ the
	// response for the main resource is complete. We store such
	// potential early subresources in this list.
	ResourceList earlySubs_;

	// This list holds possible frames. It typically contains
	// text/html that have a referer.
	ResourceList possibleFrames_;

	IPAddress srcIP_;
	PageViewPrinter* printer_;
	HTTPPageViewTester* pageTester_;
	HTTPMsgTester* msgTester_;
};

#endif
