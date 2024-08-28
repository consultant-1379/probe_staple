#include <assert.h>

#include <staple/Staple.h>
#include <staple/http/log.h>
#include <staple/http/HTTPEngine.h>
#include "HTTPUser.h"
#include "Resource.h"
#include "HTTPMsg.h"
#include "HTTPPageViewTester.h"
#include "HTTPMsgTester.h"
#include "PageViewPrinter.h"
#include "HTTPConnection.h"
#include "boost-reimplementation.h"

using std::ostream;
using std::cout;
using std::endl;
using std::string;
using std::list;

HTTPUser::HTTPUser(Staple& staple,
		   const IPAddress& ip,
		   PageViewPrinter* printer,
		   HTTPPageViewTester* pageTester,
		   HTTPMsgTester* msgTester) :
	staple_(staple),
	firstStoredTime_(Timeval::endOfTime()),
	srcIP_(ip),
	printer_(printer),
	pageTester_(pageTester),
	msgTester_(msgTester)
{
	COUNTER_INCREASE("HTTPUser constructed");
}

HTTPUser::~HTTPUser()
{
	finishAllTCPSessions();

	assert(pages_.empty());
	assert(earlySubs_.empty());
	assert(possibleFrames_.empty());
}

void HTTPUser::printSummary(ostream& o) const
{
	cout << "HTTPUser::printSummary "
	     << " IP: " << srcIP_
	     << " connections: " << connections_.size()
	     << " pages_: " << pages_.size()
	     << " earlySubs_: " << earlySubs_.size()
	     << " possibleFrames_: " << possibleFrames_.size()
	     << '\n';
	for (ConnMap::const_iterator it = connections_.begin(); it != connections_.end(); ++it) {
		cout << it->first << '\n';
		const HTTPConnection::HTTPMessages& msgs = it->second->getMessages();
		for (HTTPConnection::HTTPMessages::const_iterator it = msgs.begin(); it != msgs.end(); ++it) {
			cout << '\t' << **it << '\n';
		}
		cout << '\n';
	}
	for (PageMap::const_iterator it = pageMap_.begin(); it != pageMap_.end(); ++it) {
		cout << "Referer '" << it->first << "':\n";
		it->second->printSummary(cout);
		cout << '\n';
	}
}

/* 'm' should be a STL style map (std::map and std::unordered_map are
 * ok). insertNULL(m, key, newKey, it) associated NULL with 'key' in
 * 'm' unless there something is already associated with 'key' in
 * 'm'. 'it' will be set to the std::pair containing 'key'.
 *
 * This function is used to associate a pointer with 'key' unless
 * something was alread associated with 'key' and only do a single
 * lookup in 'm', regardless if something was already associated with
 * 'key'. (So we don't first check if 'key' exist in 'm' and then
 * insert the new association.)
 */
template<class M>
static void insertNULL(M* m, const typename M::key_type& key, bool* newKey, typename M::iterator* it)
{
	std::pair<typename M::iterator, bool> p = m->insert(std::pair<const typename M::key_type, typename M::mapped_type>(key, (typename M::mapped_type) NULL));
	*it = p.first;
	*newKey = p.second;
}

void HTTPUser::processPacket(const TCPPacket& packet)
{
	TCPConnId id(getTCPConnId(packet));
	COUNTER_INCREASE("HTTPUser::processPacket called");

	Timeval ptime(packet.pL2Packet->time);
	if (lastAct_ < ptime)
		lastAct_ = ptime;

	HTTPConnection* conn;
	ConnMap::iterator it;
	bool newConn;
	insertNULL(&connections_, id, &newConn, &it);
	if (newConn) {
		COUNTER_INCREASE("HTTPUser::processPacket: New connection");
		conn = new HTTPConnection(staple_, id, this, msgTester_);
		it->second = conn;
		stats_.tcpNum++;
	} else {
		conn = it->second;
	}

	conn->processPacket(packet);
}

void HTTPUser::finishAllTCPSessions()
{
	for (ConnMap::iterator it = connections_.begin(); it != connections_.end(); ++it)
		delete it->second;
	connections_.clear();
	checkTimeout(Timeval::endOfTime());
}

void HTTPUser::finishTCPSession(const TCPConnId& id)
{
	LOG_AND_COUNT("HTTPUser::finishTCPSession: Removing TCP session ", id);

	ConnMap::iterator it = connections_.find(id);
	if (it == connections_.end()) {
		LOG_AND_COUNT("HTTPUser::finishTCPSession: Connection not found. ", id);
		return;
	}

	delete it->second;
	connections_.erase(it);
}

// These content types are used in the main page of a page view.
static bool isMainContentType(const string& ct)
{
	// FIXME more content types here?
	if (ct == "text/html" ||
	    ct == "application/xhtml+xml" ||
	    ct == "application/xhtml")
		return true;
	else
		return false;
}

// These content types can be contained in other resources.
static bool isSubContentType(const string& ct)
{
        // The Javascript and ECMAscript types comes from RFC 4329.
        // FIXME add more.
	// FIXME neither javascript nor CSS is sniffed.
	const char* s = ct.c_str();
	if (starts_with(s, "image/")) {
		return true;
	} else if (starts_with(s, "text/")) {
		return
			ct == "text/css" ||
			ct == "text/javascript" ||
			ct == "text/x-javascript" ||
			ct == "text/ecmascript" ||
			ct == "text/javascript1.0" ||
			ct == "text/javascript1.1" ||
			ct == "text/javascript1.2" ||
			ct == "text/javascript1.3" ||
			ct == "text/javascript1.4" ||
			ct == "text/javascript1.5" ||
			ct == "text/jscript" ||
			ct == "text/livescript" ||
			ct == "text/x-ecmascript";
	} else if (starts_with(s, "application/")) {
		return
			ct == "application/javascript" ||
			ct == "application/x-javascript" ||
			ct == "application/x-shockwave-flash" ||
			ct == "application/x-ecmascript" ||
			ct == "application/ecmascript";
	} else {
		return false;
	}
}

// These content types can link to other resources.
static bool isContainerContentType(const string& ct)
{
	// FIXME more?
	if (ct == "text/html" ||
	    ct == "application/xhtml+xml" ||
	    ct == "text/css" ||
	    ct == "application/x-shockwave-flash")
		return true;
	else
		return false;
}


// mp3 is not sniffed, but it will end up as application/octet-stream
// so it shouldn't be a problem.
static bool isNonEmbeddableContentType(const string& ct)
{
	if (ct == "application/octet-stream" ||
	    ct == "application/pdf" ||
	    ct == "application/postscript" ||
	    ct == "application/x-rar-compressed" ||
	    ct == "application/zip" ||
	    ct == "application/x-gzip" ||
	    // FIXME: Is it correct to include the following here?
	    ct == "video/webm" ||
	    ct == "application/ogg" ||
	    ct == "audio/x-wave"
	    // FIXME Should we include ct == "text/plain" here?
		)
		return true;
	else
		return false;
}

Resource* HTTPUser::createResource(HTTPMsg* msg)
{
	if (isContainerContentType(msg->getContentType()))
		return createAggregateResource(msg);
	else
		return new Resource(msg);
}

Resource* HTTPUser::createAggregateResource(HTTPMsg* msg)
{
	Resource* r = new Resource(msg);
	string reqURL(msg->getRequestURL());
// FIXME log this?
/*
	PageMap::iterator it = pageMap_.find(reqURL);
	if (it == pageMap_.end()) {
		// New main page.
		log("PageView: Associating message with new main page. "
		    "IP: ", srcIP_, " URL: '", reqURL, "' ", *msg);
	} else {
		// Same URL already exist, consume it and insert new.
		consumePageView(it->second);
		log("PageView: Associating message with new main page, referer already exist. "
		    "IP: ", srcIP_, " URL: '", reqURL, "' ", *msg);
	}
*/
	pageMap_[reqURL] = r;
	for (ResourceList::iterator eIt = earlySubs_.begin(); eIt != earlySubs_.end(); ) {
		Resource* early = *eIt;
		HTTPMsg* earlyMain = early->getMain();

		if (earlyMain->getReferer() == reqURL) {
			if (addSubResource(r, early)) {
				LOG_AND_COUNT("HTTPUser: Adding early subresource.",
					      " IP: ", srcIP_, " referer: ", reqURL, " msg: ", *earlyMain);
				eIt = earlySubs_.erase(eIt);
			} else {
				++eIt;
			}
		} else {
			++eIt;
		}
	}

	return r;
}

static bool isRedirection(const HTTPMsg* msg)
{
	if (msg->getLocation().empty())
		return false;

	switch (msg->getRspStatusCode()) {
	case 300: // Multiple Choices
	case 301: // Moved Permanently
	case 302: // Found
	case 303: // See Other

	// case 304: // Not Modified
		/* Used when the cache in the user-agent is
		 * up-to-date. This is not a redirect.
		 */

        // case 305: // Use Proxy
		/* The location header contains URI of proxy the
		 * user-agent should use.
		 *
		 * FIXME: We currently don't treat this as a redirect
		 * although we probably should. It would require some
		 * special casing.
		 */

        // case 306: // Unused
		/* This was "Switch Proxy". It is unused but
		 * reservered in HTTP 1.1.
		 */
	case 307: // Temporary Redirect
		return true;

	default:
		return false;
	}
}

static bool cmpRedirectionURLs(const string& source, const string& target)
{
	if (source == target)
		return true;

	size_t pos = source.find('#');
	if (pos != source.npos && pos == target.size()) {
		for (size_t i = 0; i < pos; i++) {
			if (source[i] != target[i])
				return false;
		}

		return true;
	} else {
		return false;
	}
}

static string removeURLFragment(const string& url)
{
	size_t pos = url.find('#');
	if (pos == string::npos)
		return url;
	else
		return url.substr(0, pos);
}

bool HTTPUser::addRedirectionTarget(Resource* target)
{
	for (ResourceSet::iterator it = redirectSources_.begin();
	     it != redirectSources_.end();
	     ++it) {
		Resource* src = *it;
		if (cmpRedirectionURLs(src->getMain()->getLocation(), target->getMain()->getRequestURL()) &&
		    addSubResource(src, target)) {
			redirectSources_.erase(it);
			return true;
		}
	}

	return false;
}

HTTPUser::PageMap::iterator HTTPUser::pageMapFind(const string& referer)
{
	PageMap::iterator it = pageMap_.find(referer);
	if (it == pageMap_.end())
		it = pageMap_.find(removeURLFragment(referer));
	return it;
}

/* FIXME:

   * MIME type for fonts? (there is none, auto detect based on
     content? See
     http://stackoverflow.com/questions/2871655/proper-mime-type-for-fonts)

   * favicon? They don't have referer.
*/
void HTTPUser::associateWithPageView(HTTPMsg* msg)
{
	LOG_AND_COUNT("HTTPUser::associateWithPageView called ", *msg);

	stats_.reqNum++;
	if (msg->responseParsed())
		stats_.rspNum++;

	const string ct(msg->getContentType());
	const string referer(msg->getReferer());
	checkTimeout(msg->getRspEndTime());
	Resource* r = createResource(msg);

	if (isRedirection(msg)) {
		LOG_AND_COUNT("HTTPUser: Found redirection.",
			      " IP: ", srcIP_, " msg: ", *msg);
		redirectSources_.insert(r);
	}

	if (addRedirectionTarget(r)) {
		LOG_AND_COUNT("HTTPUser: Adding redirection target.",
			      " IP: ", srcIP_, " msg: ", *msg);
	} else if (isMainContentType(ct) && referer.empty()) {
		COUNTER_INCREASE("HTTPUser: Adding new page (no referer and main content-type)");
		// A HTML file without referer. We consider it to be a
		// new page view.
		pagesAdd(r);
	} else if (isMainContentType(ct)) {
		// If *msg is of main content-type it may be an IFRAME
		// (we know that it has a referer). We don't add it as
		// a subresource yet, this is delayed until we get
		// another subresource with matching referer. This is
		// an extra check to avoid adding clicked-to pages as
		// IFRAMEs.
		LOG_AND_COUNT("HTTPUser: Adding message as possible FRAME.",
			      " IP: ", srcIP_, " referer: '", referer, "' msg: ", *msg);
		possibleFramesAdd(r);
	}  else if (isSubContentType(ct) ||
		    // Some servers sends cached PNG images as
		    // application/octet-stream. We consider such
		    // resources to be isSubContentType, even though
		    // we consider application/octet-stream to be
		    // non-embeddable.
		    //
		    // Some servers send these resources as
		    // text/html. That case is dealt by the branches
		    // above. They are currently not special cased.
		    //
		    // 304 is Not modified
		    msg->getRspStatusCode() == 304) {
		if (referer.empty()) {
			LOG_AND_COUNT("HTTPUser: Consuming lonely resource "
				      "(sub content-type or redirection, empty referer).",
				      " IP: ", srcIP_, " msg: ", *msg);
			consumeResource(r);
		} else {
			PageMap::iterator it = pageMapFind(referer);

			if (it == pageMap_.end()) {
				LOG_AND_COUNT("HTTPUser: Main not found, adding as early subresource. "
					      "(sub content-type or redirection, referer not found)",
					      " IP: ", srcIP_, " referer: '", referer, "' msg: ", *msg);
				earlySubsAdd(r);
			} else {
				LOG_AND_COUNT("HTTPUser: Adding message as subresource. "
					      "(sub content-type or redirection, referer found)",
					      " IP: ", srcIP_, " referer: '", referer, "' msg: ", *msg);
				Resource* owner = it->second;
				if (!addSubResource(owner, r))
					consumeResource(r);
			}
		}
	} else if (isNonEmbeddableContentType(ct)) {
		LOG_AND_COUNT("HTTPUser: Consuming lonely resource (non-embeddable).",
			      " IP: ", srcIP_,
			      " msg: ", *msg);
		consumeResource(r);
	} else {
		string logCt = " Don't know what to do with content-type " + (ct == "" ? "(empty)" : ct);
		// FIXME merge this branch with "else if (isSubContentType(ct))" branch above?
		if (referer.empty()) {
			LOG_AND_COUNT("HTTPUser: Consuming lonely resource (unknown content-type, empty referer).",
				      " IP: ", srcIP_, logCt, " msg: ", *msg);
			consumeResource(r);
		} else {
			PageMap::iterator it = pageMapFind(referer);

			if (it == pageMap_.end()) {
				LOG_AND_COUNT("HTTPUser: Adding early subresource (unknown content-type, referer not found).",
					      " IP: ", srcIP_,
					      " referer: '", msg->getReferer(),
					      logCt,
					      " msg: ", *msg);
				earlySubsAdd(r);
			} else {
				LOG_AND_COUNT("HTTPUser: Adding subresource (unknown content-type, referer found).",
					      " IP: ", srcIP_,
					      logCt,
					      " msg: ", *msg);
				// FIXME should unsure subresources be
				// reintroduced?

				Resource* owner = it->second;
				if (!addSubResource(owner, r))
					consumeResource(r);
			}
		}
	}
}

bool HTTPUser::addSubResourceImpl(Resource* r, Resource* sub)
{
// FIXME this could be improved. If a.html contains a large b.jpg and
// some c.png, we may have started to download b.jpg just after we
// were finished with a.html and then 10 seconds later we start to
// download c.png (b.jpg is still not finished). In this case we will
// not add c.png due to inactivity, however this is wrong as we are
// still downloading b.jpg.
	if (sub->getStartTime().diff(r->getRootOwner()->getEndTime()) > INACTIVITY_TIMEOUT) {
		LOG_AND_COUNT("HTTPUser::addSubResource: Not adding due to inactivity.",
			      " main: ", sub->getMain(),
			      " target: ", r->getMain());
		return false;
	}

	if (r->getStartTime().diff(sub->getStartTime()) >= MAIN_SUB_BOUND) {
		LOG_AND_COUNT("HTTPUser::addSubResource: Not adding, too early subresource.");
		return false;
	}

	if (!r->add(sub)) {
		LOG_AND_COUNT("HTTPUser::addSubResource: Not adding because of cycles.");
		return false;
	} else {
		return true;
	}
}

bool HTTPUser::addSubResource(Resource* r, Resource* sub)
{
	if (!addSubResourceImpl(r, sub))
		return false;

	string reqURL(r->getMain()->getRequestURL());

// FIXME: Must test that if user clicks to page then all
// requests/responses on the first page are aborted before we go to
// the next page. Otherwise the test below may be fooled.

	/* We only consider a resource to be an IFRAME or FRAME if
	 * there is some other resource that were finished _after_ we
	 * started to download the possible frame. This is to ensure
	 * that if the user clicks on a link while the page view is
	 * still open we shouldn't add the clicked-to page as a
	 * IFRAME/FRAME.
	 */

	const Resource* root = r->getRootOwner();
	Timeval endTime(root->getEndTime());

	/* Now check if there are other possible frames that finished
	 * after 'endTime'.
	 */
	for (ResourceList::iterator it = possibleFrames_.begin(); it != possibleFrames_.end(); ++it) {
		Resource* frame = *it;
		if (frame->getMain()->getReferer() == reqURL) {
			Timeval t(frame->getMain()->getRspEndTime());
			if (endTime < t)
				endTime = t;
		}
	}

	for (ResourceList::iterator it = possibleFrames_.begin(); it != possibleFrames_.end(); ) {
		Resource* frame = *it;
		HTTPMsg* frameMsg = frame->getMain();
		bool erasedIt = false;

		string frameURL(frameMsg->getRequestURL());
		PageMap::iterator pIt = pageMapFind(frameMsg->getReferer());
		Resource* parent = NULL;

		if (frameMsg->getReferer() == reqURL)
			parent = r;
		else if (pIt != pageMap_.end() && pIt->second->getRootOwner() == root)
			parent = pIt->second;
		else
			goto next;

		if (endTime < frame->getStartTime())
			goto next;

		if (addSubResourceImpl(parent, frame)) {
			it = possibleFrames_.erase(it);
			erasedIt = true;
			LOG_AND_COUNT("HTTPUser::addSubResource: Adding frame (other resource later) ", *frameMsg);
		}

	next:
		if (!erasedIt)
			++it;
	}

	return true;
}

void HTTPUser::pagesAdd(Resource* r)
{
	pages_.push_back(r);
	updateFirstStoredTime(r);
}

void HTTPUser::possibleFramesAdd(Resource* r)
{
	possibleFrames_.push_back(r);
	updateFirstStoredTime(r);
}

void HTTPUser::earlySubsAdd(Resource* r)
{
	earlySubs_.push_back(r);
	updateFirstStoredTime(r);
}

void HTTPUser::updateFirstStoredTime(const Resource* r)
{
	if (r->getStartTime() < firstStoredTime_)
		firstStoredTime_ = r->getStartTime();
}

void HTTPUser::checkTimeout(const Timeval& curTime)
{
	if (curTime.diff(firstStoredTime_) <= TIMEOUT)
		return;

	firstStoredTime_ = Timeval::endOfTime();
	for (ResourceList::iterator it = possibleFrames_.begin();
	     it != possibleFrames_.end(); ) {
		Resource* r = *it;
		HTTPMsg* main = r->getMain();
		Timeval startTime(r->getStartTime());
		Timeval endTime(main->getRspEndTime());
		const string referer(main->getReferer());

		/* Possible frames that are about to timeout and only
		 * have a few subresources are added as frames
		 * here. This is because IFRAMEs often have only a few
		 * subresources and our other heuristics to detect
		 * them sometimes fail. We add some slack to the
		 * timeout in case the timing is not so precise.
		 */
		if (!referer.empty() &&
		    r->getParts().size() < RESOURCES_IN_FRAME &&
		    curTime.diff(startTime) > TIMEOUT/2.0) {
			PageMap::iterator pageIt = pageMapFind(referer);

			if (pageIt != pageMap_.end()) {
				Resource* owner = pageIt->second;
				if (owner->getStartTime() < endTime) {
					if (addSubResourceImpl(owner, r)) {
						LOG_AND_COUNT("HTTPUser::checkTimeout: Adding as frame (few resources in frame) ",
							      *main);
						it = possibleFrames_.erase(it);
						continue;
					}
				}
			}
		}

		if (curTime.diff(startTime) > TIMEOUT) {
			LOG_AND_COUNT("HTTPUser: Possible frame timeout. ", *r->getMain());
			consumeResource(r);
			it = possibleFrames_.erase(it);
		} else {
			if (startTime < firstStoredTime_)
				firstStoredTime_ = startTime;
			++it;
		}
	}

	for (ResourceList::iterator it = pages_.begin();
	     it != pages_.end(); ) {
		Resource* r = *it;
		Timeval startTime(r->getStartTime());

		if (curTime.diff(startTime) > TIMEOUT) {
			LOG_AND_COUNT("HTTPUser: timeout. ", *r->getMain());
			consumeResource(r);
			it = pages_.erase(it);
		} else {
			if (startTime < firstStoredTime_)
				firstStoredTime_ = startTime;
			++it;
		}
	}

	for (ResourceList::iterator it = earlySubs_.begin();
	     it != earlySubs_.end(); ) {
		Resource* r = *it;
		Timeval startTime(r->getStartTime());
		if (curTime.diff(startTime) > TIMEOUT) {
			LOG_AND_COUNT("HTTPUser: Early subresource timeout. ", *r->getMain());
			consumeResource(r);
			it = earlySubs_.erase(it);
		} else {
			if (startTime < firstStoredTime_)
				firstStoredTime_ = startTime;
			++it;
		}
	}
}

void HTTPUser::closeResource(Resource* r)
{
	PageMap::iterator mIt = pageMap_.find(r->getMain()->getRequestURL());
	if (mIt != pageMap_.end() && mIt->second == r)
		pageMap_.erase(mIt);

	redirectSources_.erase(r);
	const Resource::ResourceList& parts = r->getParts();
	for (Resource::ResourceList::const_iterator it = parts.begin(); it != parts.end(); ++it)
		closeResource(*it);
}

static bool isPage(const Resource* r)
{
	HTTPMsg* main = r->getMain();
	int subs = r->getParts().size();
	if (main->getRspStatusCode() == 200) {
		if (subs > 0)
			return true;
		else
			return isMainContentType(main->getContentType());
	} else {
		return subs > 0;
	}
}

void HTTPUser::consumeResource(Resource* r)
{
	assert(!r->getOwner());
	closeResource(r);

	if (isPage(r)) {
		LOG_AND_COUNT("HTTPUser::consumeResource called, page ", *r->getMain());
		stats_.pagesSeen++;
		printer_->printPageView(r);
		pageTester_->addPageView(r);
	} else {
		LOG_AND_COUNT("HTTPUser::consumeResource called, lonely ", *r->getMain());
		printer_->printLonelyResource(r);
		pageTester_->addLonelyResource(r);
	}
	delete r;
}

HTTPUser::Stats::Stats()
{
	pagesSeen = 0;
	tcpNum = 0;
	reqNum = 0;
	rspNum = 0;
}
