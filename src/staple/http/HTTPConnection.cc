#include <assert.h>
#include <string>

#include <staple/Type.h>
#include <staple/Staple.h>
#include <staple/http/log.h>
#include <staple/http/HTTPEngine.h>
#include "HTTPConnection.h"
#include "HTTPMsg.h"
#include "Resource.h"
#include "HTTPMsgTester.h"
#include "HTTPUser.h"

using std::string;
using std::list;

HTTPConnection::HTTPConnection(Staple& staple, const TCPConnId& id, HTTPUser* user, HTTPMsgTester* tester) :
	connId(id),
	user_(user),
	tester_(tester),
	pbuf0_(staple),
	pbuf1_(staple),
	attemptedResyncs_(0),
	resyncNeeded_(false),
	aborted_(false),
	staple_(staple)
{
	currentResponse = msgs.end();
	pbuf_[0] = &pbuf0_;
	pbuf_[1] = &pbuf1_;
	COUNTER_INCREASE("HTTPConnection constructed");
}

HTTPConnection::~HTTPConnection()
{
	finishSession();
	COUNTER_INCREASE("HTTPConnection destructed");
}

bool HTTPConnection::processPacket(const TCPPacket& packet)
{
	if (aborted_) {
		// Not for us. It may be a session which we couldn't
		// parse but goes on a HTTP port.
		COUNTER_INCREASE("HTTPConnection::processPacket: Connection aborted, dropping packet");
		return true;
	}

	int dir = packet.direction;
	bool success = true;
	if (packet.TCPFlags & TCPPacket::ACK) {
		pbuf_[1-dir]->updateAck(packet.ack);
		if (!processPacketImpl(1-dir, NULL))
			success = false;
	}

	if (!success)
		goto out;

	// FIXME We should log timings etc for first packet in the TCP
	// session. Should also log ACKs sometime (e.g., last ACK for
	// response).
	if (packet.TCPPLLen == 0)
		goto out;

	if (pbuf_[dir]->tryAddGet(packet)) {
		COUNTER_INCREASE("HTTPConnection::processPacket PacketBuffer::tryAddGet succeeded.");
		if (!processPacketImpl(dir, &packet)) {
			success = false;
			goto out;
		}
	} else {
		LOG_AND_COUNT("HTTPConnection::processPacket PacketBuffer::tryAddGet failed, copying packet.");
		if (!pbuf_[dir]->add(packet)) {
			WARN("HTTPConnection::processPacket Too much packet loss or "
			     "packet reordering, dropping connection.", connId);
			success = false;
			goto out;
		}

		if (!processPacketImpl(dir, NULL)) {
			success = false;
			goto out;
		}
	}

out:
	if (!success)
		abort();

	return success;
}

bool HTTPConnection::processPacketImpl(int dir, const TCPPacket* packet)
{
	if (aborted_) {
		delete packet;
		return false;
	}

	bool first = true;
	while (true) {
		const TCPPacket* p;
		if (packet && first)
			p = packet;
		else
			p = pbuf_[dir]->get();
		if (p == NULL) {
			// We must wait for more packets before processing
			// anything more.
			if (first) {
				LOG_AND_COUNT("HTTPConnection::processPacket packet duplication/loss/reordering detected. ",
					      this,
					      " dir: ", dir,
					      dir ? " <- " : " -> ", connId,
					      " packets in buffer: ", pbuf_[dir]->numPackets());
			}

			return true;
		}

		assert(p->direction == dir);
		bool success;
		/* direction: 0: NetA->NetB - 1: NetB->NetA
		   We assume that the client is on NetA.
		*/
		if (dir == 0)
			success = processReqPacket(*p);
		else
			success = processRspPacket(*p);

		if (first && packet) {
			/* First packet and tryAddGet returned
			 * true. Packet will be deleted by caller.
			 */
			/* NOP */
		} else {
			/* Packet copied to PacketBuffer with
			 * PacketBuffer::add. The packet must be
			 * deleted here.
			 */
			delete p;
		}

		if (!success)
			return false;

		first = false;
	}
}

bool HTTPConnection::processReqPacket(const TCPPacket& packet)
{
	return processReqPacket(packet, 0);
}

list<HTTPMsg*>::iterator backIterator(list<HTTPMsg*>& container)
{
	list<HTTPMsg*>::iterator it = container.end();
	--it;
	return it;
}

bool HTTPConnection::processReqPacket(const TCPPacket& packet, int offset)
{
	if (msgs.empty()) {
		msgs.push_back(new HTTPMsg(staple_, connId));
		currentResponse = backIterator(msgs);

		LOG_AND_COUNT("HTTPConnection: New HTTPMsg request, reason: empty. ",
			      *msgs.back(),
			      " packet.payload: ", (void*) packet.payload,
			      " offset: ", offset,
			      packet);
	} else if (resyncNeeded_ || msgs.back()->resyncNeeded()) {
		HTTPMessages::iterator oldIt = backIterator(msgs);
		HTTPMsg* msg = new HTTPMsg(staple_, connId);
		msg->doResynchronization();
		attemptedResyncs_++;

		LOG_AND_COUNT("HTTPConnection: New HTTPMsg request, reason: resync. ",
			      *msg,
			      "  packet.payload: ", (void*) packet.payload,
			      " offset: ", offset,
			      " Old: ", **oldIt,
			      packet);

		// Remove the message that caused the
		// resync. We are done with that one now.
		consumeMessage(oldIt);
		msgs.push_back(msg);
		currentResponse = backIterator(msgs);
	} else if (msgs.back()->requestParsed()) {
		HTTPMsg* old = msgs.back();
		msgs.push_back(new HTTPMsg(staple_, connId));
		LOG_AND_COUNT("HTTPConnection: New HTTPMsg request, reason: parsed. ",
			      *msgs.back(),
			      " packet.payload: ", (void*) packet.payload,
			      " offset: ", offset,
			      " Old: ", *old,
			      packet);

		if (currentResponse == msgs.end())
			currentResponse = backIterator(msgs);
	}
	resyncNeeded_ = false;
	HTTPMsg* msg = msgs.back();
	bool success;
	int unparsed = msg->processReqPacket(packet, offset, &success);
	if (!success)
		return tryResync();

	assert(0 <= unparsed);
	assert(unparsed <= packet.TCPPLLen);
	if (0 < unparsed)
		return processReqPacket(packet, packet.TCPPLLen - unparsed);
	else
		return true;
}

bool HTTPConnection::processRspPacket(const TCPPacket& packet)
{
	return processRspPacket(packet, 0);
}

bool HTTPConnection::tryResync()
{
	if (attemptedResyncs_ >= 5) {
		WARN("HTTPConnection::tryResync: Too many resync attempts, dropping TCP session.");
		return false;
	} else {
		if (!resyncNeeded_)
			WARN("HTTPConnection::tryResync: Trying to resync.");
		resyncNeeded_ = true;
		return true;
	}
}

bool HTTPConnection::processRspPacket(const TCPPacket& packet, int offset)
{
	if (packet.TCPPLLen == 0)
		return true;

	if (resyncNeeded_) {
		LOG_AND_COUNT("HTTPConnection::processRspPacket: Dropping packet, waiting for resync. ", packet);
		return true;
	}

	if (currentResponse == msgs.end()) {
		WARN("HTTPConnection::processRspPacket: Response but no request!? Trying to resync. ", packet);
		return tryResync();
	}

	HTTPMsg* curMsg = *currentResponse;
	bool wasParsed = curMsg->responseHeaderParsed();
	bool success;
	int unparsed = curMsg->processRspPacket(packet, offset, &success);
	if (!wasParsed && curMsg->responseHeaderParsed()) {
		// Update HTTP stuff in tcpConnReg.
		TCPConnId tcpConnId(getTCPConnId(packet));
		TCPConnReg::iterator tcpIt = staple_.tcpConnReg.find(tcpConnId);
		if (tcpIt != staple_.tcpConnReg.end()) {
			TCPConn& conn = tcpIt->second;
			int dir = packet.direction;
			// Make sure that we don't overwrite anything
			// we stored before.
			if (!conn.lastReqURI[1-dir].empty() && curMsg->getRequestURI().empty())
				goto noUpdate;
			if (!conn.lastReqHost[1-dir].empty() && curMsg->getHost().empty())
				goto noUpdate;
			if (!conn.userAgent.empty() && curMsg->getReqHeader("user-agent").empty())
				goto noUpdate;
			if (!conn.contentType.empty() && curMsg->getContentType().empty())
				goto noUpdate;

			conn.lastReqURI[1-dir] = curMsg->getRequestURI();
			conn.lastReqHost[1-dir] = curMsg->getHost();
			conn.userAgent = curMsg->getReqHeader("user-agent");
			conn.contentType = curMsg->getContentType();
		noUpdate:
			;
		}
	}

	if (!success)
		return tryResync();
	if (curMsg->responseParsed()) {
		LOG_AND_COUNT("HTTPConnection::processRspPacket: Got complete response ", *curMsg);
		currentResponse = consumeMessage(currentResponse);
		attemptedResyncs_ = 0;
	}

	assert(0 <= unparsed);
	assert(unparsed <= packet.TCPPLLen);
	if (0 < unparsed)
		return processRspPacket(packet, packet.TCPPLLen - unparsed);
	else
		return true;
}

HTTPConnection::HTTPMessages::iterator HTTPConnection::consumeMessage(const HTTPMessages::iterator& it)
{
	HTTPMsg* msg = *it;
	if (msg->requestParsed()) {
		// If the request is parsed we pass it on. Sometimes,
		// e.g., when a TCP session is aborted, we will only
		// see a request and not a response. We want these
		// requests to appear in the webreq log.

		if (!msg->responseParsed())
			WARN("HTTPConnection::consumeMessage: Consuming msg without fully parsed response. ", *msg);
		tester_->addMessage(this, msg);
		user_->associateWithPageView(msg);
	} else {
		WARN("HTTPConnection::consumeMessage: Dropping msg, request not fully parsed. ", *msg);
		delete msg;
	}
	return msgs.erase(it);
}

void HTTPConnection::finishSession()
{
	for (int dir = 0; dir < 2; dir++) {
		pbuf_[dir]->finishTCPSession();
		while (pbuf_[dir]->hasPackets()) {
			if (!processPacketImpl(dir, NULL))
				break;
		}
	}

	if (msgs.empty())
		return;

	bool graceful = false;
	TCPConnReg::iterator tcpIt = staple_.tcpConnReg.find(connId);
	if (tcpIt != staple_.tcpConnReg.end()) {
		if (tcpIt->second.termination == TCPConn::TERM_FIN)
			graceful = true;
	}

	while (!msgs.empty()) {
		msgs.front()->finishTCPSession(graceful);
		consumeMessage(msgs.begin());
	}
}

void HTTPConnection::printTestOutput(std::ostream& o, bool swapNetworks) const
{
	if (swapNetworks) {
		o << IPAddress(connId.netBIP) << '\t' << connId.netBPort << '\t';
		o << IPAddress(connId.netAIP) << '\t' << connId.netAPort << '\t';
	} else {
		o << IPAddress(connId.netAIP) << '\t' << connId.netAPort << '\t';
		o << IPAddress(connId.netBIP) << '\t' << connId.netBPort << '\t';
	}
}

std::ostream& operator<<(std::ostream& o, const HTTPConnection& m)
{
	if (m.msgs.size() == 0)
		return o;

	o << "TCP conn Id: ";
	m.connId.Print(o);
	o << '\n';
	for (HTTPConnection::HTTPMessages::const_iterator it = m.msgs.begin(); it != m.msgs.end(); ++it) {
		const HTTPMsg* msg = *it;
		o << *msg << '\n';
	}
	return o;
}

void HTTPConnection::abort()
{
	LOG_AND_COUNT("HTTPConnection::abort: Aborting TCP session"
		      " (doesn't look like HTTP) ", connId);
	aborted_ = true;
	finishSession();
}
