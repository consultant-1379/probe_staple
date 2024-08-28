#ifndef HTTPCONNECTION_H
#define HTTPCONNECTION_H

#include <iostream>
#include <list>

#include <staple/Staple.h>
#include <staple/TCPConn.h>
#include <staple/http/globals.h>
#include <staple/http/IPAddress.h>
#include "PacketBuffer.h"

class TCPConnId;
class TCPPacket;
class HTTPMsg;
class HTTPUser;
class HTTPMsgTester;

// Represents the HTTP traffic over one TCP session.
class HTTPConnection
{
public:
	/* Ownership of user is not transfered.
	 */
	HTTPConnection(Staple& staple, const TCPConnId&, HTTPUser* user, HTTPMsgTester* tester);
	~HTTPConnection();

	// Process one TCP packet.
	bool processPacket(const TCPPacket& p);

	friend std::ostream& operator<<(std::ostream& o, const HTTPConnection& m);

	typedef std::list<HTTPMsg*> HTTPMessages;
	const HTTPMessages& getMessages() const { return msgs; }

	void printTestOutput(std::ostream&, bool swapNetworks) const;
	const HTTPUser* getUser() const { return user_; }

	void abort();

private:
	DISALLOW_COPY_AND_ASSIGN(HTTPConnection);

	// Finish the session. All messages are consumed. This should
	// be called when the TCP session ends or on time out. This
	// method is called from the destructor.
	void finishSession();
	bool processReqPacket(const TCPPacket& packet);
	bool processReqPacket(const TCPPacket& packet, int offset);
	bool processRspPacket(const TCPPacket& packet);
	bool processRspPacket(const TCPPacket& packet, int offset);
	HTTPMessages::iterator consumeMessage(const HTTPMessages::iterator& it);
	bool tryResync();

	/* Process available packets. If 'packet' is non-NULL, then
	 * 'packet' is processed first and then all available packets
	 * in the buffer are processed.
	 */
	bool processPacketImpl(int dir, const TCPPacket* packet);

	TCPConnId connId;

	// The HTTPMsgs we are currently working on. New messages will
	// be added at the end when they are processed and old ones
	// will be deteted from the beginning when they are not used
	// anymore.
	HTTPMessages msgs;
	HTTPMessages::iterator currentResponse;

	// The user associated with this connection.
	HTTPUser* user_;
	HTTPMsgTester* tester_;

	// We have one packet buffer for each direction.
	PacketBuffer pbuf0_, pbuf1_;
	PacketBuffer* pbuf_[2];

	/* Count the number of times we have tried to resynchronize
	 * this TCP session since the last successfully parsed
	 * response. Reset to 0 when we successfully parse a response.
	 */
	int attemptedResyncs_;

	// If true, we need to resynchronize.
	bool resyncNeeded_;

	// If true, we don't process any more packets on this
	// connection.
	bool aborted_;

	Staple& staple_;
};

#endif
