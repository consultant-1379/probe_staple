#ifndef HTTPENGINE_H
#define HTTPENGINE_H

#include <list>
#include <vector>
#include <iostream>
#include <set>
#include <unordered_set>

#include <staple/TCPConn.h>
#include <staple/Type.h>
#include <staple/http/globals.h>
#include <staple/http/IPAddress.h>

class HTTPMsg;
class HTTPConnection;
class HTTPUser;
class HTTPMsgTester;
class HTTPPageViewTester;
class PageViewPrinter;
class LogFile;
class Timeval;

/* If MBBA_OUTPUT is #defined to 1 then the page logs and request logs
 * are written in a MBBA and DNA friendly format. See
 * PageViewPrinterTab.cc, PageInfo.cc, and MessageInfo.cc for details.
 */
#define MBBA_OUTPUT 1

/* The server is net B and the client is on net A, see also
 * HTTPEngine.cc.
 */
inline void setServerIP(TCPConnId* id, const IPAddress& ip)
{ id->netBIP = ip.getIP(); }
inline void setServerPort(TCPConnId* id, uint16_t port)
{ id->netBPort = port; }
inline void setClientIP(TCPConnId* id, const IPAddress& ip)
{ id->netAIP = ip.getIP(); }
inline void setClientPort(TCPConnId* id, uint16_t port)
{ id->netAPort = port; }

inline IPAddress getServerIP(const TCPConnId& id)
{ return IPAddress(id.netBIP); }
inline uint16_t getServerPort(const TCPConnId& id)
{ return id.netBPort; }
inline IPAddress getClientIP(const TCPConnId& id)
{ return IPAddress(id.netAIP); }
inline uint16_t getClientPort(const TCPConnId& id)
{ return id.netAPort; }

TCPConnId getTCPConnId(const TCPPacket& packet);

class HTTPStats
{
public:
	HTTPStats();
	long long sessionsSeen;
	long long pagesSeen;
	long long packetsSeen[2];

	/* Number of bytes on IP layer (including IP headers). */
	long long IPBytes[2];

	/* Number of bytes on application layer (HTTP). */
	long long httpBytes[2];

	long long tcpNum;
	long long reqNum;
	long long rspNum;
};

/* HTTPEngine is the entry point for HTTP parsing. Packets are entered
 * into the HTTP parsing system by calling HTTPEngine::processPacket.
 */
class HTTPEngine
{
public:
	HTTPEngine(Staple&);
	~HTTPEngine();

	void processPacket(const TCPPacket& packet);
	void printSummary() const;
	void printInProgress() const;
	void printTestOutput() const;

	void finishAllTCPSessions();
	void finishTCPSession(const TCPConnId&);

	/* The following four methods control the logging done by the
	 * HTTPEngine. By default no logging is done.
	 */

	/* If called with non-NULL stream logging of pages will go to
	 * the stream. Use a NULL argument to disable logging. Logging
	 * enabled with setPageLog will be disabled after a call to
	 * this method.
	 */
	void setPageLogStream(std::ostream*);

	/* If called with non-NULL stream logging of requests will go
	 * to the stream. Use a NULL argument to disable
	 * logging. Logging enabled with setRequestLog will be
	 * disabled after a call to this method.
	 */
	void setRequestLogStream(std::ostream*);

	/* If 'log' is true, then log pages to Staple::perfmonDirName
	 * + "/webpage_xxx.log" where "xxx" is the number of seconds
	 * since the Unix epoch. Logging enabled with setPageLogStream
	 * will be disabled after a call to this method.
	 */
	void setPageLog(bool log);

	/* If 'log' is true, then log requests to
	 * Staple::perfmonDirName + "/webreq_xxx.log" where
	 * "xxx" is the number of seconds since the Unix epoch.
	 * Logging enabled with setRequestLogStream will be disabled
	 * after a call to this method.
	 */
	void setRequestLog(bool log);

	const HTTPStats& getStats() const { return stats_; }
private:
	DISALLOW_COPY_AND_ASSIGN(HTTPEngine);

	// HTTPUsers are removed after this many seconds of inactivity.
	static const double USER_TIMEOUT = 60;

	void closePageLog();
	void closeRequestLog();

	HTTPMsgTester* msgTester_;
	HTTPPageViewTester* pageTester_;

	void finishTCPSessionImpl(const TCPConnId& id);
	void checkUserTimeout(const Timeval& time);
	void updateUserStats(const HTTPUser* user);

	/* Map source IP addresses to HTTPUser*. To be able to
	 * efficiently remove HTTPUsers that haven't be used for the
	 * last USER_TIMEOUT seconds we also store the HTTPUsers in a
	 * linked list. The linked list is sorted so that the most
	 * recently used objects are in the back of the list.
	 */
	typedef std::list<HTTPUser*> UserList;
	typedef std::unordered_map<IPAddress, UserList::iterator> UserMap;
	UserMap users_;

	/* The HTTPUsers ordered in least recently used order. The
	 * least recently used object is first in the list.
	 */
	UserList usersLRU_;

	PageViewPrinter* printer_;
	Staple& staple_;

	LogFile *pageLog_, *requestLog_;
	std::ostream *pageOut_, *requestOut_;
	HTTPStats stats_;
};

bool isHTTPPort(uint16_t port);

#endif
