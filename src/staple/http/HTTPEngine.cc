#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <cxxabi.h>
#include <ucontext.h>
#include <unistd.h>
#include <errno.h>

#include <assert.h>
#include <stdint.h>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <string>
#include <locale>

#include <staple/Packet.h>
#include <staple/TCPConn.h>
#include <staple/Type.h>
#include <staple/http/log.h>
#include <staple/http/HTTPEngine.h>
#include "HTTPMsg.h"
#include "HTTPConnection.h"
#include "Resource.h"
#include "HTTPMsgTester.h"
#include "HTTPPageViewTester.h"
#include "PageViewPrinter.h"
#include "PageViewPrinterTab.h"
#include "HTTPUser.h"
#include "LogFile.h"
#include "PageInfo.h"
#include "MessageInfo.h"

using std::cout;
using std::cerr;
using std::endl;
using std::vector;
using std::ostream;
using std::istream;
using std::string;
using std::fstream;
using std::ios_base;
using std::list;

static void crit_err_handler(int sig_num, siginfo_t * info, void*);

bool isHTTPPort(uint16_t port)
{
	return  port == 80 ||
		port == 81 ||
		port == 8000 ||
		port == 8001 ||
		port == 8080 ||
		port == 8888 ||
		port == 3128;
}

const double HTTPEngine::USER_TIMEOUT;

HTTPEngine::HTTPEngine(Staple& staple) : staple_(staple)
{
	// Make sure we are working in the classic locale to ensure
	// that tolower and friends work as expected.
	std::locale::global(std::locale::classic());

	struct sigaction sa;
	sa.sa_handler = NULL;
	sa.sa_sigaction = crit_err_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGABRT, &sa, NULL);

	msgTester_ = new HTTPMsgTester();
	pageTester_ = new HTTPPageViewTester();
	printer_ = new PageViewPrinterTab(staple_);

	requestLog_ = NULL;
	requestOut_ = NULL;
	pageLog_ = NULL;
	pageOut_ = NULL;
}

HTTPEngine::~HTTPEngine()
{
	for (UserList::iterator it = usersLRU_.begin(); it != usersLRU_.end(); ++it)
		delete *it;
	users_.clear();
	usersLRU_.clear();
	delete msgTester_;
	delete pageTester_;
	closePageLog();
	closeRequestLog();
	delete printer_;
}

void HTTPEngine::finishAllTCPSessions()
{
	for (UserList::iterator it = usersLRU_.begin(); it != usersLRU_.end(); ++it) {
		HTTPUser* u = *it;
		u->finishAllTCPSessions();
		updateUserStats(u);
		delete u;
	}
	users_.clear();
	usersLRU_.clear();
}

void HTTPEngine::closePageLog()
{
	printer_->setPageLog(NULL);
	delete pageLog_;
	pageLog_ = NULL;
}

void HTTPEngine::setPageLogStream(std::ostream* s)
{
	closePageLog();

	if (!s)
		return;

	pageLog_ = new StreamLogFile(*s);
	printer_->setPageLog(pageLog_);
}

void HTTPEngine::setPageLog(bool log)
{
	closePageLog();
	if (!log)
		return;

	pageLog_ = new RotatingLogFile(staple_, "webpage");
	printer_->setPageLog(pageLog_);

	string f(staple_.perfmonDirName + "/columns_webpage");
	fstream fout(f.c_str(), fstream::out|fstream::trunc);
	if (fout.is_open()) {
		PageInfo::writeColumns(fout);
	} else {
		error(staple_, "Failed to open '", f, "': ", strerror(errno));
	}
}

void HTTPEngine::closeRequestLog()
{
	printer_->setRequestLog(NULL);
	delete requestLog_;
	requestLog_ = NULL;
}

void HTTPEngine::setRequestLogStream(std::ostream* s)
{
	closeRequestLog();

	if (!s)
		return;

	requestLog_ = new StreamLogFile(*s);
	printer_->setRequestLog(requestLog_);
}

void HTTPEngine::setRequestLog(bool log)
{
	closeRequestLog();
	if (!log)
		return;

	requestLog_ = new RotatingLogFile(staple_, "webreq");
	printer_->setRequestLog(requestLog_);

	string f(staple_.perfmonDirName + "/columns_webreq");
	fstream fout(f.c_str(), fstream::out|fstream::trunc);
	if (fout.is_open()) {
		MessageInfo::writeColumns(fout);
	} else {
		error(staple_, "Failed to open '", f, "': ", strerror(errno));
	}
}

TCPConnId getTCPConnId(const TCPPacket& packet)
{
	TCPConnId id;

	/* direction: 0: NetA->NetB - 1: NetB->NetA
	   We assume that the client is on NetA.
	*/
	if (packet.direction == 0) {
		id.netAPort = packet.srcPort;
		id.netBPort = packet.dstPort;
		id.netAIP = packet.srcIP;
		id.netBIP = packet.dstIP;
	} else {
		id.netAPort = packet.dstPort;
		id.netBPort = packet.srcPort;
		id.netAIP = packet.dstIP;
		id.netBIP = packet.srcIP;
	}

	return id;
}

void HTTPEngine::updateUserStats(const HTTPUser* user)
{
	stats_.pagesSeen += user->getStats().pagesSeen;
	stats_.tcpNum += user->getStats().tcpNum;
	stats_.reqNum += user->getStats().reqNum;
	stats_.rspNum += user->getStats().rspNum;
}

void HTTPEngine::checkUserTimeout(const Timeval& time)
{
	UserList::iterator it = usersLRU_.begin();
	while (it != usersLRU_.end()) {
		HTTPUser* user = *it;
		if (user->hasConnections()) {
			++it;
			continue;
		}

		if (time.diff(user->getLastActivity()) > USER_TIMEOUT) {
			LOG_AND_COUNT("HTTPEngine::checkUserTimeout Removing user ", user->getClientIP());
			updateUserStats(user);
			users_.erase(user->getClientIP());
			delete user;
			it = usersLRU_.erase(it);
		} else {
			// We can break out of the loop here as the
			// list is ordered.
			break;
		}
	}
}

void HTTPEngine::processPacket(const TCPPacket& packet)
{
	COUNTER_INCREASE("HTTPEngine::processPacket called");

	// Skip parsing if we won't do any logging.
	if (!printer_->getPageLog() && !printer_->getRequestLog())
		return;

	TCPConnId id(getTCPConnId(packet));

	if (!isHTTPPort(id.netBPort)) {
		// Not for us.
		return;
	}

	checkUserTimeout(packet.pL2Packet->time);

	IPAddress aip(id.netAIP);
	UserMap::iterator it = users_.find(aip);
	HTTPUser* user;
	if (it == users_.end()) {
		COUNTER_INCREASE("HTTPEngine::processPacket new user");
		user = new HTTPUser(staple_, aip, printer_, pageTester_, msgTester_);
		usersLRU_.push_back(user);
		users_.insert(make_pair(aip, --usersLRU_.end()));
		stats_.sessionsSeen++;
	} else {
		UserList::iterator listIt = it->second;
		user = *listIt;

		// Move the entry to the back of the list.
		usersLRU_.splice(usersLRU_.end(), usersLRU_, listIt);
	}

	stats_.packetsSeen[packet.direction]++;
	stats_.IPBytes[packet.direction] += packet.IPPktLen;
	stats_.httpBytes[packet.direction] += packet.TCPPLLen;
	user->processPacket(packet);
}

void HTTPEngine::finishTCPSession(const TCPConnId& id)
{
	LOG_AND_COUNT("HTTPEngine::finishTCPSession: Removing TCP session ", id);

	IPAddress aip(id.netAIP);
	UserMap::iterator it = users_.find(aip);
	if (it == users_.end()) {
		LOG_AND_COUNT("HTTPEngine::finishTCPSession: User not found. ", aip);
		return;
	}
	HTTPUser* user = *(it->second);
	user->finishTCPSession(id);
}

void HTTPEngine::printSummary() const
{
	StreamLogFile lf(cout);
	staple_.getCounterContainer()->print(&lf);
	staple_.getCounterContainer()->writeToFile();
}

void HTTPEngine::printInProgress() const
{
	cout << "HTTPEngine summary " << users_.size() << " users\n";
	for (UserList::const_iterator it = usersLRU_.begin(); it != usersLRU_.end(); ++it) {
		const HTTPUser* u = *it;
		u->printSummary(cout);
		cout << '\n';
	}
}

void HTTPEngine::printTestOutput() const
{
	msgTester_->printOutput();
}

// Code from http://stackoverflow.com/questions/77005/how-to-generate-a-stacktrace-when-my-gcc-c-app-crashes
static void crit_err_handler(int sig_num, siginfo_t * info, void * ucontext)
{
//    sig_ucontext_t * uc = (sig_ucontext_t *)ucontext;
//    void * caller_address = (void *) uc->uc_mcontext.eip; // x86 specific
    void * array[50];
    int size = backtrace(array, 50);

    // First just dump the backtrace using as few extra features as
    // possible. The program is in an unknown state...
    backtrace_symbols_fd(array, size, 2);

    // Then try to make it more readable by demangling symbols.
    std::cerr << "signal " << sig_num
              << " (" << strsignal(sig_num) << "), address is "
              << info->si_addr
//	      << " from " << caller_address
              << std::endl << std::endl;


//    array[1] = caller_address;

    char ** messages = backtrace_symbols(array, size);

    // skip first stack frame (points here)
    for (int i = 1; i < size && messages != NULL; ++i)
    {
        char *mangled_name = 0, *offset_begin = 0, *offset_end = 0;

        // find parantheses and +address offset surrounding mangled name
        for (char *p = messages[i]; *p; ++p)
        {
            if (*p == '(')
            {
                mangled_name = p;
            }
            else if (*p == '+')
            {
                offset_begin = p;
            }
            else if (*p == ')')
            {
                offset_end = p;
                break;
            }
        }

        // if the line could be processed, attempt to demangle the symbol
        if (mangled_name && offset_begin && offset_end &&
            mangled_name < offset_begin)
        {
            *mangled_name++ = '\0';
            *offset_begin++ = '\0';
            *offset_end++ = '\0';

            int status;
            char * real_name = abi::__cxa_demangle(mangled_name, 0, 0, &status);

            // if demangling is successful, output the demangled function name
            if (status == 0)
            {
                std::cerr << "[bt]: (" << i << ") " << messages[i] << " : "
                          << real_name << "+" << offset_begin << offset_end
                          << std::endl;

            }
            // otherwise, output the mangled function name
            else
            {
                std::cerr << "[bt]: (" << i << ") " << messages[i] << " : "
                          << mangled_name << "+" << offset_begin << offset_end
                          << std::endl;
            }
            free(real_name);
        }
        // otherwise, print the whole line
        else
        {
            std::cerr << "[bt]: (" << i << ") " << messages[i] << std::endl;
        }
    }
    std::cerr << std::endl;

    // Make sure we get a core dump if allowed by resource limits.
    signal(SIGABRT, SIG_DFL);
    abort();
}

HTTPStats::HTTPStats()
{
	sessionsSeen = 0;
	pagesSeen = 0;
	packetsSeen[0] = 0;
	packetsSeen[1] = 0;
	IPBytes[0] = 0;
	IPBytes[1] = 0;
	httpBytes[0] = 0;
	httpBytes[1] = 0;
	tcpNum = 0;
	reqNum = 0;
	rspNum = 0;
}
