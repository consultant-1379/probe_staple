#ifndef HTTPMSGTESTER_H
#define HTTPMSGTESTER_H

#include <iostream>
#include <vector>
#include <string>

#include <staple/http/globals.h>
#include "HTTPMsg.h"

class HTTPConnection;

// Used to test HTTPMsg. HTTPEngine passes messages to instances
// of this class.
class HTTPMsgTester
{
public:
	HTTPMsgTester();
	~HTTPMsgTester();

	void addMessage(const HTTPConnection* conn, const HTTPMsg* msg);
	void printOutput();

	struct MsgDetails
	{
		MsgDetails(const HTTPConnection& conn, const HTTPMsg& msg);
		~MsgDetails();

		std::string connectionInfoReq_;
		std::string connectionInfoRsp_;
		HTTPMsg msg;
	};

private:
	DISALLOW_COPY_AND_ASSIGN(HTTPMsgTester);
	void printTestOutput(std::ostream& o) const;

	typedef std::vector<MsgDetails*> MsgVector;
	MsgVector msgs_;
	const char* file_;
};

#endif
