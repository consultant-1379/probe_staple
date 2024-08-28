#ifndef PAGEVIEWPRINTERTAB_H
#define PAGEVIEWPRINTERTAB_H

#include <iostream>
#include <fstream>
#include <string>
#include <limits.h>
#include <sstream>

#include <staple/TCPConn.h>
#include <staple/http/globals.h>
#include <staple/http/Timeval.h>
#include "PageViewPrinter.h"
#include "DataRWTab.h"
#include "HTTPMsg.h"

class Resource;
class Staple;

class PageViewPrinterTab : public PageViewPrinter
{
public:
	PageViewPrinterTab(const Staple&);
	~PageViewPrinterTab();

	void printPageView(const Resource*);
	void printLonelyResource(const Resource*);
	void setPageLog(LogFile*);
	void setRequestLog(LogFile*);
	LogFile* getPageLog();
	LogFile* getRequestLog();

private:
	DISALLOW_COPY_AND_ASSIGN(PageViewPrinterTab);

	void writeRequests(const Resource* r);
	DataWriterTab dwPage_, dwRequest_;
	int pageID_;
	const Staple& staple_;
};

#endif
