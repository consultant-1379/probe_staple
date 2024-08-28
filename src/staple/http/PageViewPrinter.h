#ifndef PAGEVIEWPRINTER_H
#define PAGEVIEWPRINTER_H

#include <iostream>
#include <fstream>
#include <string>
#include <map>

#include <staple/http/globals.h>

class Resource;
class HTTPMsg;
class LogFile;

class PageViewPrinter
{
public:
	PageViewPrinter() { }
	virtual void printPageView(const Resource*) = 0;
	virtual void printLonelyResource(const Resource*) = 0;

	virtual void setPageLog(LogFile*) = 0;
	virtual void setRequestLog(LogFile*) = 0;
	virtual LogFile* getPageLog() = 0;
	virtual LogFile* getRequestLog() = 0;

private:
	DISALLOW_COPY_AND_ASSIGN(PageViewPrinter);
};

class PageViewPrinterText : public PageViewPrinter
{
public:
	PageViewPrinterText(std::ostream& o);

	void printPageView(const Resource*);
	void printLonelyResource(const Resource* msg);
	void close();

private:
	DISALLOW_COPY_AND_ASSIGN(PageViewPrinterText);

	std::ostream& out_;
};

#endif
