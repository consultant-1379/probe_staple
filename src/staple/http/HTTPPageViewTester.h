#ifndef HTTPPAGEVIEWTESTER_H
#define HTTPPAGEVIEWTESTER_H

#include <vector>
#include <fstream>

#include <staple/http/globals.h>

class Resource;
class HTTPMsg;

class HTTPPageViewTester
{
public:
	HTTPPageViewTester();
	~HTTPPageViewTester();
	void addPageView(const Resource*);
	void addLonelyResource(const Resource*);

private:
	DISALLOW_COPY_AND_ASSIGN(HTTPPageViewTester);

	void printResource(const Resource* r);

	std::vector<Resource*> pageViews_;
	const char* file_;
	std::fstream fout_;
};

#endif
