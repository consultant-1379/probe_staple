#ifndef HTTPPAGEVIEW_H
#define HTTPPAGEVIEW_H

#include <map>
#include <string>
#include <vector>
#include <iostream>
#include <deque>
#include <set>

#include <staple/http/globals.h>
#include <staple/http/Timeval.h>

class HTTPMsg;
class HTTPPageViewTester;
class PageViewPrinter;
class Timeval;
class HTTPUser;
class Resource;

class ResourceVisitor
{
public:
       virtual void visit(const Resource*, int depth) = 0;
};

class Resource
{
public:
	/* Ownership of main is transfered to the resource. It will be
	 * deleted in the destructor. Ownership of conn is not
	 * transfered.
	 */
	Resource(HTTPMsg* main);
	~Resource();

	// Deep clone of this Resource.
	Resource* clone() const;

	HTTPMsg* getMain() const { return main_; }
	void printSummary(std::ostream&) const;

	// Download time in seconds for this resource (including all
	// subresources, if any).
	double downloadTime() const;

	// Number of bytes sent over the network in downlink/uplink
	// direction for this page view. Both headers and (possibly
	// compressed/encoded) bodies are included.
	int getBytesNetworkDL() const;
	int getBytesNetworkUL() const;

	Timeval getStartTime() const;

	// Get time when the last resource was finished.
	Timeval getEndTime() const
	{ return endTime_; }

	/* Get the owner of this resource, or NULL if if it is not
	 * owned by anyone.
	 */
	Resource* getOwner() const { return owner_; }

	/* Get the root owner of this resource. That is, recursively
	 * call getOwner until NULL is returned. Return 'this' when
	 * getOwner returns NULL.
	 *
	 */
	const Resource* getRootOwner() const;

	/* Number of resources contained in this one (including
	 * *this).
	 */
	int numResources() const;

	/* True if all responses were completely parsed, otherwise
	 * false.
	 */
	bool completeResponse() const;

	typedef std::vector<Resource*> ResourceList;
	const ResourceList& getParts() const { return parts_; }

	/* Add a subresource to this resource. On success (true
	 * returned) the ownership is transfered.
	 *
	 * If false is returned the Resource couldn't be added because
	 * it would create a cycle in the ownership relationship
	 * between the resources.
	 */
	bool add(Resource*);
	void visit(ResourceVisitor*, int depth) const;

private:
	DISALLOW_COPY_AND_ASSIGN(Resource);
	/* Set the owner of this resource.
	 * Should only be called by Resource::add.
	 */
	void setOwner(Resource* ar);
	void printSummaryImpl(std::ostream&, int indent) const;
	void updateEndTime(const Timeval& end);

	Resource* owner_;
	HTTPMsg* main_;
	ResourceList parts_;
	Timeval endTime_;
};

#endif
