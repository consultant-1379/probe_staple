#include <assert.h>
#include <iostream>
#include <fstream>
#include <errno.h>
#include <string.h>

#include <staple/http/Counter.h>
#include <staple/http/log.h>
#include "LogFile.h"
#include "DataRWTab.h"

using std::string;
using std::ostream;
using std::fstream;
using std::fill;
using std::set;

int CounterContainer::maxCounterID_ = 0;
CounterContainer::CounterMap CounterContainer::counterIDs_;


set<CounterContainer*>& CounterContainer::getStaticMapContainer ()
{
	static set<CounterContainer*> containers_;
	return containers_;
}

CounterContainer::CounterContainer(Staple& staple) :
	staple_(staple),
	doWrite_(0),
	logFile_(NULL),
	created_(Timeval::getCurrentTime())
{
	getStaticMapContainer ().insert(this);
}

CounterContainer::~CounterContainer()
{
	getStaticMapContainer().erase(this);
}

int CounterContainer::allocateCounter(const std::string& name)
{
	CounterMap::iterator it = counterIDs_.find(name);
	int id;
	if (it == counterIDs_.end()) {
		id = maxCounterID_++;
		counterIDs_[name] = id;

		for (set<CounterContainer*>::iterator it = getStaticMapContainer().begin(); it != getStaticMapContainer().end(); ++it) {
			CounterContainer* cc = *it;
			cc->counters_.resize(maxCounterID_, 0);
		}
	} else {
		id = it->second;
	}

	return id;
}

void CounterContainer::print(LogFile* lf)
{
	DataWriterTab dw;
	dw.setLogFile(lf);
	for (CounterMap::const_iterator it = counterIDs_.begin(); it != counterIDs_.end(); ++it) {
		const CounterMap::value_type& p = *it;
		dw.write(p.first);
		dw.write(counters_[p.second]);
		dw.endRecord();
	}
	lf->flush();
}

void CounterContainer::writeToFile()
{
	if (logFile_) {
		logFile_->openNewLogFile();
		print(logFile_);
	}

	resetAll();
}

void CounterContainer::setLogging(bool enable)
{
	delete logFile_;
	if (enable) {
		logFile_ = new RotatingLogFile(staple_, "counters");
		logFile_->setAutoRotate(false);
	} else {
		logFile_ = NULL;
	}
}

void CounterContainer::resetAll()
{
	fill(counters_.begin(), counters_.end(), 0);
}

void CounterContainer::writeToFileIfNew()
{
	if (!logFile_)
		return;

	Timeval cur(Timeval::getCurrentTime());
	if (cur.diff(created_) < RotatingLogFile::HTTP_ROP)
		return;

	if (logFile_->shouldRotate()) {
		logFile_->openNewLogFile();
		print(logFile_);
		resetAll();
	}
}

Counter::Counter(const std::string& name)
{
	id_ = CounterContainer::allocateCounter(name);
}
