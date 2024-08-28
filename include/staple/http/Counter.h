#ifndef COUNTER_H
#define COUNTER_H

#include <string>
#include <map>
#include <iostream>
#include <set>
#include <vector>

#include <staple/Staple.h>
#include <staple/http/Timeval.h>
#include <staple/http/globals.h>

class RotatingLogFile;
class LogFile;
class DataReaderTab;
class Counter;
class Staple;

/* The CounterContainer and Counter classes provide a way to
 * efficiently keep track of counters of events. Each counter has an
 * integer ID. The ID is used as an index into
 * CounterContainer::counters_ where the actual counts are held. This
 * approach makes it possible to create multiple CounterContainers
 * (corresponding to multiple instances of the Staple class) with
 * separate counts. Given a Counter ID and an instance of the Staple
 * class increasing the counter is just a matter of a few instructions
 * (one array lookup based on the counter ID and then the increase of
 * the actual counter).
 *
 * Each counter has a name. That name is only used when the counters
 * are logged to a file. No names are used when a counter is
 * increased.
 */

class CounterContainer
{
public:
	CounterContainer(Staple&);
	~CounterContainer();

	/* Allocate a counter ID. This should only be called from
	 * Counter::Counter.
	 */
	static int allocateCounter(const std::string& name);

	/* Increase counter 'c' by one. */
	inline void increase(Counter* c);
	inline long long getCount(Counter* c);

	static std::set<CounterContainer*>& getStaticMapContainer ();


	/* Print all created counters on 'lf'. */
	void print(LogFile* lf);

	/* If 'enable' is true then the are reset and written to the
	 * file Staple::perfmonDirName + "/counters" every
	 * RotatingLogFile::HTTP_ROP seconds.
	 *
	 * If 'enable' is false counters are not written to file.
	 */
	void setLogging(bool enable);

	/* Write all counters to a log file created by
	 * LogFile.cc:openNewLogFileIfNecessary.
	 */
	void writeToFile();

	/* Reset all counters to zero. */
	void resetAll();

private:
	static int maxCounterID_;

	// Map counter names to counter IDs.
	typedef std::map<std::string, int> CounterMap;
	static CounterMap counterIDs_;

	void writeToFileIfNew();

	Staple& staple_;
	unsigned doWrite_;
	RotatingLogFile* logFile_;
	Timeval created_;
	std::vector<long long> counters_;
};

class Counter
{
public:
	Counter(const std::string& name);
	int getID() const { return id_; }

	void increase(Staple& staple)
	{
		staple.getCounterContainer()->increase(this);
	}

private:
	DISALLOW_COPY_AND_ASSIGN(Counter);

	int id_;
};

void CounterContainer::increase(Counter* c)
{
	counters_[c->getID()]++;
	doWrite_++;

	// To avoid calling gettimeofday all the time we only
	// check the timeout once every 2^20 \approx 1e6
	// counter increase.
	if ((doWrite_ & ((1 << 20) - 1)) == 0)
		writeToFileIfNew();
}

long long CounterContainer::getCount(Counter* c)
{
	return counters_[c->getID()];
}

/* A helper macro to simplify the task of creating and increasing a
 * counter by name.
 */
#define COUNTER_INCREASE(name)					  \
	do {							  \
		static Counter* counter = NULL;			  \
		if (!counter)					  \
			counter = new Counter(name);		  \
		counter->increase(staple_);			  \
	} while(0)

#endif
