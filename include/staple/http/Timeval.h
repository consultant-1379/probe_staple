#ifndef TIMEVAL_H
#define TIMEVAL_H

#include <iostream>
#include <sys/time.h>

class Timeval
{
public:
	Timeval();
	explicit Timeval(double sec);
	Timeval(int sec, int usec);
	// We are allowing implicit conversion from struct timeval.
	Timeval(const struct timeval&);

	static Timeval getCurrentTime();
	static Timeval endOfTime();

	// Seconds since the Unix epoch.
	double toDouble() const;

	const struct timeval& getTimeval() const;
	time_t getSec() const { return tv_.tv_sec; }
	suseconds_t getUsec() const { return tv_.tv_usec; }

	// Compute difference in seconds between *this and o. In
	// symbols: return *this - o in seconds.
	double diff(const Timeval& o) const;

	bool operator< (const Timeval&) const;
	bool operator<= (const Timeval&) const;
	bool operator> (const Timeval&) const;
	bool operator>= (const Timeval&) const;
	bool operator== (const Timeval&) const;

	friend std::istream& operator>>(std::istream&, Timeval&);

private:
	struct timeval tv_;
};

std::ostream& operator<<(std::ostream&, const Timeval&);
std::istream& operator>>(std::istream&, Timeval&);

double timevalToDouble(const struct timeval& tv);

#endif
