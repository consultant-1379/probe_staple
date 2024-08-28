#include <time.h>
#include <limits>
#include <string.h>

#include <staple/http/Timeval.h>

using std::ostream;
using std::istream;
using std::string;
using std::numeric_limits;

Timeval::Timeval()
{
	tv_.tv_sec = 0;
	tv_.tv_usec = 0;
}

Timeval::Timeval(double sec)
{
	tv_.tv_sec = sec;
	tv_.tv_usec = sec*1000000.0;
}

Timeval::Timeval(int sec, int usec)
{
	tv_.tv_sec = sec;
	tv_.tv_usec = usec;
}

Timeval::Timeval(const struct timeval& tv) : tv_(tv)
{ }

Timeval Timeval::getCurrentTime()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return Timeval(tv);
}

Timeval Timeval::endOfTime()
{
	return Timeval(numeric_limits<int>::max(), 0);
}

double Timeval::toDouble() const
{
	return timevalToDouble(tv_);
}

const struct timeval& Timeval::getTimeval() const
{
	return tv_;
}

double Timeval::diff(const Timeval& o) const
{
	return toDouble() - o.toDouble();
}

bool Timeval::operator< (const Timeval& rhs) const
{
	if (tv_.tv_sec != rhs.tv_.tv_sec)
		return tv_.tv_sec < rhs.tv_.tv_sec;
	else
		return tv_.tv_usec < rhs.tv_.tv_usec;
}

bool Timeval::operator<= (const Timeval& rhs) const
{
	return *this == rhs || *this < rhs;
}

bool Timeval::operator> (const Timeval& rhs) const
{
	return rhs < *this;
}

bool Timeval::operator>= (const Timeval& rhs) const
{
	return rhs <= *this;
}

bool Timeval::operator== (const Timeval& rhs) const
{
	return tv_.tv_sec == rhs.tv_.tv_sec && tv_.tv_usec == rhs.tv_.tv_usec;
}

ostream& operator<<(ostream& o, const Timeval& tv)
{
	char buf[128];
	time_t t = tv.getTimeval().tv_sec;
	struct tm* tm = localtime(&t);
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
	o << buf;
	sprintf(buf, ".%03ld", tv.getTimeval().tv_usec/1000);
	return o << buf;
}

double timevalToDouble(const struct timeval& tv)
{
       return double(tv.tv_sec) + double(tv.tv_usec)/1000000.0;
}

istream& operator>>(std::istream& in, Timeval& tv)
{
	string datePart, timePart;
	char space;
	in >> datePart;
	in >> space;
	in >> timePart;
	string both(datePart + space + timePart);
	struct tm tm;
	memset(&tm, 0, sizeof(tm));
	int year, month, msec;
	int ret = sscanf(both.c_str(), "%d-%d-%d %d:%d:%d.%d",
			 &year,
			 &month,
			 &tm.tm_mday,
			 &tm.tm_hour,
			 &tm.tm_min,
			 &tm.tm_sec,
			 &msec);

	tm.tm_year = year - 1900;
	tm.tm_mon = month - 1;

	if (ret != 7) {
		in.setstate(istream::failbit);
		return in;
	}
	time_t t = mktime(&tm);
	tv.tv_.tv_sec = t;
	tv.tv_.tv_usec = msec*1000;
	return in;
}

