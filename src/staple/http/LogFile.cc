#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <limits.h>

#include <staple/Staple.h>
#include <staple/http/Timeval.h>
#include <staple/http/log.h>
#include "LogFile.h"

using std::string;
using std::fstream;
using std::ostream;

const int RotatingLogFile::HTTP_ROP = PERFMON_ROP;

void makeLeadingDirs(const string& path)
{
	string prefix;
	for (size_t i = 0; i < path.size(); i++) {
		char c = path[i];
		if (c == '/')
			mkdir(prefix.c_str(), 0777); // We don't care if this succeeds or not.
		prefix.push_back(c);
	}
}

RotatingLogFile::RotatingLogFile(Staple& staple, const string& name)
	: staple_(staple), name_(name),  ROPEnd_(0), autoRotate_(true)
{
	fout_.exceptions(fstream::failbit | fstream::badbit);
}

void RotatingLogFile::flush()
{
	if (fout_.is_open())
		fout_.flush();
}

void RotatingLogFile::setAutoRotate(bool enable)
{
	autoRotate_ = enable;
}

string RotatingLogFile::getTempFilename() const
{
	char buf[PATH_MAX];
	snprintf(buf, sizeof(buf), "%s/%s%s.tmp",
		 staple_.perfmonDirName.c_str(),
		 name_.c_str(),
		 staple_.perfmonLogPrefix.c_str());
	return buf;
}

string RotatingLogFile::getFilename(const Timeval& cur) const
{
	char buf[PATH_MAX];

	//Calculate the previous ROP Time
	time_t previousRopTime = cur.getSec() - HTTP_ROP;
	struct tm * prevRopTime;
	prevRopTime = gmtime ( &previousRopTime );
	char prevTimeStamp[4];
	sprintf(prevTimeStamp, "%02d%02d", prevRopTime->tm_hour, prevRopTime->tm_min);

	//Calculate the current ROP Time
	time_t epochTime = cur.getSec();
	struct tm * ropTime;
	ropTime = gmtime ( &epochTime );

	//Create the Time stamp string in the format: A<year><month><day>.<previousRop HourMinute><currentRop HourMinute>
	char fileTimeStamp[20];
	sprintf(fileTimeStamp, "A%04d%02d%02d.%s-%02d%02d", (ropTime->tm_year+1900), (ropTime->tm_mon+1), ropTime->tm_mday, prevTimeStamp, ropTime->tm_hour, ropTime->tm_min);


	snprintf(buf, sizeof(buf), "%s/%s_staple_%s_%ld%s.log",
		 staple_.perfmonDirName.c_str(),
		 fileTimeStamp,
		 name_.c_str(),
		 (long) cur.getSec(),
		 staple_.perfmonLogPrefix.c_str());
	return buf;
}

Timeval RotatingLogFile::openNewLogFile()
{
	Timeval cur(Timeval::getCurrentTime());
	openNewLogFile(cur);
	return cur;
}

void RotatingLogFile::openNewLogFile(const Timeval& cur)
{
	string tmpName(getTempFilename());
	if (fout_.is_open()) {
		fout_.close();
		string newName(getFilename(ROPEnd_));
		if (rename(tmpName.c_str(), newName.c_str())) {
			error(staple_, "RotatingLogFile::openNewLogFile: Failed to rename log file '",
			      tmpName, "' -> '", newName, "': ", strerror(errno));
			// We ignore the error and keep going. The old
			// temporary log file will be overwritten.
		}
	}

	makeLeadingDirs(tmpName);
	fout_.open(tmpName.c_str(), fstream::out|fstream::trunc);
	if (!fout_.is_open()) {
		error(staple_, "RotatingLogFile::openNewLogFile: Failed to open log file: '",
		      tmpName, "': ", strerror(errno));
		// FIXME do something more sensible here?
		assert(false);
	}
	ROPEnd_ = Timeval(ROPEnd_.getSec() + HTTP_ROP);

	/* ROPEnd_ is initialized to 0 in the constructor so in the
	 * first call to this method the condition below will be
	 * true. It will also be true if we didn't log anything for an
	 * entire ROP.
	 */
	if (ROPEnd_ < cur) {
		long secs = cur.getSec();
		ROPEnd_ = Timeval(secs + HTTP_ROP - secs % HTTP_ROP);
	}
}

bool RotatingLogFile::openNewLogFileIfNecessary()
{
	Timeval cur(Timeval::getCurrentTime());

	if (!fout_.is_open() ||
	    (autoRotate_ && ROPEnd_ < cur)) {
		openNewLogFile(cur);
		return true;
	} else {
		return false;
	}
}

void RotatingLogFile::writeLine(const string& s)
{
	/* FIXME: We can avoid calling openNewLogFileIfNecessary
	 * (which calls gettimeofday) here by creating a thread which
	 * waits for HTTP_ROP seconds and then rotates all log files.
	 *
	 * As all use of fout_ goes through writeLine the locking will
	 * be simple and contained within the RotatingLogFile class.
	 */

	openNewLogFileIfNecessary();
	fout_ << s << '\n';
}

bool RotatingLogFile::shouldRotate() const
{
	return ROPEnd_ < Timeval::getCurrentTime();
}

StreamLogFile::StreamLogFile(ostream& o) : out_(o)
{ }

StreamLogFile::~StreamLogFile()
{ }

void StreamLogFile::writeLine(const std::string& s)
{
	out_ << s << '\n';
}

void StreamLogFile::flush()
{
	out_.flush();
}

