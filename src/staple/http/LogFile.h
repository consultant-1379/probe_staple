#ifndef LOGFILE_H
#define LOGFILE_H

#include <string>
#include <fstream>

#include <staple/http/Timeval.h>
#include <staple/http/globals.h>

class Staple;

/* mkdir(2) all directory components in 'path'. That is, if path is
 * "a/b/c", then mkdir("a", 0777) and mkdir("a/b", 0777) will be
 * called. No errors are reported.
 *
 * FIXME: Should this function be moved to some other file?
 */
void makeLeadingDirs(const std::string& path);

/* All logging goes through the LogFile interface. The main design
 * goal have been to keep the interface as simple as possible and
 * enable an easy to use threaded implementation of RotatingLogFile
 * below.
 */
class LogFile
{
public:
	virtual ~LogFile() { }
	virtual void writeLine(const std::string&) = 0;
	virtual void flush() = 0;
};

/* A rotating log file changes name every HTTP_ROP seconds. The name
 * is 'name'_xxx.log where xxx is the number of seconds since the Unix
 * epoch.
 */
class RotatingLogFile : public LogFile
{
public:
	RotatingLogFile(Staple&, const std::string& name);

        // New log files are opened after HTTP_ROP seconds.
	static const int HTTP_ROP;

	/* Disable/enable auto rotate. Default: enabled.
	 */
	void setAutoRotate(bool enable);

        /* Create a new log file if HTTP_ROP seconds has elapsed since
	 * the last time a new file was created. The file will be
	 * created in ProgramArgs::getPerfmonDirName() and will be
	 * named after creation time and 'name'.
	 *
	 * Return true if a new file was created and false otherwise.
	 */
	bool openNewLogFileIfNecessary();

	/* Create a new log file. Timestamp of creation is returned.
	 */
	Timeval openNewLogFile();

	/* Write one line to the log file and rotate the log file if
	 * necessary (unless setAutoRotate(false) have been called).
	 */
	void writeLine(const std::string&);

	/* Return true if the log file should be rotated now,
	 * otherwise false. Useful if setAutoRotate(false) have been
	 * called.
	 */
	bool shouldRotate() const;

	void flush();

private:
	DISALLOW_COPY_AND_ASSIGN(RotatingLogFile);

	void openNewLogFile(const Timeval&);
	std::string getTempFilename() const;
	std::string getFilename(const Timeval& cur) const;

	Staple& staple_;
	std::string name_;

	// End time of the current ROP.
	Timeval ROPEnd_;
	std::fstream fout_;
	bool autoRotate_;
};

/* A StreamLogFile is just a thin wrapper around a std::ostream.
 */
class StreamLogFile : public LogFile
{
public:
	StreamLogFile(std::ostream&);
	~StreamLogFile();
	void writeLine(const std::string&);
	void flush();

private:
	DISALLOW_COPY_AND_ASSIGN(StreamLogFile);

	std::ostream& out_;
};
#endif
