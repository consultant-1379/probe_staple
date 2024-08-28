#include <limits.h>
#include <assert.h>
#include <stdlib.h>

#include "DataRWTab.h"
#include "LogFile.h"

using std::istream;
using std::ostream;
using std::endl;
using std::string;

DataWriterTab::DataWriterTab() : logFile_(NULL), curCol_(0)
{ }

DataWriterTab::~DataWriterTab()
{ }

void DataWriterTab::setLogFile(LogFile* lf)
{
	assert(curCol_ == 0);
	logFile_ = lf;
}

void DataWriterTab::write(const std::string& s)
{
	write(s, INT_MAX);
}

void DataWriterTab::write(const std::string& s, int maxLen)
{
	int len = 0;
	if (curCol_ > 0)
		buf_ << '\t';
	curCol_++;

	if (s.size() == 0) {
		// Special case empty strings. Some scripts in Perfmon
		// cannot deal with \t\t in the log files.
		buf_ << "\\N";
		return;
	}

	for (size_t i = 0; i < s.size(); i++) {
		char c = s[i];
		len++;
		if (len > maxLen)
			break;

		if (c == '\\')
			buf_ << "\\\\";
		else if (c == '\t')
			buf_ << "\\t";
		else if (c == '\n')
			buf_ << "\\n";
		else if (c == '\r')
			buf_ << "\\r";
		else if (isprint(c))
			buf_ << c;
		else {
			char buf[16];
			sprintf(buf, "\\x%02x", (unsigned char) c);
			buf_ << buf;
		}
	}
}

void DataWriterTab::write(int x)
{
	writeSimple(x);
}

void DataWriterTab::write(long long x)
{
	writeSimple(x);
}

void DataWriterTab::write(double x)
{
	// We don't want scientific notation, use sprintf instead of
	// mucking with C++ manipulators.
	char buf[32];
	snprintf(buf, sizeof(buf), "%f", x);
	writeSimple(buf);
}

void DataWriterTab::write(const Timeval& t)
{
	writeSimple(t);
}

void DataWriterTab::write(const IPAddress& ip)
{
	writeSimple(ip);
}

void DataWriterTab::write(HTTPMsg::Method m)
{
	writeSimple(m);
}

void DataWriterTab::endRecord()
{
	curCol_ = 0;

	logFile_->writeLine(buf_.str());
	buf_.str("");
}

// FIXME: Use curLine_ to print current line number on exception.
DataReaderTab::DataReaderTab(istream& in) : curCol_(0), curLine_(1), in_(in)
{
	in_.exceptions(istream::failbit | istream::badbit);
	in_.unsetf(istream::skipws);
}

void DataReaderTab::skipTab()
{
	char c = in_.get();
	if (c != '\t')
		in_.setstate(istream::failbit);
}

string DataReaderTab::readString()
{
	if (curCol_ > 0)
		skipTab();
	string ret;
	while (true) {
		char c = in_.peek();
		if (c == '\t' || c == '\n')
			break;

		in_.ignore();

		if (c != '\\') {
			ret.push_back(c);
		} else {
			c = in_.get();
			switch (c) {
			case 'n':
				ret.push_back('\n');
				break;
			case 'r':
				ret.push_back('\r');
				break;
			case 't':
				ret.push_back('\t');
				break;
			case '\\':
				ret.push_back('\\');
				break;
			case 'x':
			{
				char buf[3];
				buf[0] = in_.get();
				buf[1] = in_.get();
				buf[2] = '\0';
				assert(isxdigit(buf[0]));
				assert(isxdigit(buf[1]));
				int x = strtoul(buf, NULL, 16);
				ret.push_back(x);
				break;
			}

			case 'N':
				// NUL value. If we see \N we
				// shouldn't have anything else in the
				// string.
				assert(ret.size() == 0);
				c = in_.peek();
				assert(c == '\t' || c == '\n');
				return string();

			default:
				assert(false);
			}
		}
	}

	curCol_++;
	return ret;
}

int DataReaderTab::readInt()
{
	return readSimple<int>();
}

long long DataReaderTab::readLonglong()
{
	return readSimple<long long>();
}

double DataReaderTab::readDouble()
{
	return readSimple<double>();
}

Timeval DataReaderTab::readTimeval()
{
	return readSimple<Timeval>();
}

IPAddress DataReaderTab::readIPAddress()
{
	return readSimple<IPAddress>();
}

HTTPMsg::Method DataReaderTab::readMethod()
{
	return readSimple<HTTPMsg::Method>();
}

void DataReaderTab::endRecord()
{
	char c = in_.get();
	if (c != '\n')
		in_.setstate(istream::failbit);

	// We call peek to set the eof bit of the stream if we are at
	// the end of it.
	in_.peek();
	curCol_ = 0;
	curLine_++;
}
