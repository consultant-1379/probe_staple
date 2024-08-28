#ifndef DATARWTAB_H
#define DATARWTAB_H

#include <string>
#include <iostream>
#include <sstream>

#include <staple/http/Timeval.h>
#include <staple/http/IPAddress.h>
#include <staple/http/globals.h>
#include "HTTPMsg.h"

class LogFile;

class DataWriterTab
{
public:
	DataWriterTab();
	~DataWriterTab();

	// Ownership of 'lf' is not transfered.
	void setLogFile(LogFile* lf);
	LogFile* getLogFile()
	{ return logFile_; }

	void write(int);
	void write(long long);
	void write(const std::string&);
	void write(const std::string&, int maxLen);
	void write(double);
	void write(const Timeval&);
	void write(const IPAddress&);
	void write(HTTPMsg::Method);
	void endRecord();

private:
	DISALLOW_COPY_AND_ASSIGN(DataWriterTab);

	LogFile* logFile_;
	std::stringstream buf_;
	int curCol_;
	template<typename T> void writeSimple(const T& x)
	{

		if (curCol_ > 0)
			buf_ << '\t';
		buf_ << x;
		curCol_++;
	}
};

class DataReaderTab
{
public:
	DataReaderTab(std::istream&);

	std::string readString();
	int readInt();
	long long readLonglong();
	double readDouble();
	Timeval readTimeval();
	IPAddress readIPAddress();
	HTTPMsg::Method readMethod();
	void endRecord();

	bool eof() { return in_.eof(); }

private:
	DISALLOW_COPY_AND_ASSIGN(DataReaderTab);

	int curCol_;
	int curLine_;
	void skipTab();
	template<typename T> T readSimple()
	{
		if (curCol_ > 0)
			skipTab();
		T x;
		in_ >> x;
		curCol_++;
		return x;
	}

	std::istream& in_;
};

#endif
