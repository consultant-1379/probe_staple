#ifndef STAPLEJNIIMPL_H
#define STAPLEJNIIMPL_H

#include <staple/Staple.h>
#include <jni.h>


class StapleJniImpl : public Staple
{

public:
	enum eventTypes {
		// TCPTA session file
		TCPTA,
		// Partial TCPTA session File
		TCPTA_PARTIAL,
		// Flash Video File
		FLV_FULL,
		// Partial flash video session file
		FLV_PARTIAL,
		// Invalid session file
		INVALID
	};



	StapleJniImpl() : lastPerfmonROP(0)
	{
		// Default log is sdtout
		logStream.rdbuf(std::cout.rdbuf());
	}
	void start(JNIEnv *, jobject, jstring, jstring, jstring, jstring, jstring, jstring, jint,
			jstring, jboolean, jint, jstring, jstring, jboolean, jstring, jboolean, jboolean, jint);
	void start(const char * ipAndMaskA, const char * ipAndMaskB, const char * macA, const char * macB,
			std::string pcapdumpfile, std::string tempfileprefix, int slot_Time, const char * logFileName, bool ignore_L2_DupPackets,
			int logLevel, std::string log_Directory, std::string log_Prefix, bool noHTTP, char * inputDumpFileName,
			bool publishToHazelcast, bool writeOutputToFile, int flushPeriod);
	void writeLog(bool p_isFinal);
	int publishEvent(int eventType, std::string event);
	void flush();
	JNIEnv* JNU_GetEnv();
	jstring JNU_NewStringUTF(JNIEnv* env, jboolean* hasException, std::string str);
	jvalue JNU_CallMethodByName(JNIEnv* env, jboolean* hasException,
			const char* name, const char* descriptor, ...);
	void throwJavaException(const char *message);

	// Perfmon log files
	std::ofstream     flvfile;
	std::ofstream     flvpartialfile;
	std::ofstream     tcptafile;
	std::ofstream     tcptapartialfile;
	// The ROP number of the last Perfmon log file
	unsigned long     lastPerfmonROP;
};

#endif
