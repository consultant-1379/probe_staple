/*
 * StapleJniImpl.cc
 *
 *  Created on: 19 Jan 2012
 *      Author: eeidbnn
 */

#include <jni/StapleJniInterface.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#include <staple/Parser.h>
#include <staple/http/Counter.h>
#include <staple/http/log.h>

#include <jni/StapleJniImpl.h>


#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>

void handler(int sig) {
	void *array[10];
	size_t size;

	// get void*'s for all entries on the stack
	size = backtrace(array, 10);

	// print out all the frames to stderr
	fprintf(stderr, "Error: signal %d:\n", sig);
	backtrace_symbols_fd(array, size, 2);
}

//Native counterpart to the StapleJniInterface publish method
struct hazelcastPublisher {
	//back pointer to the StapleJniInterface which calls this class
	jobject backPtr;

	/**
	 * Callback method which is used to publish the event using Hazelcast.
	 * @param eventType The type of event: 0 = TCPTA, 1 = TCPTA_PARTIAL, 2 = FLV, 3 = FLV_PARTIAL and 4 = INVALID
	 * @param event The Event text to publish
	 */
	void publishEvent(jint eventType, jstring event);

	/**
	 * Flushes the publiser's cache.
	 */
	void flush();

};

struct ThreadArgs {
	StapleJniImpl& stapleJni;
	Parser& parser;
};

struct FlushThreadArgs {
	StapleJniImpl& stapleJni;
	int flushPeriod;
};

void* ParserThreadLauncher(void*);
void* FlushThread(void*);

JavaVM *jvm;
StapleJniImpl jniStaple;
hazelcastPublisher *cpp_obj = new hazelcastPublisher();
int traceLevel = 0;
bool SHUTTING_DOWN = false;


/**
 * This method instructs all the Publishers to flush their cache.
 */
void StapleJniImpl::flush()
{
	if (traceLevel>=3) std::cout << "StapleJniImpl::flush-->\n";
	jboolean has_exception;
	JNIEnv* env = JNU_GetEnv();
	//	if (traceLevel>=3) std::cout << "StapleJniImpl::flush: Calling the CallMethodByName(" << env << ", " << has_exception << ", " << cpp_obj->backPtr << ", flush, ()V\n";
	jniStaple.JNU_CallMethodByName(env, &has_exception, "flush", "()V");
	if(has_exception){
		env->ExceptionClear();
		if (traceLevel>=3) std::cout << "StapleJniImpl::flush: Exception attempting to flush the buffer";
	}
	if (traceLevel>=3) std::cout << "StapleJniImpl::flush-->\n";
}


/*
 * Class:     com_ericsson_eniqanalysis_probing_jni_StapleJniInterface
 * Method:    startStaple
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;ZILjava/lang/String;ZZZ)V
 *
 * @param inputDumpFile name of the input pcap packet dump file to process
 * @param ipAddressAndMaskA IP, port and mask of Net A (port is optional)
 * @param ipAddressAndMaskB IP, port and mask of Net B (port is optional)
 * @param macA MAC address (or prefix) of the Net A device
 * @param macB MAC address (or prefix) of the Net B device
 * @param outputInterval The time interval at which staple should output new files.
 * @param logFile The name of the staple log file
 * @param ignoreL2DupPackets ignore layer 2 duplicate packets (default: false)
 * @param traceLevel The trace level.
 * 					0 - quiet (no logging)
 * 					1 - log overall statistics
 *  				2 - log individual statistics
 *   				3 - log packets
 *    				4 - log packet payload
 *    				5 - log debug info
 * @param stapleOutputDirectory The directory where staple will output the dump files
 * @param noHttpProcessing don't do any HTTP processing
 * @param publishInHazelcast Indicates if staple should publish to Hazelcast
 * @param outputToFile Indicates if staple should output dump files to the stapleOutputDirectory
 */
JNIEXPORT void JNICALL Java_com_ericsson_eniqanalysis_probing_jni_StapleJniInterface_startStaple
(JNIEnv *env, jobject jobj, jstring inputDumpFile, jstring ipAddressAndMaskA, jstring ipAddressAndMaskB,
		jstring mac_A, jstring mac_B, jint slotTime, jstring logFile, jstring logPrefix, jboolean ignoreL2DupPackets,
		jint tracelevel, jstring stapleOutputDirectory, jboolean noHttpProcessing, jboolean publishInHazelcast,
		jboolean outputToFile, jint flushPeriod)
{
	signal(SIGSEGV, handler);   // install stacktrace handler
	traceLevel = tracelevel;

	if (traceLevel>=3) std::cout << "StapleJniInterface_startStaple(env:"<<env<<") -->\n";

	cpp_obj->backPtr = env->NewGlobalRef(jobj);
	env -> GetJavaVM(&jvm);

	const char *ipAndMaskA = 0, *ipAndMaskB = 0, *macA = 0, *macB = 0;
	const char *logFileName = 0, *logFilePrefix = 0, *inputPcapFile=0, *outputDirectory=0;

	if (ipAddressAndMaskA != NULL) ipAndMaskA = env->GetStringUTFChars(ipAddressAndMaskA, 0);
	if (ipAddressAndMaskB != NULL) ipAndMaskB = env->GetStringUTFChars(ipAddressAndMaskB, 0);
	if (mac_A != NULL) macA = env->GetStringUTFChars(mac_A, 0);
	if (mac_B != NULL) macB = env->GetStringUTFChars(mac_B, 0);

	if (logFile != NULL) logFileName = env->GetStringUTFChars(logFile, 0);
	if (logPrefix != NULL) logFilePrefix = env->GetStringUTFChars(logPrefix, 0);
	if (stapleOutputDirectory != NULL) outputDirectory = env->GetStringUTFChars(stapleOutputDirectory, 0);
	if (inputDumpFile != NULL) inputPcapFile = (char*)env->GetStringUTFChars(inputDumpFile, 0);

	if (traceLevel>=3) std::cout << "\n\nThe following parameters have being passed: ";
	if (inputPcapFile!=0) if (traceLevel>=3) std::cout << "\n inputPcapFile: " << inputPcapFile;
	if (ipAndMaskA!=0) if (traceLevel>=3) std::cout << "\n ipAndMaskA: " << ipAndMaskA;
	if (ipAndMaskB!=0) if (traceLevel>=3) std::cout << "\n ipAndMaskB: " << ipAndMaskB;
	if (macA!=0) if (traceLevel>=3) std::cout << "\n macA: " << macA;
	if (macB!=0) if (traceLevel>=3) std::cout << "\n macB: " << macB;
	if (traceLevel>=3) std::cout << "\n slotTime: " << slotTime;
	if (logFileName!=0) if (traceLevel>=3) std::cout << "\n logFile: " << logFileName;
	if (traceLevel>=3) std::cout << "\n ignoreL2DupPackets: " << ((int)(ignoreL2DupPackets) == 1 ? "true" : "false");
	if (traceLevel>=3) std::cout << "\n traceLevel: " << traceLevel;
	if (outputDirectory!=0) if (traceLevel>=3) std::cout << "\n stapleOutputDirectory: " << outputDirectory;
	if (traceLevel>=3) std::cout << "\n Publish To Hazelcast: " << ((int)(publishInHazelcast) == 1 ? "true" : "false");
	if (traceLevel>=3) std::cout << "\n Write Output to file: " << ((int)(outputToFile) == 1 ? "true" : "false");
	if (traceLevel>=3) std::cout << "\n flushPeriod: " << flushPeriod;

	if (traceLevel>=3) std::cout << "\n\nAbout to call the parser!\n";
	std::string empty = "";
	jniStaple.start(ipAndMaskA, ipAndMaskB, macA, macB, empty, empty, (int)slotTime,
			logFileName, (bool)(ignoreL2DupPackets), (int)traceLevel, outputDirectory, logFilePrefix,
			(bool)(noHttpProcessing), (char*)inputPcapFile, (bool)publishInHazelcast, (bool)outputToFile, (int)flushPeriod);

	if (traceLevel>=3) std::cout << "\n\nFinished processing the file: " << inputDumpFile << "\n\n";
	if(env->ExceptionCheck()){
		if (traceLevel>=3) std::cout << "\n\nException in StapleJniImpl";
	}


	if (traceLevel>=3) std::cout << "\nReturning to Java....\n";

	env->ReleaseStringUTFChars(ipAddressAndMaskA, ipAndMaskA);
	env->ReleaseStringUTFChars(ipAddressAndMaskB, ipAndMaskB);
	env->ReleaseStringUTFChars(mac_A, macA);
	env->ReleaseStringUTFChars(mac_B, macB);
	env->ReleaseStringUTFChars(logFile, logFileName);
	env->ReleaseStringUTFChars(logPrefix, logFilePrefix);
	env->ReleaseStringUTFChars(stapleOutputDirectory, outputDirectory);
	env->ReleaseStringUTFChars(inputDumpFile, inputPcapFile);

	if (traceLevel>=3) std::cout << "StapleJniInterface_startStaple() <--\n";
	return;
}

/**
 * This method is used to terminate the Staple application when eniq-analysis
 * is being shut down
 */
JNIEXPORT void JNICALL Java_com_ericsson_eniqanalysis_probing_jni_StapleJniInterface_terminate
  (JNIEnv *, jobject){
	SHUTTING_DOWN = true;
}


/**
 * Callback method which is used to publish the event using Hazelcast.
 * @param eventType The type of event. See the
 * 				StapleJniImpl.eventTypes enum:
 * 				0 = TCPTA, 1 = TCPTA_PARTIAL, 2 = FLV,
 * 				3 = FLV_PARTIAL and 4 = INVALID
 * @param event The Event text to publish
 */
int StapleJniImpl::publishEvent(int eventType, std::string event)
{
	if (traceLevel>=3) std::cout << "StapleJniImpl::publishEvent-->\n";
	jboolean has_exception;
	JNIEnv* env = JNU_GetEnv();
	jstring eventString = jniStaple.JNU_NewStringUTF(env, &has_exception, event);
	jniStaple.JNU_CallMethodByName(env,
			&has_exception,
			"publishEvent",
			"(ILjava/lang/String;)V",
			(jint)eventType,
			eventString);
	if (has_exception) {
		env->ExceptionClear();
		return -1;
	} else {
		if (traceLevel>=3) std::cout << "StapleJniImpl::publishEvent <--\n";
		return 0;
	}
}



JNIEnv* StapleJniImpl::JNU_GetEnv(){
	JNIEnv* env;
	int status = jvm -> GetEnv((void**)&env,JNI_VERSION_1_6);
	if(status < 0) {
		if (traceLevel>=3) std::cout << "callback_handler: failed to get JNI environment, assuming native thread\n";
		status = jvm->AttachCurrentThread((void**)&env, NULL);
		if(status < 0) {
			if (traceLevel>=3) std::cout << "callback_handler: failed to attach current thread\n";
		}
	}
	return env;
}

/**
 * Creates a jstring corresponding to the given string object
 */
jstring StapleJniImpl::JNU_NewStringUTF(JNIEnv* env, jboolean* hasException, std::string str){
	if((hasException==NULL)||((*hasException)==JNI_FALSE)){
		jstring jstr=env->NewStringUTF(str.c_str());
		if(hasException){
			(*hasException)=env->ExceptionCheck();
		}
		return jstr;
	}
	return NULL;
}

/**
 * Calls the JNI method with the given name
 * hasException: indicates if this method generated any errors
 * name: The name of the method to call
 * descriptor: The method signature
 * va_list args: The method args (if any)
 */
jvalue StapleJniImpl::JNU_CallMethodByName(JNIEnv* env, jboolean* hasException,
		const char* name, const char* descriptor, ...){

	va_list args;
	jclass clazz;
	jmethodID mid;
	jvalue result={0};
	jobject obj = cpp_obj->backPtr;

	if(env->EnsureLocalCapacity(2)==JNI_OK){
		clazz=env->GetObjectClass(obj);
		mid=env->GetMethodID(clazz,name,descriptor);
		if(mid){
			const char* p=descriptor;
			while(*p!=')'){ p++;} p++;
			va_start(args,descriptor);
			switch(*p){
			case 'V':           env->CallVoidMethodV(obj,mid,args);               break;
			case '[': case 'L': result.l=env->CallObjectMethodV(obj,mid,args);    break;
			case 'Z':           result.z=env->CallBooleanMethodV(obj,mid,args);   break;
			case 'B':           result.b=env->CallByteMethodV(obj,mid,args);      break;
			case 'C':           result.c=env->CallCharMethodV(obj,mid,args);      break;
			case 'S':           result.s=env->CallShortMethodV(obj,mid,args);     break;
			case 'I':           result.i=env->CallIntMethodV(obj,mid,args);       break;
			case 'J':           result.j=env->CallLongMethodV(obj,mid,args);      break;
			case 'F':           result.f=env->CallFloatMethodV(obj,mid,args);     break;
			case 'D':           result.d=env->CallDoubleMethodV(obj,mid,args);    break;
			default: env->FatalError("jnu.cpp - JNU_CallMethodByName : Illegal descriptor.");
			}
			va_end(args);
		}else{
			fprintf(stdout,"COULD NOT FIND %s\n",name);
		}
		env->DeleteLocalRef(clazz);
	}

	if(hasException){
		*hasException=env->ExceptionCheck();
	}
	return result;
}


/**
 * This method throws a java.lang.Exception object with the specified message
 * back to the calling java application.
 * Note: An exception raised through JNI (in this method) does not immediately
 * disrupt the native method execution.  Flow control must be implemented in
 * the calling methods i.e. explicit return statements are required.
 */
void StapleJniImpl::throwJavaException(const char *message){
	std::cerr << message << "\n";
	jclass newExcCls;
	JNIEnv* env = JNU_GetEnv();
	newExcCls = env->FindClass("java/lang/Exception");
	if (newExcCls != NULL) {
		env->ThrowNew(newExcCls, message);
	}
	env->DeleteLocalRef(newExcCls);
	return;
}



void StapleJniImpl::start(const char * ipAndMaskA, const char * ipAndMaskB, const char * macA, const char * macB,
		std::string pcapdumpfile, std::string tempfileprefix, int slot_Time, const char * logFileName, bool ignore_L2_DupPackets,
		int logLevel, std::string log_Directory, std::string log_Prefix, bool noHTTP, char * inputDumpFileName,
		bool publishToHazelcast, bool writeOutputToFile, int flushPeriod)
{
	if (traceLevel>=3) std::cout << "StapleJniImpl::start()-->\n";
	//setLogLevel(logLevel);
	outfileSlotTime = slot_Time;
	if (pcapdumpfile != ""){
		outputDumpGiven = true;
		outputDumpPrefix = pcapdumpfile;
	}
	if (tempfileprefix != "") outputDumpTmpPrefix = tempfileprefix;
	ignoreL2Duplicates = ignore_L2_DupPackets;
	if (log_Directory != "") perfmonDirName = log_Directory;
	if (log_Prefix != "") perfmonLogPrefix = log_Prefix;



	if (macA != NULL && *macA != '\0'){
		netMACLen[0] = sscanf (macA,"%x:%x:%x:%x:%x:%x",&netMAC[0].addr[0],&netMAC[0].addr[1],
				&netMAC[0].addr[2],&netMAC[0].addr[3],&netMAC[0].addr[4],&netMAC[0].addr[5]);
		if ((netMACLen[0]>6) || (netMACLen[0]<0))
			netMACLen[0]=0;
	}
	if (macB != NULL && *macB != '\0'){
		netMACLen[1] = sscanf (macB,"%x:%x:%x:%x:%x:%x",&netMAC[1].addr[0],&netMAC[1].addr[1],
				&netMAC[1].addr[2],&netMAC[1].addr[3],&netMAC[1].addr[4],&netMAC[1].addr[5]);
		if ((netMACLen[1]>6) || (netMACLen[1]<0))
			netMACLen[0]=0;
	}

	if (ipAndMaskA != NULL && *ipAndMaskA != '\0'){
		unsigned short netId = 0;

		unsigned short IP[4];
		unsigned short mask, port;

		// Only network is given
		if (sscanf (ipAndMaskA,"%hu.%hu.%hu.%hu/%hu",&IP[0],&IP[1],&IP[2],&IP[3],&mask) == 5)
		{
			netIP[netId][addrFilterNum[netId]].byte[0] = IP[3*byteOrderPlatform];
			netIP[netId][addrFilterNum[netId]].byte[1] = IP[1+byteOrderPlatform];
			netIP[netId][addrFilterNum[netId]].byte[2] = IP[2-byteOrderPlatform];
			netIP[netId][addrFilterNum[netId]].byte[3] = IP[3*(1-byteOrderPlatform)];
			netMask[netId][addrFilterNum[netId]].data = (mask != 32) ? ((((unsigned long)1)<<mask)-1)<<(32-mask) :
					0xffffffff;
			netGiven[netId][addrFilterNum[netId]] = true;
			portGiven[netId][addrFilterNum[netId]] = false;
		}
		// Network and port is given
		else if (sscanf (ipAndMaskA,"%hu.%hu.%hu.%hu:%hu/%hu",&IP[0],&IP[1],&IP[2],&IP[3],&port,&mask) == 6)
		{
			netIP[netId][addrFilterNum[netId]].byte[0] = IP[3*byteOrderPlatform];
			netIP[netId][addrFilterNum[netId]].byte[1] = IP[1+byteOrderPlatform];
			netIP[netId][addrFilterNum[netId]].byte[2] = IP[2-byteOrderPlatform];
			netIP[netId][addrFilterNum[netId]].byte[3] = IP[3*(1-byteOrderPlatform)];
			netMask[netId][addrFilterNum[netId]].data = (mask != 32) ? ((((unsigned long)1)<<mask)-1)<<(32-mask) :
					0xffffffff;
			netPort[netId][addrFilterNum[netId]] = port;
			netGiven[netId][addrFilterNum[netId]] = true;
			portGiven[netId][addrFilterNum[netId]] = true;
		}
		// Only port is given
		else if (sscanf (ipAndMaskA,":%hu",&port) == 1)
		{
			netPort[netId][addrFilterNum[netId]] = port;
			netGiven[netId][addrFilterNum[netId]] = false;
			portGiven[netId][addrFilterNum[netId]] = true;
		}
		// Wrong input
		else
		{
			throwJavaException("Staple Error: Wrong Net IP");
			return;
		}

		addrFilterNum[netId]++;
	}
	if (ipAndMaskB != NULL && *ipAndMaskB != '\0'){
		unsigned short netId = 1;

		unsigned short IP[4];
		unsigned short mask, port;

		// Only network is given
		if (sscanf (ipAndMaskB,"%hu.%hu.%hu.%hu/%hu",&IP[0],&IP[1],&IP[2],&IP[3],&mask) == 5)
		{
			netIP[netId][addrFilterNum[netId]].byte[0] = IP[3*byteOrderPlatform];
			netIP[netId][addrFilterNum[netId]].byte[1] = IP[1+byteOrderPlatform];
			netIP[netId][addrFilterNum[netId]].byte[2] = IP[2-byteOrderPlatform];
			netIP[netId][addrFilterNum[netId]].byte[3] = IP[3*(1-byteOrderPlatform)];
			netMask[netId][addrFilterNum[netId]].data = (mask != 32) ? ((((unsigned long)1)<<mask)-1)<<(32-mask) :
					0xffffffff;
			netGiven[netId][addrFilterNum[netId]] = true;
			portGiven[netId][addrFilterNum[netId]] = false;
		}
		// Network and port is given
		else if (sscanf (ipAndMaskB,"%hu.%hu.%hu.%hu:%hu/%hu",&IP[0],&IP[1],&IP[2],&IP[3],&port,&mask) == 6)
		{
			netIP[netId][addrFilterNum[netId]].byte[0] = IP[3*byteOrderPlatform];
			netIP[netId][addrFilterNum[netId]].byte[1] = IP[1+byteOrderPlatform];
			netIP[netId][addrFilterNum[netId]].byte[2] = IP[2-byteOrderPlatform];
			netIP[netId][addrFilterNum[netId]].byte[3] = IP[3*(1-byteOrderPlatform)];
			netMask[netId][addrFilterNum[netId]].data = (mask != 32) ? ((((unsigned long)1)<<mask)-1)<<(32-mask) :
					0xffffffff;
			netPort[netId][addrFilterNum[netId]] = port;
			netGiven[netId][addrFilterNum[netId]] = true;
			portGiven[netId][addrFilterNum[netId]] = true;
		}
		// Only port is given
		else if (sscanf (ipAndMaskB,":%hu",&port) == 1)
		{
			netPort[netId][addrFilterNum[netId]] = port;
			netGiven[netId][addrFilterNum[netId]] = false;
			portGiven[netId][addrFilterNum[netId]] = true;
		}
		// Wrong input
		else
		{
			throwJavaException("Staple Error: Wrong Net IP");
			return;
		}

		addrFilterNum[netId]++;
	}


	// At least one network IP has to be given OR at least one MAC address
	if ((addrFilterNum[0]==0) && (addrFilterNum[1]==0) && (netMACLen[0]==0) && (netMACLen[1]==0))
	{
		throwJavaException("Staple Error: No network is specified");
		return;
	}
	// Network IP addresses should not overlap
	if ((addrFilterNum[0]>0) && (addrFilterNum[1]>0) &&
			(netIP[0][0].data & netMask[0][0].data & netMask[1][0].data) == (netIP[1][0].data & netMask[0][0].data & netMask[1][0].data))
	{
		throwJavaException("Staple Error: Overlapping network addresses");
		return;
	}

	// Create logfile if necessary
	std::ofstream logFile;
	if ((logLevel > 0) && (logFileName != 0))
	{
		// Open file
		logFile.open(logFileName,std::ios::out|std::ios::app);
		if (!logFile.good())
		{
			throwJavaException("Staple Error opening the logfile.");
			return;
		}

		// Redirect log output to logfile
		logStream.rdbuf(logFile.rdbuf());
	}

	// Create list of input packet dump files (but do not open them yet)
	PacketDumpFile::ErrorCode errorCode = packetDumpFile.CreateInputFileList(inputDumpFileName);

	// Open (first) input packet dump file
	errorCode = packetDumpFile.FirstInputFile();
	if (errorCode != PacketDumpFile::NO_ERROR)
	{
		throwJavaException("Staple Error opening the input dumpfile.");
		return;
	}

	// Read dumpfile entries step-by-step
	// ----------------------------------
	L2Packet* pL2Packet = NULL;
	L3Packet* pL3Packet = NULL;

	// Initialize the parser
	Parser parser(*this);
	parser.Init();
	parser.perfmonTCPTAFile = &tcptafile;
	parser.perfmonTCPTAPartialFile = &tcptapartialfile;
	parser.perfmonFLVFile = &flvfile;
	parser.perfmonFLVPartialFile = &flvpartialfile;

	parser.hazelcastPublish = publishToHazelcast;
	parser.writeToFile = writeOutputToFile;


	if (!noHTTP)
	{
		parser.setHTTPPageLog(true);
		parser.setHTTPRequestLog(true);
		getCounterContainer()->setLogging(true);
	}

	pthread_t flushThread;
	if (publishToHazelcast){
		struct FlushThreadArgs flushThreadArgs = {*this, flushPeriod};
		pthread_create(&flushThread, NULL, FlushThread, (void*) &flushThreadArgs);
	}

	// Launch perfmon logfile writer thread
	pthread_t thread;
	struct ThreadArgs t = {*this, parser};
	pthread_create(&thread, NULL, ParserThreadLauncher, (void*) &t);

	//Continue until no more to read from the file or
	//a terminate request is received
	while (!SHUTTING_DOWN)
	{
		// Delete last packet
		if (pL2Packet != NULL) delete pL2Packet;
		// Read next packet
		pL2Packet = packetDumpFile.ReadPacket(&errorCode);
		// Handle errors
		if (errorCode == PacketDumpFile::ERROR_EOF)
		{
			// EOF: try to open next input file (if available)
			errorCode = packetDumpFile.NextInputFile();
			if (errorCode != PacketDumpFile::NO_ERROR)
			{
				// Cannot open next input file, stop execution
				break;
			}
			else
			{
				// Successful open, continue reading packets
				continue;
			}
		}
		if (errorCode == PacketDumpFile::ERROR_FORMAT) continue;
		if (errorCode == PacketDumpFile::ERROR_L2_DUPLICATE) continue;
		if (pL2Packet == NULL) continue;

		// Parse the packet
		parser.ParsePacket(pL2Packet);
	}

	// TCPdump file processed
	// ----------------------
	// Finish ongoing connections
	parser.FinishConnections();

	// Delete last packet
	if (pL2Packet != NULL) delete pL2Packet;

	// Print overall statistics
	if (logLevel >= 1)
	{
		parser.PrintOverallStatistics(logStream);
	}

	if (!noHTTP) getCounterContainer()->writeToFile();

	// Close output dump file
	if (outputDumpGiven == true) packetDumpFile.CloseOutputFile();

	// Terminate perfmon logfile writer thread
	pthread_cancel(thread);
	pthread_join(thread, 0);

	// Terminate the Hazelcast flush thread
	if (publishToHazelcast){
		pthread_cancel(flushThread);
		pthread_join(flushThread, 0);
	}

	// Write and close final perfmon logfiles
	writeLog(true);

	//Flush the Hazelcast buffer
	StapleJniImpl::flush();

	// Stop heap profiling
#ifdef PROFILE
	HeapProfilerStop();
#endif
}

// Global function for launching Parser logfile writer thread
void* FlushThread(void* arg)
{
	struct FlushThreadArgs & args = *reinterpret_cast<struct FlushThreadArgs*>(arg);
	StapleJniImpl& jniStaple = args.stapleJni;
	int flushPeriod = args.flushPeriod;
	if (traceLevel>=3) std::cout << "FlushThread starting. This will attempt to flush the cache every " << flushPeriod <<" seconds....\n";
	while (true)
	{
		//Flush the Hazelcast buffer
		jniStaple.flush();
		struct timespec s = {flushPeriod, 0};
		nanosleep(&s, 0);
	}
	return NULL;
}



// Global function for launching Parser logfile writer thread
void* ParserThreadLauncher(void* arg)
{
	struct ThreadArgs & args = *reinterpret_cast<struct ThreadArgs*>(arg);
	StapleJniImpl& jniStaple = args.stapleJni;
	Parser& parser = args.parser;//*reinterpret_cast<Parser*>(p_pParser);
	if (traceLevel>=3) std::cout << "ParserThreadLauncher starting. This will create new outfiles every " << PERFMON_ROP <<" seconds....\n";
	while (true)
	{
		// Close & recreate perfmon logfiles
		pthread_mutex_lock(&parser.perfmonFileMutex);
		jniStaple.writeLog(false);
		pthread_mutex_unlock(&parser.perfmonFileMutex);
		// Sleep until the next ROP
		struct timeval actRealTime;
		struct timezone tmpZone;
		gettimeofday(&actRealTime,&tmpZone);
		unsigned long secsToSleep = PERFMON_ROP*(jniStaple.lastPerfmonROP+1) - actRealTime.tv_sec;
		unsigned long usecsPassed = actRealTime.tv_usec;
		struct timespec s = {secsToSleep, 1000 * usecsPassed};
		nanosleep(&s, 0);
	}
	return NULL;
}

// Close old perfmon logfiles, and create new ones (if necessary)
void StapleJniImpl::writeLog(bool p_isFinal)
{
	struct timeval actRealTime;
	struct timezone tmpZone;

	// Prepare new (temporary) perfmon logfiles
	char tcpta_tmp[1000];
	sprintf(tcpta_tmp, "%s/tcpta%s.tmp",perfmonDirName.c_str(),perfmonLogPrefix.c_str());
	char tcpta_partial_tmp[1000];
	sprintf(tcpta_partial_tmp, "%s/tcpta-partial%s.tmp",perfmonDirName.c_str(),perfmonLogPrefix.c_str());
	char flv_tmp[1000];
	sprintf(flv_tmp, "%s/flv%s.tmp",perfmonDirName.c_str(),perfmonLogPrefix.c_str());
	char flv_partial_tmp[1000];
	sprintf(flv_partial_tmp, "%s/flv-partial%s.tmp",perfmonDirName.c_str(),perfmonLogPrefix.c_str());

	// Initialize lastPerfmonROP
	if (lastPerfmonROP==0)
	{
		gettimeofday(&actRealTime,&tmpZone);
		lastPerfmonROP = actRealTime.tv_sec/PERFMON_ROP;
	}
	// Rename the old temporary log files to their final names (not in the first ROP)
	else
	{
		flvfile.close();
		flvpartialfile.close();
		tcptafile.close();
		tcptapartialfile.close();

		//Calculate the previous ROP Time
		time_t previousRopTime = PERFMON_ROP*lastPerfmonROP;
		struct tm * prevRopTime;
		prevRopTime = gmtime ( &previousRopTime );
		char prevTimeStamp[4];
		sprintf(prevTimeStamp, "%02d%02d", prevRopTime->tm_hour, prevRopTime->tm_min);

		//Increment the ROP counter
		lastPerfmonROP++;

		//Calculate the current ROP Time
		time_t epochTime = PERFMON_ROP*lastPerfmonROP;
		struct tm * ropTime;
		ropTime = gmtime ( &epochTime );

		//Create the Time stamp string in the format: A<year><month><day>.<previousRop HourMinute><currentRop HourMinute>
		char fileTimeStamp[20];
		sprintf(fileTimeStamp, "A%04d%02d%02d.%s-%02d%02d", (ropTime->tm_year+1900), (ropTime->tm_mon+1), ropTime->tm_mday, prevTimeStamp, ropTime->tm_hour, ropTime->tm_min);



		// The file names contain timestamp
		char tcpta_name[1000];
		sprintf(tcpta_name, "%s/%s_staple_tcpta_%i%s.log",perfmonDirName.c_str(), fileTimeStamp, epochTime, perfmonLogPrefix.c_str());
		char tcpta_partial_name[1000];
		sprintf(tcpta_partial_name, "%s/%s_staple_tcpta-partial_%i%s.log",perfmonDirName.c_str(), fileTimeStamp, epochTime, perfmonLogPrefix.c_str());
		char flv_name[1000];
		sprintf(flv_name, "%s/%s_staple_flv_%i%s.log",perfmonDirName.c_str(), fileTimeStamp, epochTime, perfmonLogPrefix.c_str());
		char flv_partial_name[1000];
		sprintf(flv_partial_name, "%s/%s_staple_flv-partial_%i%s.log",perfmonDirName.c_str(), fileTimeStamp, epochTime, perfmonLogPrefix.c_str());

		rename(flv_tmp,flv_name);
		rename(flv_partial_tmp,flv_partial_name);
		rename(tcpta_tmp,tcpta_name);
		rename(tcpta_partial_tmp,tcpta_partial_name);
	}

	if (p_isFinal==false)
	{
		// Open the new (temporary) perfmon logfiles
		flvfile.open(flv_tmp);
		if (!flvfile.is_open())
		{
			printf("Error opening log file %s\n",strerror(errno));
			return;
		}
		flvpartialfile.open(flv_partial_tmp);
		if (!flvpartialfile.is_open())
		{
			printf("Error opening log file %s\n",strerror(errno));
			return;
		}
		tcptafile.open(tcpta_tmp);
		if (!tcptafile.is_open())
		{
			printf("Error opening log file %s\n",strerror(errno));
			return;
		}
		tcptapartialfile.open(tcpta_partial_tmp);
		if (!tcptapartialfile.is_open())
		{
			printf("Error opening log file %s\n",strerror(errno));
			return;
		}
	}
}







