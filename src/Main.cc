// Iteratorokat atadni a fuggvenyekben
// XXXReg[] kigyomlalasa, atirasa iteratorosra
// Add SYNFlood protection
// IP byte counterek hasznalatanak atnezese - aktualis csomagot hozza kell-e adni stb...
// TCP TA veg detekcio - PSH bit hasznalatanak csekkelese akkor, ha hibahataron belul van az MSS (el kene kerulni, hogy veletlen ne zarjunk le TA-t, inkabb daraboljuk szet!)
// google-perftools-1.4/src/pprof --lines --gif ./staple staple.0002.heap >test.gif
// TBD: offline perfmon log write based on trace timestamps (not actual wallclock time)

#include <stdlib.h>
#include <errno.h>

#include <staple/Parser.h>
#include <staple/http/Counter.h>
#include <staple/http/log.h>
#include "Main.h"

#ifdef PROFILE
   #include "google-perftools-1.4/src/google/heap-profiler.h"
#endif

int main(int argc, char** argv)
{
   PerfmonStaple perfmonStaple;
   perfmonStaple.main(argc, argv);
   return 0;
}   

struct ThreadArgs
{
   PerfmonStaple& perfmonStaple;
   Parser& parser;
};

void* ParserThreadLauncher(void*);

void PerfmonStaple::main(int argc, char** argv)
{
   // Start heap profiling
   #ifdef PROFILE
      HeapProfilerStart("staple");
   #endif

   if (argc < 2)
   {
      std::cout << "Usage: " << argv[0] << " [switches] input_dumpfile\n";
      std::cout << "Switches:\n";
      std::cout << "   -A    IP:port/mask        IP, port and mask of Net A (port is optional)\n";
      std::cout << "   -B    IP:port/mask        IP, port and mask of Net B (port is optional)\n";
      std::cout << "   -MACA xx:xx:xx:xx:xx:xx   MAC address (or prefix) of the Net A device\n";
      std::cout << "   -MACB yy:yy:yy:yy:yy:yy   MAC address (or prefix) of the Net B device\n";
      std::cout << "   -w    [filename_prefix]   write output pcap dumpfile - with optional name prefix (default: dump)\n";
      std::cout << "   -wt   tmp_filename_prefix temporary output pcap dumpfile name prefix (default: tmp)\n";
      std::cout << "   -t    slottime            slot time for the output pcap dumpfile [sec] (default: 300 sec)\n";
      std::cout << "   -l    logfile             log to \"logfile\" \n";
      std::cout << "                             default is stdout\n";
      std::cout << "   -id                       ignore layer 2 duplicate packets (default: false)\n";
      std::cout << "   -n    loglevel            0 - quiet (no logging)\n";
      std::cout << "                             1 - log overall statistics\n";
      std::cout << "                             2 - log individual statistics\n";
      std::cout << "                             3 - log packets\n";
      std::cout << "                             4 - log packet payload\n";
      std::cout << "                             5 - log debug info\n";
      std::cout << "   -p    perfmon_log_dir     directory where the perfmon logs will be placed\n";
      std::cout << "   -pp   perfmon_log_prefix  the name of perfmon log files will include this prefix string\n";
      std::cout << "   -nohttp                   don't do any HTTP processing\n";
      std::cout << "   input_dumpfile            name of the input pcap packet dump file\n";
      exit(-1);
   }

   // Process input parameters
   char* inputDumpFileName = 0;
   char* logFileName = 0;
   bool noHTTP = false;
   unsigned short i=1;
   while (i<argc)
   {
      // Network address specification with MAC prefixes
      if ((strcmp(argv[i],"-MACA") == 0) || (strcmp(argv[i],"-MACB") == 0))
      {
         unsigned short netId = (strcmp(argv[i],"-MACA")==0) ? 0 : 1;
         i++;

         netMACLen[netId] = sscanf (argv[i],"%x:%x:%x:%x:%x:%x",&netMAC[netId].addr[0],&netMAC[netId].addr[1],&netMAC[netId].addr[2],&netMAC[netId].addr[3],&netMAC[netId].addr[4],&netMAC[netId].addr[5]);
         if ((netMACLen[netId]>6) || (netMACLen[netId]<0)) netMACLen[netId]=0;

         i++;
         continue;
      }

      // Network address specification with IP addresses
      if ((strcmp(argv[i],"-A") == 0) || (strcmp(argv[i],"-B") == 0))
      {
         unsigned short netId = (strcmp(argv[i],"-A")==0) ? 0 : 1;
         i++;

         unsigned short IP[4];
         unsigned short mask, port;

         // Only network is given
         if (sscanf (argv[i],"%hu.%hu.%hu.%hu/%hu",&IP[0],&IP[1],&IP[2],&IP[3],&mask) == 5)
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
         else if (sscanf (argv[i],"%hu.%hu.%hu.%hu:%hu/%hu",&IP[0],&IP[1],&IP[2],&IP[3],&port,&mask) == 6)
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
         else if (sscanf (argv[i],":%hu",&port) == 1)
         {
            netPort[netId][addrFilterNum[netId]] = port;
            netGiven[netId][addrFilterNum[netId]] = false;
            portGiven[netId][addrFilterNum[netId]] = true;
         }
         // Wrong input
         else
         {
            std::cerr << "Wrong Net IP!\n";
            exit(-1);
         }

         addrFilterNum[netId]++;
         i++;
         continue;
      }

      // Logfile
      if (strcmp(argv[i],"-l") == 0)
      {
         i++;
         logFileName = argv[i++];
         continue;
      }

      // Perfmon logfile
      if (strcmp(argv[i],"-p") == 0)
      {
         i++;
         perfmonDirName = argv[i++];
         continue;
      }

      // Perfmon logfile prefix
      if (strcmp(argv[i],"-pp") == 0)
      {
         i++;
         perfmonLogPrefix = argv[i++];
         continue;
      }

      // Output dump file prefix
      if (strcmp(argv[i],"-w") == 0)
      {
         i++;
         if (argv[i][0] != '-')
         {
            outputDumpPrefix = argv[i++];
         }
         outputDumpGiven = true;
         continue;
      }

      // Output dumpfile temporary name prefix
      if (strcmp(argv[i],"-wt") == 0)
      {
         i++;
         outputDumpTmpPrefix = argv[i++];
         continue;
      }

      // Output dumpfile slottime
      if (strcmp(argv[i],"-t") == 0)
      {
         i++;
         outfileSlotTime = atol(argv[i++]);
         continue;
      }

      // Ignore L2 duplicate packets
      if (strcmp(argv[i],"-id") == 0)
      {
         i++;
         ignoreL2Duplicates = true;
         continue;
      }

      // Loglevel
      if (strcmp(argv[i],"-n") == 0)
      {
         i++;
         logLevel = atoi(argv[i++]);
         continue;
      }

      if (strcmp(argv[i],"-nohttp") == 0)
      {
         i++;
         noHTTP = true;
         continue;
      }

      // Not a switch -> it is the input dumpfile
      inputDumpFileName = argv[i++];
   }

   // At least one network IP has to be given OR at least one MAC address
   if ((addrFilterNum[0]==0) && (addrFilterNum[1]==0) && (netMACLen[0]==0) && (netMACLen[1]==0))
   {
      std::cerr << "No network is specified!\n";
      exit(-1);
   }
   // Network IP addresses should not overlap
   if ((addrFilterNum[0]>0) && (addrFilterNum[1]>0) &&
   (netIP[0][0].data & netMask[0][0].data & netMask[1][0].data) == (netIP[1][0].data & netMask[0][0].data & netMask[1][0].data))
   {
      std::cerr << "Overlapping network addresses!\n";
      exit(-1);
   }

   // Create logfile if necessary
   std::ofstream logFile;
   if ((logLevel > 0) && (logFileName != 0))
   {
      // Open file
      logFile.open(logFileName,std::ios::out|std::ios::app);
      if (!logFile.good())
      {
         std::cerr << "Error opening logfile!\n";
         exit(-1);
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
      std::cerr << "Error opening input dumpfile!\n";
      exit(-1);
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

   if (!noHTTP)
   {
      parser.setHTTPPageLog(true);
      parser.setHTTPRequestLog(true);
      getCounterContainer()->setLogging(true);
   }

   // Launch perfmon logfile writer thread
   pthread_t thread;
   struct ThreadArgs t = {*this, parser};
   pthread_create(&thread, NULL, ParserThreadLauncher, (void*) &t);
   
   while (1)
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
   
   // Write and close final perfmon logfiles
   PerfmonLogWrite(true);

   // TBD: close normal logfile

   // TBD: move the above to a SIGINT handler

   // Stop heap profiling
   #ifdef PROFILE
      HeapProfilerStop();
   #endif
}

// Global function for launching Parser logfile writer thread
void* ParserThreadLauncher(void* arg)
{
   struct ThreadArgs & args = *reinterpret_cast<struct ThreadArgs*>(arg);
   PerfmonStaple& perfmonStaple = args.perfmonStaple;
   Parser& parser = args.parser;//*reinterpret_cast<Parser*>(p_pParser);
   while (true)
   {
      // Close & recreate perfmon logfiles
      pthread_mutex_lock(&parser.perfmonFileMutex);
      perfmonStaple.PerfmonLogWrite(false);
      pthread_mutex_unlock(&parser.perfmonFileMutex);
      // Sleep until the next ROP
      struct timeval actRealTime;
      struct timezone tmpZone;
      gettimeofday(&actRealTime,&tmpZone);
      unsigned long secsToSleep = PERFMON_ROP*(perfmonStaple.lastPerfmonROP+1) - actRealTime.tv_sec;
      unsigned long usecsPassed = actRealTime.tv_usec;
      struct timespec s = {secsToSleep, 1000 * usecsPassed};
      nanosleep(&s, 0);
   }
   return NULL;
}

// Close old perfmon logfiles, and create new ones (if necessary)
void PerfmonStaple::PerfmonLogWrite(bool p_isFinal)
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
         exit(-1);
      }
      flvpartialfile.open(flv_partial_tmp);
      if (!flvpartialfile.is_open())
      {
         printf("Error opening log file %s\n",strerror(errno));
         exit(-1);
      }
      tcptafile.open(tcpta_tmp);
      if (!tcptafile.is_open())
      {
         printf("Error opening log file %s\n",strerror(errno));
         exit(-1);
      }
      tcptapartialfile.open(tcpta_partial_tmp);
      if (!tcptapartialfile.is_open())
      {
         printf("Error opening log file %s\n",strerror(errno));
         exit(-1);
      }
   }
}
