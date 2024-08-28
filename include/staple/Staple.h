#ifndef STAPLE_H
#define STAPLE_H

#include <sys/time.h>
#include <map>
#include <ostream>
#include <fstream>
#include <string.h>
#include <memory>
#include <staple/Type.h>
#include <staple/IPSession.h>
#include <staple/TCPConn.h>
#include <staple/PacketDumpFile.h>

// Associative array for the IP, HTTP sessions and TCP connections (TBD: should go into parser class)
#if defined(USE_HASH_MAP)
   typedef std::unordered_map<IPAddressId,IPSession,IPAddressIdTraits,IPAddressIdTraits>    IPSessionReg;
   typedef std::unordered_map<TCPConnId,TCPConn,TCPConnIdTraits,TCPConnIdTraits>            TCPConnReg;
#else
   typedef std::map<IPAddressId,IPSession,IPAddressIdTraits>   IPSessionReg;
   typedef std::map<TCPConnId,TCPConn,TCPConnIdTraits>         TCPConnReg;
#endif

class IPStats
{
public:
   unsigned long packetsRead;
   unsigned long lastPacketsRead;
   unsigned long packetsDuplicated[DUPSTATS_MAX+1];
   unsigned long packetsMatched[2];
   unsigned long bytesRead;
   unsigned long kBytesRead;
   unsigned long lastKBytesRead;
   unsigned long bytesMatched[2];
   unsigned long kBytesMatched[2];
   void Init()
   {
      packetsRead=0;
      lastPacketsRead=0;
      for (int i=0;i<=DUPSTATS_MAX;i++) {packetsDuplicated[i]=0;}
      packetsMatched[0]=0;
      packetsMatched[1]=0;
      bytesRead=0;
      kBytesRead=0;
      lastKBytesRead=0;
      bytesMatched[0]=0;
      bytesMatched[1]=0;
      kBytesMatched[0]=0;
      kBytesMatched[1]=0;
   }
};
class TCPStats
{
public:
   unsigned long packetsRead;
   unsigned long packetsMatched[2];
   unsigned long bytesRead;
   unsigned long kBytesRead;
   unsigned long bytesMatched[2];
   unsigned long kBytesMatched[2];
   unsigned long bytesPL[2];                               // Only for loss reliable TCPs!
   unsigned long kBytesPL[2];                              // Only for loss reliable TCPs!
   unsigned long bytesPLAlreadySeen[2];                    // Only for loss reliable TCPs!
   unsigned long kBytesPLAlreadySeen[2];                   // Only for loss reliable TCPs!
   unsigned long dataPacketsSeen[2];
   unsigned long signPacketsSeenBMP[2];
   unsigned long signPacketsSeenAMP[2];
   unsigned long signPacketsLostBMP[2];
   unsigned long signPacketsLostAMP[2];
   unsigned long signPacketsSeenAMPTS[2];                  // Number of AMP significant packets where the TS loss estimation was reliable
   unsigned long signPacketsLostAMPTSOriginal[2];          // Number of sign. packets lost AMP where the TS loss estimation was reliable (calculated by the original algorithm)
   unsigned long signPacketsLostAMPTSValidation[2];        // Number of sign. packets lost AMP where the TS loss estimation was reliable (calculated by the timestamp-based algorithm)
   unsigned long lossBurstsDetected[2];
   unsigned long rtxPeriods[2];
   unsigned long SYNACKFound[2];
   unsigned long SYNACKNotFound[2];
   unsigned long SYNFound[2];
   unsigned long SYNNotFound[2];

   unsigned long tcpsSeen;
   unsigned long lossReliable;
   unsigned long tsLossReliable;
   unsigned long rtxDataOffset;
   unsigned long captureLoss;
   unsigned long standalone;
   unsigned long SACKPermitted;
   unsigned long TSSeen;
   unsigned long mssLow[2];                                // #TCPs with MSS between 400-600 bytes
   unsigned long mssHigh[2];                               // #TCPs with MSS between 1400-1600 bytes
   unsigned long wndLow[2];                                // #TCPs with receiver window 0-10000 bytes
   unsigned long wndMed[2];                                // #TCPs with receiver window 10000-20000 bytes
   unsigned long wndHigh[2];                               // #TCPs with receiver window 20000-30000 bytes
   unsigned long termFIN;
   unsigned long termRST;
   unsigned long termTO;

   // TCPTA log time stats
   unsigned long allTCPTALogNum;                           // #TCPTA logged
   unsigned long old60TCPTALogNum;                         // #TCPTA ended more than 60s before logging

   void Init()
   {
      packetsRead=0;
      packetsMatched[0]=0;
      packetsMatched[1]=0;
      bytesRead=0;
      kBytesRead=0;
      bytesMatched[0]=0;
      bytesMatched[1]=0;
      kBytesMatched[0]=0;
      kBytesMatched[1]=0;
      bytesPL[0]=0;
      bytesPL[1]=0;
      kBytesPL[0]=0;
      kBytesPL[1]=0;
      bytesPLAlreadySeen[0]=0;
      bytesPLAlreadySeen[1]=0;
      kBytesPLAlreadySeen[0]=0;
      kBytesPLAlreadySeen[1]=0;
      dataPacketsSeen[0]=0;
      dataPacketsSeen[1]=0;
      signPacketsSeenBMP[0]=0;
      signPacketsSeenBMP[1]=0;
      signPacketsSeenAMP[0]=0;
      signPacketsSeenAMP[1]=0;
      signPacketsLostBMP[0]=0;
      signPacketsLostBMP[1]=0;
      signPacketsLostAMP[0]=0;
      signPacketsLostAMP[1]=0;
      signPacketsSeenAMPTS[0]=0;
      signPacketsSeenAMPTS[1]=0;
      signPacketsLostAMPTSOriginal[0]=0;
      signPacketsLostAMPTSOriginal[1]=0;
      signPacketsLostAMPTSValidation[0]=0;
      signPacketsLostAMPTSValidation[1]=0;

      lossBurstsDetected[0]=0;
      lossBurstsDetected[1]=0;
      rtxPeriods[0]=0;
      rtxPeriods[1]=0;
      SYNACKFound[0]=0;
      SYNACKFound[1]=0;
      SYNACKNotFound[0]=0;
      SYNACKNotFound[1]=0;
      SYNFound[0]=0;
      SYNFound[1]=0;
      SYNNotFound[0]=0;
      SYNNotFound[1]=0;

      tcpsSeen=0;
      lossReliable=0;
      tsLossReliable=0;
      rtxDataOffset=0;
      captureLoss=0;
      standalone=0;
      SACKPermitted=0;
      TSSeen=0;
      mssLow[0]=0;
      mssLow[1]=0;
      mssHigh[0]=0;
      mssHigh[1]=0;
      wndLow[0]=0;
      wndLow[1]=0;
      wndMed[0]=0;
      wndMed[1]=0;
      wndHigh[0]=0;
      wndHigh[1]=0;
      termFIN=0;
      termRST=0;
      termTO=0;

      allTCPTALogNum=0;
      old60TCPTALogNum=0;
   }
};
class UDPStats
{
public:
   unsigned long packetsRead;
   unsigned long packetsMatched[2];
   unsigned long bytesRead;
   unsigned long kBytesRead;
   unsigned long bytesMatched[2];
   unsigned long kBytesMatched[2];
   void Init()
   {
      packetsRead=0;
      packetsMatched[0]=0;
      packetsMatched[1]=0;
      bytesRead=0;
      kBytesRead=0;
      bytesMatched[0]=0;
      bytesMatched[1]=0;
      kBytesMatched[0]=0;
      kBytesMatched[1]=0;
   }
};
class ICMPStats
{
public:
   unsigned long packetsRead;
   unsigned long packetsMatched[2];
   unsigned long bytesRead;
   unsigned long kBytesRead;
   unsigned long bytesMatched[2];
   unsigned long kBytesMatched[2];
   void Init()
   {
      packetsRead=0;
      packetsMatched[0]=0;
      packetsMatched[1]=0;
      bytesRead=0;
      kBytesRead=0;
      bytesMatched[0]=0;
      bytesMatched[1]=0;
      kBytesMatched[0]=0;
      kBytesMatched[1]=0;
   }
};
class FLVStats
{
public:
   unsigned long sessionsSeen[2];
   unsigned long packets[2];
   unsigned long bytes[2];
   unsigned long kBytes[2];
   double        duration[2];
   double        qoe[2];
   unsigned long qoeNum[2];

   FLVStats()
   {
      sessionsSeen[0]=0;
      sessionsSeen[1]=0;
      bytes[0]=0;
      bytes[1]=0;
      kBytes[0]=0;
      kBytes[1]=0;
      duration[0]=0;
      duration[1]=0;
      qoe[0]=0;
      qoe[1]=0;
      qoeNum[0]=0;
      qoeNum[1]=0;
   }
};
class MP4Stats
{
public:
   unsigned long sessionsSeen[2];

   void Init()
   {
      sessionsSeen[0]=0;
      sessionsSeen[1]=0;
   }
};

class Parser;
class CounterContainer;

/**
 * Main class holding references to instances doing real work.
 */
class Staple
{
public:
   Staple();
   ~Staple();

   // Input parameters
   unsigned short logLevel;
   MACAddress netMAC[2];
   unsigned short netMACLen[2];
   DoubleWord netIP[2][100];
   unsigned short netPort[2][100];
   DoubleWord netMask[2][100];
   bool netGiven[2][100];
   bool portGiven[2][100];
   unsigned short addrFilterNum[2];
   bool outputDumpGiven;
   std::string outputDumpPrefix;
   std::string outputDumpTmpPrefix;
   unsigned long outfileSlotTime;
   bool ignoreL2Duplicates;
   std::string perfmonDirName;
   std::string perfmonLogPrefix;

   // Overall statistics
   unsigned long  packetsRead;                       // Packets read from the file
   unsigned long  packetsDuplicated[DUPSTATS_MAX+1]; // Number of packets wrt. duplicates ([0]: # of original transmissions, [1]: # 1st duplicates, ..., [DUPSTATS_MAX]: # of DUPSTATS_MAX+ duplicates)
   struct timeval traceStartTime;                    // First timestamp of the trace [s]
   struct timeval actTime;                           // Actual timestamp [s]
   struct timeval actRelTime;                        // Actual timestamp (relative to trace start) [s]
   unsigned short tsMinorReorderingNum;              // The number of minor timestamp reorderings detected
   unsigned short tsMajorReorderingNum;              // The number of major timestamp reorderings detected
   unsigned short tsJumpNum;                         // The number of timestamp jumps
   double         tsJumpLen;                         // The overall duration of timestamp jumps [s]

   IPStats ipStats;
   TCPStats tcpStats;
   UDPStats udpStats;
   ICMPStats icmpStats;
   FLVStats flvStats;
   MP4Stats mp4Stats;

   // Internal variables
   IPSessionReg   ipSessionReg;
   TCPConnReg     tcpConnReg;

   // Program start time
   struct timeval startRealTime;
   struct timeval lastRealTime;
   
   unsigned short byteOrderPlatform;
   std::ostream logStream;

   PacketDumpFile packetDumpFile;
   std::auto_ptr<Parser> parser;
   
   static void config(std::string const& key, std::string const& value, void*) throw (std::string);

   CounterContainer* getCounterContainer();

private:
   CounterContainer* counterContainer_;
};

#endif
