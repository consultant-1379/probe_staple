#ifndef PARSER_H
#define PARSER_H

#include <sys/time.h>
#include <pthread.h>             // pthread_create
#include <ostream>
#include <staple/Packet.h>
#include <staple/Staple.h>
#include <staple/http/HTTPEngine.h>

void* ParserThreadLauncher(void*);

// Parser class
class Parser {

public:

   IPSessionReg::iterator     ipIndex;                         // Cached index for fast IP session lookup
   TCPConnReg::iterator       tcpIndex;                        // Cached index for fast TCP connection lookup

   struct timeval    lastIPPacketTime;
   struct timeval    lastTCPTimeoutCheck;
   struct timeval    lastIPTimeoutCheck;
   
   struct timeval    lastStatusLogTime;                        // The time of the last status log

   std::ostream*     perfmonTCPTAFile;                         // Perfmon TCPTA log file
   std::ostream*     perfmonTCPTAPartialFile;                  // Perfmon partial TCPTA log file
   std::ostream*     perfmonFLVFile;                           // Perfmon FLV log file
   std::ostream*     perfmonFLVPartialFile;                    // Perfmon partial FLV log file

   bool hazelcastPublish;
   bool writeToFile;



   pthread_mutex_t   perfmonFileMutex;                         // MUTEX used for writing/modifying perfmon logfiles
   
   Parser(Staple&);
   void Init();
   void ParsePacket(L2Packet*);
   void HighestSeqTCPDataPacket(TCPPacket&, TCPConnReg::iterator&, IPSession&);
   void NewTCPPayload(TCPPacket&, TCPConnId&);
   void AssembleTCPPayload(TCPConnReg::iterator&, TCPPacket&);
   void TCPPayloadACKed(TCPConnReg::iterator&, TCPPacket&);
   bool ReleaseTCPConnection(TCPConnReg::iterator&);
   void FinishFLV(TCPConnReg::iterator&, unsigned short);
   bool FinishTCPTransaction(TCPConnReg::iterator&,IPSession&,unsigned short);
   bool EndOfWindowLoss(TCPConn&,unsigned short,unsigned long,unsigned long);
   bool SACKAMPLossCheck(TCPConn&,unsigned short,unsigned long,unsigned long);
   bool AMPLossRange(TCPConn&,unsigned short,unsigned long,unsigned long,bool skipReordered);
   void RemovePacketsFromSignificantSet(TCPConn&,unsigned short,unsigned long,bool,bool);
   bool FinishRetransmissionState(TCPConn&,unsigned short);
   bool ReleaseIPSession(IPSessionReg::iterator&);
   void ApplyHistorySizeLimits(TCPConnReg::iterator&, unsigned short);
   bool RemovePacketFromHistory(TCPConnReg::iterator&, unsigned short);
   void FinishConnections();
   bool PrintTCPStatistics (TCPConnReg::iterator&, std::ostream&);
   bool PrintTCPTAStatistics (TCPConnReg::iterator&, TCPTransaction&, unsigned short, bool, bool);
   void PrintOverallStatistics (std::ostream&);

   Staple&           staple;

   void setHTTPPageLogStream(std::ostream*);
   void setHTTPRequestLogStream(std::ostream*);
   void setHTTPPageLog(bool);
   void setHTTPRequestLog(bool);

private:
   HTTPEngine httpEngine;
};

#endif
