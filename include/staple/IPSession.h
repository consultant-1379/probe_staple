#ifndef IPSESSION_H
#define IPSESSION_H

#include <staple/Type.h>
#include <staple/TCPConn.h>

class Staple;

// Data stored for each user session
class IPSession {
public:
   // 0 - direction Net A -> Net B
   // 1 - direction Net B -> Net A

   // Statistics
   unsigned long  packetsSeen[2];             // The number of packets seen
   unsigned long  bytesSeen[2];               // The amount of data seen [bytes]
   struct timeval firstPacketTime[2];         // The time of the first packet [s]
   struct timeval lastPacketTime[2];          // The time of the last packet [s]
   struct timeval lastButOnePacketTime[2];    // The time of the last but one packet [s]

   // Status variables
   unsigned short lastPacketLength[2];        // The total length of the last packet [bytes]
   unsigned short lastButOnePacketLength[2];  // The total length of the last but one packet [bytes]
   unsigned short lastIPIdSeen[2];            // The IP Id of the last DATA packet seen
   unsigned long  lastSlotData[2];            // The aggregate amount of IP session data seen in the last slot [bytes]
   unsigned long  actSlotStartTime;           // The start time of the actual slot [s]
   unsigned long  actSlotData[2];             // The aggregate amount of IP session data seen in the actual slot [bytes]

   // Channel rate calculation status
   unsigned short nTCPsInRTTCalcState[2];     // Number of TCPs in RTT calculation state
   unsigned long  CRPipeSize[2];              // Pipe size [bytes]
   unsigned long  CRLastPipeCounter[2];       // The IP session counter when the last pipe size was calculated [bytes]
   unsigned long  CRFirstByteCandidate[2];    // The IP session counter candidate for being the first byte of channel rate calc [bytes]
   unsigned long  CRFirstByte[2];             // The IP data session counter when the first channel rate calculation packet was sent [bytes]
   struct timeval CRFirstACKTime[2];          // The time when the first packet was ACKed in the actual channel rate calculation state [s]
   unsigned long  CRLastByte[2];              // The IP data session counter when the last channel rate calculation packet was sent [bytes]
   struct timeval CRLastACKTime[2];           // The time when the last packet was ACKed in the actual channel rate calculation state [s]
   // Overall channel rate
   unsigned long  CRAllBytes[2];              // The overall amount of IP session data ACKed at channel rate calculations [bytes]
   double         CRAllDuration[2];           // The overall duration of channel rate calculations [s]

#if defined(USE_HASH_MAP)
   typedef std::unordered_map<TCPConnId,unsigned char,TCPConnIdTraits,TCPConnIdTraits> TCPReg;
#else
   typedef std::map<TCPConnId,unsigned char,TCPConnIdTraits> TCPReg;
#endif
   TCPReg tcpReg;                             // List of the TCP connections of the user
   Staple* pStaple;                           // Pointer to staple (not a reference because hash tables need a default constructor)

   IPSession() : pStaple(NULL) {}
   void Init(Staple&);
   bool AddTCPConnection(TCPConnId& tcpConnId);
   bool RemoveTCPConnection(const TCPConnId& tcpConnId);
   void IncreaseTCPsInRTTCalcState(unsigned short direction);
   void DecreaseTCPsInRTTCalcState(unsigned short direction);
   void FinishChannelRateCalc(unsigned short direction, bool reset);

};

#endif
