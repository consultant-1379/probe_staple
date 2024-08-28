#ifndef PACKETTRAINLIST_H
#define PACKETTRAINLIST_H

#include <list>

#include <staple/Type.h>
#include <staple/Packet.h>

class PacketTrainTCPPacket
{
public:
   unsigned long      seq;               // Sequence number [bytes]
   unsigned long      len;               // Payload length [bytes]
   struct timeval     t;                 // Capture time (first transmission) [s]
   bool               signAMP;           // True if lossInfo is a valid estimate for AMP loss
   bool               signBMP;           // True if lossInfo is a valid estimate for BMP loss
   bool               ampLossCandidate;  // True, if both an original transmission and a retransmission were seen
   bool               reordered;         // True if the packet was reordered (for SACK retransmit validation)
   char               lossInfo;          // Estimation of the type of the loss the first transmission experienced
   char               lossTSInfo;        // Loss verification based on TCP timestamps (can only detect AMP losses, only valid if TS info is present in TCP)

   // lossInfo
   static const char NOT_LOST = 0x00;
   static const char LOST_BMP = 0x01;
   static const char LOST_AMP = 0x02;
   // lossTSInfo
   static const char NOT_LOST_TS = 0x00;
   static const char LOST_AMP_TS = 0x01;

   void Init()
   {
      seq = 0;
      len = 0;
      t.tv_sec = 0;
      t.tv_usec = 0;
      signAMP = false;
      signBMP = false;
      ampLossCandidate = false;
      reordered = false;
      lossInfo = NOT_LOST;
      lossTSInfo = NOT_LOST_TS;
   }
};

// Packet train
// ------------
// Contains information on a continous packet train
class PacketTrain {
public:
   unsigned long     firstSeq;          // Sequence number of the first byte in the packet train
   unsigned long     lastSeq;           // Sequence number of the first byte BEYOND the packet train
   std::list<PacketTrainTCPPacket> packetList;     // List of packets in the packet train

   void Init()
   {
      firstSeq = 0;
      lastSeq = 0;
      packetList.clear();
   }

   // Needed for sorting (by firstSeq)
   bool operator <(const PacketTrain& x) const
   {
      return (firstSeq < x.firstSeq);
   };
   // Needed for finding
   bool operator ==(const PacketTrain& x) const
   {
      return ((firstSeq == x.firstSeq) && (lastSeq == x.lastSeq));
   };

   bool TestPartialOverlap (unsigned long p_firstSeq, unsigned long p_lastSeq);
   std::list<PacketTrainTCPPacket>::iterator TestPacket (unsigned long p_firstSeq, unsigned long p_lastSeq);
   std::list<PacketTrainTCPPacket>::iterator TestPacketSeq (unsigned long p_seq);
   bool InsertPacketToFront (PacketTrainTCPPacket& p_packet);
   bool InsertPacketToBack (PacketTrainTCPPacket& p_packet);
   bool RemoveFirstPacket();
   void Print(std::ostream& outStream) const;
};

// Packet train list
// -----------------
// Contains a list of packet trains
class PacketTrainList {
public:
   unsigned long          firstSeq;
   unsigned long          lastSeq;
   std::list<PacketTrain> packetTrainList;        // List of packet trains

   void Init()
   {
      firstSeq = 0;
      lastSeq = 0;
      packetTrainList.clear();
   }
   
   std::list<PacketTrain>::iterator TestPartialOverlap (unsigned long p_firstSeq, unsigned long p_lastSeq);
   bool InsertPacket (PacketTrainTCPPacket& p_packet);
   bool RemoveFirstPacket();
   void Print(std::ostream& outStream) const;
};

#endif
