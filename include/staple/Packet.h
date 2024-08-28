#ifndef PACKET_H
#define PACKET_H

#include <sys/time.h>
#include <iostream>
#include <list>

#include <staple/Type.h>

class Staple;

struct StapleStub
{
   StapleStub(Staple& s) : staple(s) {}
   Staple& staple;
};

class L2Packet;

// Base class for layer 3 packets
// ------------------------------
class L3Packet : public StapleStub {

public:
   // Layer 3 (and above) packet types
   static const char UNKNOWN = 0x00;
   static const char IP = 0x01;
   static const char UDP = 0x02;
   static const char TCP = 0x04;
   static const char ICMP = 0x08;
   char              l3Type;

   Byte*             payload;                   /* (L4!) payload data */
   unsigned short    payloadSavedLen;
   L2Packet*         pL2Packet;

   virtual ~L3Packet();
   L3Packet(Staple & s)
    : StapleStub(s)
   {
      payload = NULL;
      payloadSavedLen = 0;
      pL2Packet = NULL;
   };
   L3Packet(const L3Packet& p) : StapleStub(p.staple)
   {
      l3Type = p.l3Type;
      payloadSavedLen = p.payloadSavedLen;
      payload = new Byte[payloadSavedLen];
      memcpy(payload, p.payload, payloadSavedLen);
      pL2Packet = NULL;
   }
   virtual void Init()
   {
      l3Type = UNKNOWN;
   };
   virtual void Print(std::ostream&) const;
};

std::ostream& operator<<(std::ostream& o, const L3Packet& p);

// Base class for layer 2 packets (includes L3 packet as a contained object)
// -------------------------------------------------------------------------
class L2Packet : public StapleStub {

public:
   // Layer 2 packet types
   typedef enum
   {
      UNKNOWN,
      ETHERNET,
   } L2Type;

   struct timeval     time;
   unsigned long      l2SavedLen;
   L2Type             l2Type;
   L3Packet*          pL3Packet;

   virtual ~L2Packet();
   L2Packet(Staple& s)
    : StapleStub(s)
   {
      pL3Packet = NULL;
   };
   L2Packet(const L2Packet& p) : StapleStub(p.staple)
   {
      time = p.time;
      l2SavedLen = p.l2SavedLen;
      l2Type = p.l2Type;
      pL3Packet = NULL;
   }

   virtual void Init()
   {
      l2Type = UNKNOWN;
   };
   virtual void Print(std::ostream&) const {};
   virtual L2Packet* clone() const;
};

// Ethernet packet
// ---------------
class EthernetPacket : public L2Packet {

public:

   short             VLANId;
   MACAddress        srcMAC;
   MACAddress        dstMAC;

   virtual ~EthernetPacket() {};
   EthernetPacket(Staple & s) : L2Packet(s) {}
   virtual void Init()
   {
      l2Type = ETHERNET;
   };
   virtual void Print(std::ostream&) const {};
   virtual EthernetPacket* clone() const;
};

// IP packet
// ---------
class IPPacket : public L3Packet {

public:
   // IP flags
   static const char MF = 0x01;
   static const char DF = 0x02;

   DoubleWord        srcIP;
   DoubleWord        dstIP;
   bool              match;             /* True if packet IP matches the filters */
   Byte              direction;         /* 0: NetA->NetB - 1: NetB->NetA */
   unsigned short    IPPktLen;
   unsigned short    IPId;
   unsigned char     IPFlags;
   unsigned short    fragOffset;

   virtual ~IPPacket() {};
   IPPacket(Staple & s) : L3Packet(s)
   {
   };
   virtual void Init()
   {
      l3Type = IP;
   };
   virtual void Print(std::ostream&) const;
};

// TCP packet
// ----------
class TCPPacket : public IPPacket {

public:
   // TCP flags
   static const char FIN = 0x01;
   static const char SYN = 0x02;
   static const char RST = 0x04;
   static const char PSH = 0x08;
   static const char ACK = 0x10;
   static const char URG = 0x20;

   // TCP option types
   static const char NONE = 0x00;
   static const char SACKPERM = 0x01;   // SACK-permitted option (RFC 2018)
   static const char SACK = 0x02;       // SACK option (RFC 2018)
   static const char TIMESTAMP = 0x04;  // Timestamp option (RFC 1323)
   static const char MSS = 0x08;        // MSS option (RFC 793)
   static const char WNDSCALE = 0x10;   // Window scaling option (RFC 1323)

   unsigned short    srcPort;
   unsigned short    dstPort;
   char              TCPFlags;
   unsigned long     seq;
   unsigned long     ack;
   unsigned short    rwnd;
   unsigned short    options;           // The type of options present
   unsigned short    TCPPLLen;
   
   // SACK specific fields
   unsigned long     sackLeftEdge[4];
   unsigned long     sackRightEdge[4];
   unsigned char     sackBlockNum;      // Number of SACK blocks seen

   // Timestamp specific fields
   unsigned long     tsValue;
   unsigned long     tsEcho;

   // Window scale specific fields
   unsigned char     wndScaleVal;       // The number of bits to shift the advertised window value

   virtual ~TCPPacket() {};
   TCPPacket(Staple& s) : IPPacket(s)
   {
   };
   virtual void Init()
   {
      l3Type = IP|TCP;
   };
   virtual void Print(std::ostream&) const;
};

// UDP packet
// ----------
class UDPPacket : public IPPacket {

public:
   unsigned short    srcPort;
   unsigned short    dstPort;
   unsigned short    UDPPLLen;

   virtual ~UDPPacket() {};
   UDPPacket(Staple & s) : IPPacket(s)
   {
   };
   virtual void Init()
   {
      l3Type = IP|UDP;
   };
   virtual void Print(std::ostream&) const;
};

// ICMP packet
// -----------
class ICMPPacket : public IPPacket {

public:
   // ICMP type codes (more to be added)
   static const unsigned short NET_UNREACH = 0x0300;
   static const unsigned short HOST_UNREACH = 0x0301;
   static const unsigned short PROTO_UNREACH = 0x0302;
   static const unsigned short PORT_UNREACH = 0x0303;
   static const unsigned short FRAG_NEEDED = 0x0304;
   static const unsigned short SRCROUTE_FAIL = 0x0305;
   static const unsigned short TTL_EXCEEDED = 0x0B00;
   static const unsigned short FRAG_TIME_EXCEEDED = 0x0B01;
   static const unsigned short ECHO = 0x0800;
   static const unsigned short ECHO_REPLY = 0x0000;

   unsigned short typeCode;

   virtual ~ICMPPacket() {};
   ICMPPacket(Staple& s) : IPPacket(s)
   {
   };
   virtual void Init()
   {
      l3Type = IP|ICMP;
   };
   virtual void Print(std::ostream&) const;
};

#endif
