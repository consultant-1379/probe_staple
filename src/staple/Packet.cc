#include <iostream>
#include <iomanip>
#include <stdio.h>

#include <staple/Type.h>
#include <staple/Packet.h>
#include <staple/Staple.h>

L3Packet::~L3Packet()
{
   if (payload != NULL) delete [] payload;
   // Make sure that L2Packet::~L2Packet doesn't try to delete us
   if (pL2Packet)
   {
      pL2Packet->pL3Packet = NULL;
      delete pL2Packet;
   }
};

void L3Packet :: Print(std::ostream& outStream) const
{
   char tmpBuff[80];
   std::string tmpString;

   // Packet type
   outStream << " type";
   if ((l3Type&IP) != 0) outStream << " IP";
   if ((l3Type&UDP) != 0) outStream << " UDP";
   if ((l3Type&TCP) != 0) outStream << " TCP";
   if ((l3Type&ICMP) != 0) outStream << " ICMP";
   if (l3Type == UNKNOWN) outStream << " UNKNOWN";

   outStream << "\n";

   // Payload
   if ((staple.logLevel >= 4) && (payloadSavedLen>0)) outStream << "Payload:\n" << "TBD" << "\n";
}

std::ostream& operator<<(std::ostream& o, const L3Packet& p)
{
   p.Print(o);
   return o;
}

L2Packet::~L2Packet()
{
   // Make sure L3Packet::~L3Packet doesn't try to delete us
   if (pL3Packet)
   {
      pL3Packet->pL2Packet = NULL;
      delete pL3Packet;
   }
};

L2Packet* L2Packet::clone() const
{
   return new L2Packet(*this);
}

EthernetPacket* EthernetPacket::clone() const
{
   return new EthernetPacket(*this);
}

void IPPacket :: Print(std::ostream& outStream) const
{
   char tmpBuff[80];
   std::string tmpString;

   DoubleWord netAIP = (direction == 0) ? srcIP : dstIP;
   DoubleWord netBIP = (direction == 0) ? dstIP : srcIP;

   // NetA IP
   sprintf((char*)&tmpBuff,"%hu.%hu.%hu.%hu",(unsigned)netAIP.byte[3],(unsigned)netAIP.byte[2],(unsigned)netAIP.byte[1],(unsigned)netAIP.byte[0]);
   tmpString = (const char *)&tmpBuff;
   tmpString.append(15-tmpString.size(),' ');
   outStream << tmpString;

   // Direction
   outStream << ((direction == 0) ? " -> " : " <- ");

   // NetB IP
   sprintf((char*)&tmpBuff,"%hu.%hu.%hu.%hu",(unsigned)netBIP.byte[3],(unsigned)netBIP.byte[2],(unsigned)netBIP.byte[1],(unsigned)netBIP.byte[0]);
   tmpString = (const char *)&tmpBuff;
   tmpString.append(15-tmpString.size(),' ');
   outStream << tmpString;

   outStream << " IPPktLen " << IPPktLen << " IPId " << IPId;
   outStream << "\n";

   // Payload
   if ((staple.logLevel >= 4) && (payloadSavedLen>0)) outStream << "Payload:\n" << "TBD" << "\n";
}

void TCPPacket :: Print(std::ostream& outStream) const
{
   char tmpBuff[80];
   std::string tmpString;
   outStream << staple.actTime.tv_sec << ".";
   outStream.fill('0');
   outStream.width(3);  
   outStream << (staple.actTime.tv_usec/1000) << " ";
   
   DoubleWord netAIP = (direction == 0) ? srcIP : dstIP;
   DoubleWord netBIP = (direction == 0) ? dstIP : srcIP;
   unsigned short netAPort = (direction == 0) ? srcPort : dstPort;
   unsigned short netBPort = (direction == 0) ? dstPort : srcPort;

   // NetA IP
   sprintf((char*)&tmpBuff,"%hu.%hu.%hu.%hu",(unsigned)netAIP.byte[3],(unsigned)netAIP.byte[2],(unsigned)netAIP.byte[1],(unsigned)netAIP.byte[0]);
   tmpString = (const char *)&tmpBuff;
   tmpString.append(15-tmpString.size(),' ');
   outStream << tmpString << ":";

   // NetA port
   sprintf((char*)&tmpBuff,"%hu",netAPort);
   tmpString = (const char *)&tmpBuff;
   outStream << tmpString.append(5-tmpString.size(),' ');

   // Direction
   outStream << ((direction == 0) ? " -> " : " <- ");

   // NetB IP
   sprintf((char*)&tmpBuff,"%hu.%hu.%hu.%hu",(unsigned)netBIP.byte[3],(unsigned)netBIP.byte[2],(unsigned)netBIP.byte[1],(unsigned)netBIP.byte[0]);
   tmpString = (const char *)&tmpBuff;
   tmpString.append(15-tmpString.size(),' ');
   outStream << tmpString << ":";

   // NetB Port
   sprintf((char*)&tmpBuff,"%hu",netBPort);
   tmpString = (const char *)&tmpBuff;
   outStream << tmpString.append(5-tmpString.size(),' ') << " ";

   // Flags
   outStream << ((TCPFlags&FIN) ? "F" : "-");
   outStream << ((TCPFlags&SYN) ? "S" : "-");
   outStream << ((TCPFlags&RST) ? "R" : "-");
   outStream << ((TCPFlags&PSH) ? "P" : "-");
   outStream << ((TCPFlags&ACK) ? "A" : "-");
   outStream << ((TCPFlags&URG) ? "U" : "-");

   outStream << " seq " << seq << " ack " << ack << " len " << TCPPLLen << " rwnd " << rwnd;

   // Options
   if (options != NONE)
   {
      outStream << " options";
      if (options&SACKPERM) outStream << " SACKPERM";
      if (options&SACK) outStream << " SACK";
      if (options&TIMESTAMP) outStream << " TIMESTAMP";
      if (options&MSS) outStream << " MSS";
      if (options&WNDSCALE) outStream << " WNDSCALE";
   }

   outStream << "\n";

   // Payload
   if ((staple.logLevel >= 4) && (payloadSavedLen>0)) outStream << "Payload:\n" << "TBD" << "\n";
}

void UDPPacket :: Print(std::ostream& outStream) const
{
   char tmpBuff[80];
   std::string tmpString;

   DoubleWord netAIP = (direction == 0) ? srcIP : dstIP;
   DoubleWord netBIP = (direction == 0) ? dstIP : srcIP;
   unsigned short netAPort = (direction == 0) ? srcPort : dstPort;
   unsigned short netBPort = (direction == 0) ? dstPort : srcPort;

   // NetA IP
   sprintf((char*)&tmpBuff,"%hu.%hu.%hu.%hu",(unsigned)netAIP.byte[3],(unsigned)netAIP.byte[2],(unsigned)netAIP.byte[1],(unsigned)netAIP.byte[0]);
   tmpString = (const char *)&tmpBuff;
   tmpString.append(15-tmpString.size(),' ');
   outStream << tmpString << ":";

   // NetA port
   sprintf((char*)&tmpBuff,"%hu",netAPort);
   tmpString = (const char *)&tmpBuff;
   outStream << tmpString.append(5-tmpString.size(),' ');

   // Direction
   outStream << ((direction == 0) ? " -> " : " <- ");

   // NetB IP
   sprintf((char*)&tmpBuff,"%hu.%hu.%hu.%hu",(unsigned)netBIP.byte[3],(unsigned)netBIP.byte[2],(unsigned)netBIP.byte[1],(unsigned)netBIP.byte[0]);
   tmpString = (const char *)&tmpBuff;
   tmpString.append(15-tmpString.size(),' ');
   outStream << tmpString << ":";

   // NetB Port
   sprintf((char*)&tmpBuff,"%hu",netBPort);
   tmpString = (const char *)&tmpBuff;
   outStream << tmpString.append(5-tmpString.size(),' ') << " ";

   outStream << "len " << UDPPLLen << "\n";

   // Payload
   if ((staple.logLevel >= 4) && (payloadSavedLen>0)) outStream << "Payload:\n" << "TBD" << "\n";
}

void ICMPPacket :: Print(std::ostream& outStream) const
{
   char tmpBuff[80];
   std::string tmpString;

// Time???

   DoubleWord netAIP = (direction == 0) ? srcIP : dstIP;
   DoubleWord netBIP = (direction == 0) ? dstIP : srcIP;

   // NetA IP
   sprintf((char*)&tmpBuff,"%hu.%hu.%hu.%hu",(unsigned)netAIP.byte[3],(unsigned)netAIP.byte[2],(unsigned)netAIP.byte[1],(unsigned)netAIP.byte[0]);
   tmpString = (const char *)&tmpBuff;
   tmpString.append(15-tmpString.size(),' ');
   outStream << tmpString;

   // Direction
   outStream << ((direction == 0) ? " -> " : " <- ");

   // NetB IP
   sprintf((char*)&tmpBuff,"%hu.%hu.%hu.%hu",(unsigned)netBIP.byte[3],(unsigned)netBIP.byte[2],(unsigned)netBIP.byte[1],(unsigned)netBIP.byte[0]);
   tmpString = (const char *)&tmpBuff;
   tmpString.append(15-tmpString.size(),' ');
   outStream << tmpString;

   outStream << " ICMP";
   switch (typeCode)
   {
      case NET_UNREACH: outStream << " NETWORK UNREACHABLE"; break;
      case HOST_UNREACH: outStream << " HOST UNREACHABLE"; break;
      case PROTO_UNREACH: outStream << " PROTOCOL UNREACHABLE"; break;
      case PORT_UNREACH: outStream << " PORT UNREACHABLE"; break;
      case FRAG_NEEDED: outStream << " FRAGMENTATION NEEDED"; break;
      case SRCROUTE_FAIL: outStream << " SOURCE ROUTE FAILURE"; break;
      case TTL_EXCEEDED: outStream << " TTL EXCEEDED"; break;
      case FRAG_TIME_EXCEEDED: outStream << " FRAGMENT REASSEMBLY TIME EXCEEDED"; break;
      case ECHO: outStream << " ECHO"; break;
      case ECHO_REPLY: outStream << " ECHO REPLY"; break;
   }

   outStream << " IPPktLen " << IPPktLen << " IPId " << IPId;
   outStream << "\n";
}
