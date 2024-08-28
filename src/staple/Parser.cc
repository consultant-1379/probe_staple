// URL-ben levo karaktereknek 32 es 126 kozott kell lennie (ASCII)
// Update TCP SEQ sanity check & add wrap-around handling
// plPos utolso valid ertekenek hasznalata rate/byte countnal FLV-ben (inicializalatlan payload teruletrol gabalyodhat bele, ahol a frame tag veletlenul epp valid)
// TCP TA loss reliability vegig false ha a TCP soran egyszer a multban barmi gebasz volt (tul konzervativ)
// History size-t dinamikusra kene venni, mert nagy ablakmereteknel veszhet csomag es a loss-t invalidalja
// Payload signature search-ot csak web portokra kene csinalni (mert csak FLV-t ismerunk fel most)

#include <cmath>
#include <unistd.h>              // usleep
#include <cstdlib>               // abs(int64_t)
#include "utf8.h"
#include <sstream>


#include <staple/Parser.h>
#include <staple/Staple.h>
#include <staple/Type.h>
#include <jni/StapleJniImpl.h>
#include <staple/PacketTrainList.h>
#include <staple/http/HTTPEngine.h>

#include "Util.h"

Parser::Parser(Staple& s) : staple(s), httpEngine(s) {}

void Parser::Init()
{
   ipIndex = staple.ipSessionReg.end();
   tcpIndex = staple.tcpConnReg.end();

   lastIPPacketTime.tv_sec = 0;
   lastIPPacketTime.tv_usec = 0;
   lastTCPTimeoutCheck.tv_sec = 0;
   lastTCPTimeoutCheck.tv_usec = 0;
   lastIPTimeoutCheck.tv_sec = 0;
   lastIPTimeoutCheck.tv_usec = 0;

   lastStatusLogTime.tv_sec = 0;
   lastStatusLogTime.tv_usec = 0;

   perfmonTCPTAFile = NULL;
   perfmonTCPTAPartialFile = NULL;
   perfmonFLVFile = NULL;
   perfmonFLVPartialFile = NULL;

   hazelcastPublish = false;
   writeToFile = true;

   // Initialize perfmon file mutex
   pthread_mutex_init(&perfmonFileMutex, NULL);
}

void Parser::ParsePacket(L2Packet* pL2Packet)
{
   IPStats& ipStats = staple.ipStats;
   TCPStats& tcpStats = staple.tcpStats;
   UDPStats& udpStats = staple.udpStats;
   ICMPStats& icmpStats = staple.icmpStats;
   FLVStats& flvStats = staple.flvStats;
   MP4Stats& mp4Stats = staple.mp4Stats;
   
   const unsigned short& logLevel = staple.logLevel;
   
   staple.packetsRead++;

   // Initialize trace times
   if (staple.packetsRead == 1)
   {
      staple.traceStartTime = pL2Packet->time;
      staple.actTime = pL2Packet->time;
      staple.actRelTime.tv_sec = 0;
      staple.actRelTime.tv_usec = 0;
      lastTCPTimeoutCheck = pL2Packet->time;
      lastIPTimeoutCheck = pL2Packet->time;
   }
   // Check timestamp order
   // (TCP_TIMEOUT <= IP_TIMEOUT !!!)
   #define TCP_TIMEOUT 30
   #define IP_TIMEOUT 30
   if ((pL2Packet->time.tv_sec < staple.actTime.tv_sec) || ((pL2Packet->time.tv_sec == staple.actTime.tv_sec) && (pL2Packet->time.tv_usec < staple.actTime.tv_usec)))
   {
      struct timeval reorderDiff = AbsTimeDiff(pL2Packet->time, staple.actTime);
      double rDiff = reorderDiff.tv_sec + (double)reorderDiff.tv_usec/1000000;
      if (logLevel >= 5)
      {
         staple.logStream << ((rDiff<TS_MAJOR_REORDERING_THRESH) ? "Minor" : "Major") << " dump file timestamp reordering detected at packet:\n";
         pL2Packet->Print(staple.logStream);
      }
      if (rDiff>=TS_MAJOR_REORDERING_THRESH)
      {
         // Major reordering -> terminate all HTTP sessions, TCP connections and IP sessions
         httpEngine.finishAllTCPSessions();
         lastTCPTimeoutCheck = pL2Packet->time;
         lastTCPTimeoutCheck.tv_sec -= (TCP_TIMEOUT+1);
         lastIPTimeoutCheck = pL2Packet->time;
         lastIPTimeoutCheck.tv_sec -= (IP_TIMEOUT+1);
      }
      else
      {
         // Minor reordering -> treat timestamp as actTime
         pL2Packet->time = staple.actTime;
      }
      // Update statistics
      (rDiff<TS_MAJOR_REORDERING_THRESH) ? staple.tsMinorReorderingNum++ : staple.tsMajorReorderingNum++;
   }
   // If no reordering -> check for timestamp jumps
   else
   {
      struct timeval jumpTimeDiff = AbsTimeDiff(staple.actTime, pL2Packet->time);
      double jumpTDiff = jumpTimeDiff.tv_sec + (double)jumpTimeDiff.tv_usec/1000000;
      if (jumpTDiff >= TS_JUMP_THRESH)
      {
         if (logLevel >= 5)
         {
            staple.logStream << "Dump file time jump detected at " << staple.actTime.tv_sec << " s (length " << jumpTimeDiff.tv_sec << " s).\n";
         }
         staple.tsJumpNum++;
         staple.tsJumpLen += jumpTDiff;
      }
   }

   // Update actual times
   staple.actTime = pL2Packet->time;
   staple.actRelTime = AbsTimeDiff(staple.traceStartTime, staple.actTime);

   // Write status log
   if ((staple.actTime.tv_sec - lastStatusLogTime.tv_sec >= STATUS_LOG_PERIOD) || (lastStatusLogTime.tv_sec == 0))
   {
      // Write traffic info
      unsigned long ipPktNum = ipStats.packetsMatched[0]+ipStats.packetsMatched[1];
      unsigned long ipKBytes = ipStats.kBytesMatched[0]+ipStats.kBytesMatched[1];
      // Processing speed
      struct timeval actRealTime;
      struct timezone tmpZone;
      gettimeofday(&actRealTime,&tmpZone);
      struct timeval timeDiff = AbsTimeDiff(actRealTime, staple.lastRealTime);
      double tDiff = timeDiff.tv_sec + (double)timeDiff.tv_usec/1000000;
      // Store original format flags
      std::ios_base::fmtflags origFormat = staple.logStream.flags();
      int origPrec = staple.logStream.precision();
      staple.logStream.precision(2);
      staple.logStream.setf(std::ios::fixed);
      staple.logStream << staple.actTime.tv_sec << " "
                       << (((double)(staple.actTime.tv_sec - staple.traceStartTime.tv_sec))/3600) << "h"
                       << " pkt " << ipPktNum
                       << " vol " << ((double)ipKBytes/1048576) << "GB"
                       << " SA-lossDL " << (100*((double)(tcpStats.SYNACKNotFound[0]))/(tcpStats.SYNACKFound[0]+tcpStats.SYNACKNotFound[0])) << "%"
                       << " SA-lossUL " << (100*((double)(tcpStats.SYNACKNotFound[1]))/(tcpStats.SYNACKFound[1]+tcpStats.SYNACKNotFound[1])) << "%"
                       << " S-lossDL " << (100*((double)(tcpStats.SYNNotFound[1]))/(tcpStats.SYNFound[1]+tcpStats.SYNNotFound[1])) << "%"
                       << " S-lossUL " << (100*((double)(tcpStats.SYNNotFound[0]))/(tcpStats.SYNFound[0]+tcpStats.SYNNotFound[0])) << "%"
                       << " TCP " << (100*(double)(tcpStats.kBytesMatched[0]+tcpStats.kBytesMatched[1])/ipKBytes) << "%"
                       << " UDP " << (100*(double)(udpStats.kBytesMatched[0]+udpStats.kBytesMatched[1])/ipKBytes) << "%"
                       << " FLV " << (100*(double)(flvStats.kBytes[0]+flvStats.kBytes[1])/ipKBytes) << "%"
                       << " HTTP " << (100*(double)(httpEngine.getStats().IPBytes[0]+httpEngine.getStats().IPBytes[1])/1024/ipKBytes) << "%"
                       << " [" << (ipStats.packetsRead-ipStats.lastPacketsRead)/tDiff << " pkt/s "
                       << (ipStats.kBytesRead-ipStats.lastKBytesRead)/tDiff << " KB/s]"
                       << " TCPlr " << (100*(double)(tcpStats.lossReliable)/tcpStats.tcpsSeen) << "%"
                       << " TCPdo " << (100*(double)(tcpStats.rtxDataOffset)/tcpStats.tcpsSeen) << "%"
                       << " TCPcl " << (100*(double)(tcpStats.captureLoss)/tcpStats.tcpsSeen) << "%"
                       << " TANum " << tcpStats.allTCPTALogNum << " 60s " << tcpStats.old60TCPTALogNum;

      tcpStats.SYNNotFound[0]=0;
      tcpStats.SYNNotFound[1]=0;
      tcpStats.SYNFound[0]=0;
      tcpStats.SYNFound[1]=0;
      tcpStats.SYNACKNotFound[0]=0;
      tcpStats.SYNACKNotFound[1]=0;
      tcpStats.SYNACKFound[0]=0;
      tcpStats.SYNACKFound[1]=0;
      // Write internal state
      TCPConnReg::iterator index = staple.tcpConnReg.begin();
      unsigned long tcpConnNum = staple.tcpConnReg.size();
      unsigned long tcpTANum[2];
      unsigned long flvNum[2];
      tcpTANum[0] = 0;
      tcpTANum[1] = 0;
      flvNum[0] = 0;
      flvNum[1] = 0;
      while (index != staple.tcpConnReg.end())
      {
         TCPConn& actTCPConn = (index->second);
         // Update in-session statistics
         tcpTANum[0] += actTCPConn.transactionList[0].size();
         tcpTANum[1] += actTCPConn.transactionList[1].size();
         flvNum[0] += (actTCPConn.flv[0].found) ? 1 : 0;
         flvNum[1] += (actTCPConn.flv[1].found) ? 1 : 0;
         index++;
      }
      staple.logStream << " #tcp " << tcpConnNum << " #tcpta " << tcpTANum[0] << "/" << tcpTANum[1] << " #flv " << flvNum[0] << "/" << flvNum[1] << "\n";
      // Revert to original formatting settings
      staple.logStream.flags(origFormat);
      staple.logStream.precision(origPrec);
      // Update state
      staple.lastRealTime = actRealTime;
      ipStats.lastPacketsRead = ipStats.packetsRead;
      ipStats.lastKBytesRead = ipStats.kBytesRead;
      // Update last log time
      lastStatusLogTime = staple.actTime;
   }

   // Terminate timeouted TCPs
   if ((lastTCPTimeoutCheck.tv_sec+TCP_TIMEOUT) < staple.actTime.tv_sec)
   {
      struct timeval diffA, diffB;
      double dA,dB;
      TCPConnReg::iterator index = staple.tcpConnReg.begin();
      while (index != staple.tcpConnReg.end())
      {
         diffA = AbsTimeDiff(staple.actTime, ((*index).second).lastPacketTime[0]);
         diffB = AbsTimeDiff(staple.actTime, ((*index).second).lastPacketTime[1]);
         dA = diffA.tv_sec + (double)diffA.tv_usec/1000000;
         dB = diffB.tv_sec + (double)diffB.tv_usec/1000000;
         if ((dA > TCP_TIMEOUT) && (dB > TCP_TIMEOUT))
         {
            if (logLevel >= 3)
            {
               staple.logStream << "TCP connection timeouted.\n";
            }

            TCPConnReg::iterator eraseIndex = index++;

            ((*eraseIndex).second).termination = TCPConn::TERM_TO;
            ReleaseTCPConnection(eraseIndex);
         }
         else
         {
            index++;
         }
      }
      lastTCPTimeoutCheck = staple.actTime;
   }

   // Terminate timeouted IP sessions
   if ((lastIPTimeoutCheck.tv_sec+IP_TIMEOUT) < staple.actTime.tv_sec)
   {
      struct timeval diffA, diffB;
      double dA,dB;
      IPSessionReg::iterator index = staple.ipSessionReg.begin();
      while (index != staple.ipSessionReg.end())
      {
         diffA = AbsTimeDiff(staple.actTime, ((*index).second).lastPacketTime[0]);
         diffB = AbsTimeDiff(staple.actTime, ((*index).second).lastPacketTime[1]);
         dA = diffA.tv_sec + (double)diffA.tv_usec/1000000;
         dB = diffB.tv_sec + (double)diffB.tv_usec/1000000;
         if ((dA > IP_TIMEOUT) && (dB > IP_TIMEOUT))
         {
            if (logLevel >= 3)
            {
               staple.logStream << "IP session timeouted.\n";
            }

            IPSessionReg::iterator eraseIndex = index++;

            ReleaseIPSession(eraseIndex);
         }
         else
         {
            index++;
         }
      }
      lastIPTimeoutCheck = staple.actTime;
   }

   if (pL2Packet->pL3Packet == NULL)
   {
      // Pure L2 packet
      // --------------
   }
   else
   {
      // L3 packet
      // ---------
      L3Packet* pL3Packet = pL2Packet->pL3Packet;
      if ((pL3Packet->l3Type&L3Packet::IP) == 0)
      {
         // Non-IP packet
         // -------------
      }
      else
      {
         // IP packet
         // ---------
         IPPacket& ipPacket = *((IPPacket*)pL3Packet);

         ipStats.packetsRead++;
         ipStats.bytesRead+=ipPacket.IPPktLen;
         if (ipStats.bytesRead>>10 != 0)
         {
            ipStats.kBytesRead += ipStats.bytesRead>>10;
            ipStats.bytesRead &= 0x3ff;
         }
         if (ipPacket.match == true)
         {
            ipStats.packetsMatched[ipPacket.direction]++;
            ipStats.bytesMatched[ipPacket.direction]+=ipPacket.IPPktLen;
            if (ipStats.bytesMatched[ipPacket.direction]>>10 != 0)
            {
               ipStats.kBytesMatched[ipPacket.direction] += ipStats.bytesMatched[ipPacket.direction]>>10;
               ipStats.bytesMatched[ipPacket.direction] &= 0x3ff;
            }
         }

         // Matching IP packet
         if (ipPacket.match == true)
         {
            // Calculate IP session key
            IPAddressId ipSessionId;
            ipSessionId.IP = (ipPacket.direction == 0) ? ipPacket.srcIP : ipPacket.dstIP;

            // Find the IP session
            ipIndex = staple.ipSessionReg.find(ipSessionId);

            // IP session not found
            if (ipIndex == staple.ipSessionReg.end())
            {
               // Create and insert new entry to the registry
               IPSession newIPSession;
               newIPSession.Init(staple);

               std::pair<IPSessionReg::iterator,bool> ret = staple.ipSessionReg.insert(std::pair<IPAddressId,IPSession>(ipSessionId,newIPSession));
               ipIndex = ret.first;
            }

            IPSession& ipSession = ipIndex->second;

            // Update IP statistics
            ipSession.packetsSeen[ipPacket.direction]++;
            ipSession.bytesSeen[ipPacket.direction] += ipPacket.IPPktLen;
            if ((ipSession.packetsSeen[0]+ipSession.packetsSeen[1]) == 1)
            {
               ipSession.firstPacketTime[ipPacket.direction] = staple.actTime;
            }
            lastIPPacketTime = ipSession.lastPacketTime[ipPacket.direction];
            ipSession.lastButOnePacketTime[ipPacket.direction] = ipSession.lastPacketTime[ipPacket.direction];
            ipSession.lastButOnePacketLength[ipPacket.direction] = ipSession.lastPacketLength[ipPacket.direction];
            ipSession.lastPacketTime[ipPacket.direction] = staple.actTime;
            ipSession.lastPacketLength[ipPacket.direction] = ipPacket.IPPktLen;
            ipSession.lastIPIdSeen[ipPacket.direction] = ipPacket.IPId;

            // Calculate IP session data volumes
            unsigned long actSlotNum = staple.actTime.tv_sec / IPSESSIONDATA_SLOTTIME;
            // Should we start a new slot?
            if (actSlotNum > (ipSession.actSlotStartTime/IPSESSIONDATA_SLOTTIME))
            {
               // Was the last slot empty?
               if (actSlotNum > ((ipSession.actSlotStartTime/IPSESSIONDATA_SLOTTIME)+1))
               {
                  ipSession.lastSlotData[0] = 0;
                  ipSession.lastSlotData[1] = 0;
               }
               else
               {
                  ipSession.lastSlotData[0] = ipSession.actSlotData[0];
                  ipSession.lastSlotData[1] = ipSession.actSlotData[1];
               }
               ipSession.actSlotStartTime = actSlotNum*IPSESSIONDATA_SLOTTIME;
               ipSession.actSlotData[0] = 0;
               ipSession.actSlotData[1] = 0;
            }
            // Add data volume to the actual slot's data
            ipSession.actSlotData[ipPacket.direction] += ipPacket.IPPktLen;
         }

         if ((ipPacket.l3Type&L3Packet::ICMP) != 0)
         {
            // ICMP packet
            // ----------
            ICMPPacket& icmpPacket = *((ICMPPacket*)pL3Packet);

            icmpStats.packetsRead++;
            icmpStats.bytesRead+=icmpPacket.IPPktLen;
            if (icmpStats.bytesRead>>10 != 0)
            {
               icmpStats.kBytesRead += icmpStats.bytesRead>>10;
               icmpStats.bytesRead &= 0x3ff;
            }
            if (icmpPacket.match == true)
            {
               icmpStats.packetsMatched[icmpPacket.direction]++;
               icmpStats.bytesMatched[icmpPacket.direction]+=icmpPacket.IPPktLen;
               if (icmpStats.bytesMatched[icmpPacket.direction]>>10 != 0)
               {
                  icmpStats.kBytesMatched[icmpPacket.direction] += icmpStats.bytesMatched[icmpPacket.direction]>>10;
                  icmpStats.bytesMatched[icmpPacket.direction] &= 0x3ff;
               }
            }
         }

         if ((ipPacket.l3Type&L3Packet::UDP) != 0)
         {
            // UDP packet
            // ----------
            UDPPacket& udpPacket = *((UDPPacket*)pL3Packet);

            udpStats.packetsRead++;
            udpStats.bytesRead+=udpPacket.IPPktLen;
            if (udpStats.bytesRead>>10 != 0)
            {
               udpStats.kBytesRead += udpStats.bytesRead>>10;
               udpStats.bytesRead &= 0x3ff;
            }
            if (udpPacket.match == true)
            {
               udpStats.packetsMatched[udpPacket.direction]++;
               udpStats.bytesMatched[udpPacket.direction]+=udpPacket.IPPktLen;
               if (udpStats.bytesMatched[udpPacket.direction]>>10 != 0)
               {
                  udpStats.kBytesMatched[udpPacket.direction] += udpStats.bytesMatched[udpPacket.direction]>>10;
                  udpStats.bytesMatched[udpPacket.direction] &= 0x3ff;
               }
            }

            // Non-matching UDP packet
            // -----------------------
            if (udpPacket.match == false) return;

            // Logging
            if (logLevel >= 3)
            {
               staple.logStream << " - UDP packet";
            }
         }

         if ((ipPacket.l3Type&L3Packet::TCP) != 0)
         {
            // TCP packet
            // ----------
            TCPPacket& tcpPacket = *((TCPPacket*)pL3Packet);

            tcpStats.packetsRead++;
            tcpStats.bytesRead+=tcpPacket.IPPktLen;
            if (tcpStats.bytesRead>>10 != 0)
            {
               tcpStats.kBytesRead += tcpStats.bytesRead>>10;
               tcpStats.bytesRead &= 0x3ff;
            }
            if (tcpPacket.match == true)
            {
               tcpStats.packetsMatched[tcpPacket.direction]++;
               tcpStats.bytesMatched[tcpPacket.direction]+=tcpPacket.IPPktLen;
               if (tcpStats.bytesMatched[tcpPacket.direction]>>10 != 0)
               {
                  tcpStats.kBytesMatched[tcpPacket.direction] += tcpStats.bytesMatched[tcpPacket.direction]>>10;
                  tcpStats.bytesMatched[tcpPacket.direction] &= 0x3ff;
               }
            }
            // Non-matching TCP packet
            // -----------------------
            if (tcpPacket.match == false) return;

            // Connection lookup
            // -----------------
            // Calculate connection key
            TCPConnId tcpConnId;
            tcpConnId.netAIP = (tcpPacket.direction == 0) ? tcpPacket.srcIP : tcpPacket.dstIP;
            tcpConnId.netBIP = (tcpPacket.direction == 0) ? tcpPacket.dstIP : tcpPacket.srcIP;
            tcpConnId.netAPort = (tcpPacket.direction == 0) ? tcpPacket.srcPort : tcpPacket.dstPort;
            tcpConnId.netBPort = (tcpPacket.direction == 0) ? tcpPacket.dstPort : tcpPacket.srcPort;

            // Get IP session (using cached iterator)
            IPSession& ipSession = ipIndex->second;

            bool releaseTCP = false;
            bool newTCPPL = false;
            tcpIndex = staple.tcpConnReg.find(tcpConnId);
            // Connection not found
            // --------------------
            if (tcpIndex == staple.tcpConnReg.end())
            {
               // Initiator SYN (first)
               if (((tcpPacket.TCPFlags&TCPPacket::SYN) != 0) && ((tcpPacket.TCPFlags&TCPPacket::ACK) == 0))
               {
                  // Logging
                  if (logLevel >= 3)
                  {
                     staple.logStream << " - connection setup (SYN) - original seq " << tcpPacket.seq << " ack " << tcpPacket.ack;
                  }

                  // Create new TCP entry
                  TCPConn newTCPConn;
                  newTCPConn.Init();
                  newTCPConn.direction = tcpPacket.direction;
                  newTCPConn.IPSessionBytes[tcpPacket.direction] = ipSession.bytesSeen[tcpPacket.direction] - tcpPacket.IPPktLen;
                  newTCPConn.IPSessionBytes[1-tcpPacket.direction] = ipSession.bytesSeen[1-tcpPacket.direction];
                  newTCPConn.firstSYNTime = staple.actTime;
                  newTCPConn.firstSYNLen = tcpPacket.IPPktLen;
                  struct timeval gap = AbsTimeDiff(staple.actTime, lastIPPacketTime);
                  newTCPConn.firstSYNGap = gap.tv_sec + (double)gap.tv_usec/1000000;
                  newTCPConn.SYNCount = 1;
                  // Determine load
                  if (((ipSession.actSlotData[0]+ipSession.lastSlotData[0])<=UNLOADED_MAXDATA_BEFORE) &&
                  ((ipSession.actSlotData[1]+ipSession.lastSlotData[1])<=UNLOADED_MAXDATA_BEFORE))
                  {
                     newTCPConn.unloadedSetup = true;
                  }
                  // Initialize SYNReg
                  newTCPConn.SYNReg[tcpPacket.seq]=1;
                  newTCPConn.highestExpectedSeq[tcpPacket.direction]=1;
                  newTCPConn.highestExpectedDataSeq[tcpPacket.direction]=1;
                  // Fill in window scale parameters if necessary
                  if ((tcpPacket.options&TCPPacket::WNDSCALE)!=0)
                  {
                     newTCPConn.wndScaleSeen[tcpPacket.direction] = true;
                     newTCPConn.wndScaleVal[tcpPacket.direction] = tcpPacket.wndScaleVal;
                  }

                  // Insert new entry to the TCP registry
                  std::pair<TCPConnReg::iterator,bool> ret = staple.tcpConnReg.insert(std::pair<TCPConnId,TCPConn>(tcpConnId,newTCPConn));
                  tcpIndex = ret.first;

                  // Add TCP to IP session
                  ipSession.AddTCPConnection(tcpConnId);

                  // Use relative sequence numbers
                  tcpPacket.seq = 0;
                  tcpPacket.ack = 0;
               }
               // Unclassified TCP connection
               // ---------------------------
               else
               {
                  // Update capture loss stats: peer SYN ACK without a SYN
                  if (((tcpPacket.TCPFlags&TCPPacket::SYN) != 0) &&
                  ((tcpPacket.TCPFlags&TCPPacket::ACK) != 0))
                  {
                     tcpStats.SYNNotFound[1-tcpPacket.direction]++;
                  }
                  // Logging
                  if (logLevel >= 3)
                  {
                     staple.logStream << " - does not belong to a registered TCP connection";
                  }
               }
            }
            // Connection found
            // ----------------
            else
            {
               TCPConn &tcpConn = tcpIndex->second;

               // Update IP data
               tcpConn.IPBytes[tcpPacket.direction] += tcpPacket.IPPktLen;
               tcpConn.PLBytes[tcpPacket.direction] += tcpPacket.TCPPLLen;
               // Connection setup is in progress
               // -------------------------------
               if (tcpConn.setupSuccess==false)
               {
                  // Initiator SYN (not first)
                  if (((tcpPacket.TCPFlags&TCPPacket::SYN) != 0) &&
                  ((tcpPacket.TCPFlags&TCPPacket::ACK) == 0) &&
                  (tcpPacket.direction==tcpConn.direction))
                  {
                     // Logging
                     if (logLevel>=3)
                     {
                        staple.logStream << " - repeated SYN - original seq " << tcpPacket.seq << " ack " << tcpPacket.ack;
                     }
                     // If SEQ is not yet seen, insert to the SYN registry
                     if (tcpConn.SYNReg.find(tcpPacket.seq) == tcpConn.SYNReg.end())
                     {
                        tcpConn.SYNReg[tcpPacket.seq]=1;
                     }
                     tcpConn.SYNCount++;
                     // Use relative sequence numbers
                     tcpPacket.seq = 0;
                     tcpPacket.ack = 0;
                  }
                  // Peer SYN ACK
                  else if (((tcpPacket.TCPFlags&TCPPacket::SYN) != 0) &&
                  ((tcpPacket.TCPFlags&TCPPacket::ACK) != 0) &&
                  (tcpPacket.direction==(1-tcpConn.direction)))
                  {
                     // Logging
                     if (logLevel>=3)
                     {
                        staple.logStream << " - SYN ACK - original seq " << tcpPacket.seq << " ack " << tcpPacket.ack;
                     }
                     // If SEQ is not yet seen, insert to the SYN ACK registry
                     if (tcpConn.SYNACKReg.find(tcpPacket.seq) == tcpConn.SYNACKReg.end())
                     {
                        tcpConn.SYNACKReg[tcpPacket.seq]=1;
                     }
                     // First SYN ACK
                     if (tcpConn.SYNACKCount == 0)
                     {
                        tcpConn.firstSYNACKTime = staple.actTime;
                        tcpConn.firstSYNACKLen = tcpPacket.IPPktLen;
                        struct timeval gap = AbsTimeDiff(staple.actTime,lastIPPacketTime);
                        tcpConn.firstSYNACKGap = gap.tv_sec + (double)gap.tv_usec/1000000;
                        tcpConn.highestExpectedSeq[tcpPacket.direction]=1;
                        tcpConn.highestExpectedDataSeq[tcpPacket.direction]=1;
                        tcpConn.highestACKSeen[tcpPacket.direction]=1;
                        // Update capture loss stats: first SYN ACK with a SYN
                        tcpStats.SYNFound[tcpConn.direction]++;
                    }
                     tcpConn.SYNACKCount++;
                     // Use relative sequence numbers
                     tcpPacket.seq = 0;
                     tcpPacket.ack = 1;
                     // Fill in window scale parameters if necessary
                     if ((tcpPacket.options&TCPPacket::WNDSCALE)!=0)
                     {
                        tcpConn.wndScaleSeen[tcpPacket.direction] = true;
                        tcpConn.wndScaleVal[tcpPacket.direction] = tcpPacket.wndScaleVal;
                     }
                  }
                  // Initiator ACK (first)
                  else if (((tcpPacket.TCPFlags&TCPPacket::SYN) == 0) &&
                  ((tcpPacket.TCPFlags&TCPPacket::ACK) != 0) &&
                  (tcpPacket.direction==tcpConn.direction) &&
                  (tcpConn.SYNReg.find(tcpPacket.seq-1) != tcpConn.SYNReg.end()))
                  {
                     // Check if SYN ACK was seen (everything all right - no capture loss)
                     if (tcpConn.SYNACKReg.find(tcpPacket.ack-1) != tcpConn.SYNACKReg.end())
                     {
                        // Logging
                        if (logLevel>=3)
                        {
                           staple.logStream << " - first ACK - original seq " << tcpPacket.seq << " ack " << tcpPacket.ack;
                        }
                        // First ACK
                        tcpConn.firstACKTime = staple.actTime;
                        tcpConn.firstACKLen = tcpPacket.IPPktLen;
                        struct timeval gap = AbsTimeDiff(staple.actTime,lastIPPacketTime);
                        tcpConn.firstACKGap = gap.tv_sec + (double)gap.tv_usec/1000000;
                        // Calculate partial RTTs
                        struct timeval partialRTT;
                        double pRTT;
                        if (tcpConn.SYNCount == 1)
                        {
                           partialRTT = AbsTimeDiff(tcpConn.firstSYNACKTime, tcpConn.firstSYNTime);
                           pRTT = partialRTT.tv_sec + (double)partialRTT.tv_usec/1000000;
                           // Fill in initial RTT
                           tcpConn.initialRTT[1-tcpConn.direction] = pRTT;
                           // Initialize min. and max. RTT for the TCP connection
                           tcpConn.minRTT[1-tcpPacket.direction] = pRTT;
                           tcpConn.maxRTT[1-tcpPacket.direction] = pRTT;

                           if (logLevel >= 3)
                           {
                              staple.logStream << " - " << ((1-tcpConn.direction == 0) ? "NetA" : "NetB") << " RTT is " << pRTT << "s";
                           }
                        }
                        if (tcpConn.SYNACKCount == 1)
                        {
                           partialRTT = AbsTimeDiff(tcpConn.firstACKTime, tcpConn.firstSYNACKTime);
                           pRTT = partialRTT.tv_sec + (double)partialRTT.tv_usec/1000000;
                           // Fill in initial RTT
                           tcpConn.initialRTT[tcpConn.direction] = pRTT;
                           // Initialize min. and max. RTT for the TCP connection
                           tcpConn.minRTT[tcpPacket.direction] = pRTT;
                           tcpConn.maxRTT[tcpPacket.direction] = pRTT;

                           if (logLevel >= 3)
                           {
                              staple.logStream << " - " << ((tcpConn.direction == 0) ? "NetA" : "NetB") << " RTT is " << pRTT << "s";
                           }
                        }
                        // Calculate setup delay
                        struct timeval setupDelay = AbsTimeDiff(staple.actTime, tcpConn.firstSYNTime);
                        double sDelay = setupDelay.tv_sec + (double)setupDelay.tv_usec/1000000;
                        if (logLevel >= 3)
                        {
                           staple.logStream << " - Connection setup delay is " << sDelay << "s";
                        }
                        // Determine setup load
                        unsigned long parallelIPBytes0 = ipSession.bytesSeen[0] - tcpConn.IPSessionBytes[0] - tcpConn.IPBytes[0];
                        unsigned long parallelIPBytes1 = ipSession.bytesSeen[1] - tcpConn.IPSessionBytes[1] - tcpConn.IPBytes[1];
                        if ((tcpConn.unloadedSetup==true) && (parallelIPBytes0<=UNLOADED_MAXDATA_DURING) && (parallelIPBytes1<=UNLOADED_MAXDATA_DURING))
                        {
                           if (logLevel >= 3)
                           {
                              staple.logStream << " (unloaded)";
                           }
                        }
                        else
                        {
                           tcpConn.unloadedSetup = false;
                        }
                        // Get ISNs
                        tcpConn.ISN[tcpPacket.direction]=tcpPacket.seq-1;
                        tcpConn.ISN[1-tcpPacket.direction]=tcpPacket.ack-1;
                        // Set timestamp-based loss estimation reliability
                        tcpConn.tsLossReliable = ((tcpConn.TSSeen[0]==true) && (tcpConn.TSSeen[1]==true)) ? true : false;
                        // Successful setup
                        tcpConn.setupSuccess=true;
                        // Update capture loss stats: first ACK with a SYN ACK
                        tcpStats.SYNACKFound[tcpConn.direction]++;
                     }
                     // No SYN ACK was seen (first ACK without a SYN ACK)
                     else
                     {
                        // Update capture loss stats
                        tcpStats.SYNACKNotFound[tcpConn.direction]++;
                     }
                  }
                  // Other packet
                  else if (((tcpPacket.TCPFlags&TCPPacket::SYN) != 0) ||
                  (tcpPacket.TCPPLLen != 0))
                  {
                     // Logging
                     if (logLevel>=3)
                     {
                        staple.logStream << " - connection setup procedure is not interpretable - connection erased";
                     }
                     // Release TCP connection
                     releaseTCP = true;
                  }
               }
               // Connection is already set up
               // ----------------------------
               if (tcpConn.setupSuccess==true)
               {
                  // Sanity checks
                  // -------------
                  // SYN on an already set up connection
                  if (((tcpPacket.TCPFlags&TCPPacket::SYN) != 0) && ((tcpPacket.TCPFlags&TCPPacket::ACK) == 0))
                  {
                     // Terminate old TCP connection
                     tcpConn.termination = TCPConn::TERM_TO;
                     ReleaseTCPConnection(tcpIndex);

                     // Logging
                     if (logLevel >= 3)
                     {
                        staple.logStream << " - SYN on an already set up connection - original seq " << tcpPacket.seq << " ack " << tcpPacket.ack;
                     }

                     // Create new TCP entry
                     TCPConn newTCPConn;
                     newTCPConn.Init();
                     newTCPConn.IPSessionBytes[tcpPacket.direction] = ipSession.bytesSeen[tcpPacket.direction] - tcpPacket.IPPktLen;
                     newTCPConn.IPSessionBytes[1-tcpPacket.direction] = ipSession.bytesSeen[1-tcpPacket.direction];
                     newTCPConn.direction = tcpPacket.direction;
                     newTCPConn.firstSYNTime = staple.actTime;
                     newTCPConn.firstSYNLen = tcpPacket.IPPktLen;
                     struct timeval gap = AbsTimeDiff(staple.actTime,lastIPPacketTime);
                     newTCPConn.firstSYNGap = gap.tv_sec + (double)gap.tv_usec/1000000;
                     newTCPConn.SYNCount = 1;
                     // Determine load
                     if (((ipSession.actSlotData[0]+ipSession.lastSlotData[0])<=UNLOADED_MAXDATA_BEFORE) &&
                     ((ipSession.actSlotData[1]+ipSession.lastSlotData[1])<=UNLOADED_MAXDATA_BEFORE))
                     {
                        newTCPConn.unloadedSetup = true;
                     }
                     // Initialize SYNReg
                     newTCPConn.SYNReg[tcpPacket.seq]=1;
                     newTCPConn.highestExpectedSeq[tcpPacket.direction]=1;
                     newTCPConn.highestExpectedDataSeq[tcpPacket.direction]=1;
                     // Fill in window scale parameters if necessary
                     if ((tcpPacket.options&TCPPacket::WNDSCALE)!=0)
                     {
                        newTCPConn.wndScaleSeen[tcpPacket.direction] = true;
                        newTCPConn.wndScaleVal[tcpPacket.direction] = tcpPacket.wndScaleVal;
                     }
                     // Insert new entry to the TCP registry
                     std::pair<TCPConnReg::iterator,bool> ret = staple.tcpConnReg.insert(std::pair<TCPConnId,TCPConn>(tcpConnId,newTCPConn));
                     tcpIndex = ret.first;
                     // Add TCP to IP session
                     ipSession.AddTCPConnection(tcpConnId);

                     // Use relative sequence numbers
                     tcpPacket.seq = 0;
                     tcpPacket.ack = 0;
                  }
                  // SEQ check (FIN included, SYN & RST & other zero TCP payload excluded)
                  else if (((tcpPacket.TCPPLLen > 0) || ((tcpPacket.TCPFlags&TCPPacket::FIN) != 0)) &&
                		  ((tcpPacket.TCPFlags&TCPPacket::RST) == 0) &&
                		  ((tcpPacket.TCPFlags&TCPPacket::SYN) == 0) &&
                		  ((tcpPacket.seq < tcpConn.ISN[tcpPacket.direction]) ||
                				  (abs((int64_t)(tcpPacket.seq-tcpConn.ISN[tcpPacket.direction]) - (int64_t)(tcpConn.highestExpectedSeq[tcpPacket.direction])) > TCP_SEQ_INSANE_THRESH)))
                  {
                     // Logging
                     if (logLevel>=3)
                     {
                        staple.logStream << " - insane seq";
                     }
                     // Terminate TCP connection
                     ReleaseTCPConnection(tcpIndex);
                     tcpIndex = staple.tcpConnReg.end();
                  }
                  // ACK check (RST excluded!)
                  else if ((((tcpPacket.TCPFlags&TCPPacket::ACK) != 0) && ((tcpPacket.TCPFlags&TCPPacket::RST) == 0)) &&
                		  ((tcpPacket.ack < tcpConn.ISN[1-tcpPacket.direction]) ||
                          (abs((int64_t)(tcpPacket.ack-tcpConn.ISN[1-tcpPacket.direction]) - (int64_t)(tcpConn.highestACKSeen[tcpPacket.direction])) > TCP_SEQ_INSANE_THRESH)))
                  {
                     // Logging
                     if (logLevel>=3)
                     {
                        staple.logStream << " - insane ack";
                     }
                     // Terminate TCP connection
                     ReleaseTCPConnection(tcpIndex);
                     tcpIndex = staple.tcpConnReg.end();
                  }
                  // Connection is OK
                  // ----------------
                  else
                  {
                     // Use relative sequence numbers (also for SACK blocks)
                     tcpPacket.seq -= tcpConn.ISN[tcpPacket.direction];
                     tcpPacket.ack -= tcpConn.ISN[1-tcpPacket.direction];
                     for (int i=0;i<tcpPacket.sackBlockNum;i++)
                     {
                        tcpPacket.sackLeftEdge[i] -= tcpConn.ISN[1-tcpPacket.direction];
                        tcpPacket.sackRightEdge[i] -= tcpConn.ISN[1-tcpPacket.direction];
                     }

                     // DATA packet (containing real data)
                     // ----------------------------------
                     if (tcpPacket.TCPPLLen > 0)
                     {
                        // Logging
                        if (logLevel >= 3)
                        {
                           staple.logStream << " - DATA";
                        }

                        // Update first DATA packet time if necessary (for data TP & GP calculation)
                        if ((tcpConn.firstDataPacketTime[tcpPacket.direction].tv_sec==0) && (tcpConn.firstDataPacketTime[tcpPacket.direction].tv_usec==0))
                        {
                           tcpConn.firstDataPacketTime[tcpPacket.direction] = staple.actTime;
                        }

                        // Update min., max. and mean data packet sizes
                        if ((tcpPacket.IPPktLen < tcpConn.minDataPacketIPLen[tcpPacket.direction]) || (tcpConn.dataPacketsSeen[tcpPacket.direction] == 0))
                        {
                           tcpConn.minDataPacketIPLen[tcpPacket.direction] = tcpPacket.IPPktLen;
                        }
                        if ((tcpPacket.IPPktLen > tcpConn.maxDataPacketIPLen[tcpPacket.direction]) || (tcpConn.dataPacketsSeen[tcpPacket.direction] == 0))
                        {
                           tcpConn.maxDataPacketIPLen[tcpPacket.direction] = tcpPacket.IPPktLen;
                        }
                        tcpConn.meanDataPacketIPLen[tcpPacket.direction] = ((tcpConn.meanDataPacketIPLen[tcpPacket.direction] * tcpConn.dataPacketsSeen[tcpPacket.direction]) + tcpPacket.IPPktLen) / (tcpConn.dataPacketsSeen[tcpPacket.direction]+1);
                        // Logging
                        if (logLevel >= 5)
                        {
                           staple.logStream << " - Size stats:" << tcpConn.minDataPacketIPLen[tcpPacket.direction] << "|" << tcpConn.meanDataPacketIPLen[tcpPacket.direction] << "|" << tcpConn.maxDataPacketIPLen[tcpPacket.direction];
                        }
                        // Update non-pushed data packet flag (for MSS estimation)
                        if (((tcpPacket.TCPFlags&TCPPacket::PSH)==0) &&
                        ((tcpPacket.TCPFlags&TCPPacket::SYN)==0) &&
                        ((tcpPacket.TCPFlags&TCPPacket::FIN)==0) &&
                        ((tcpPacket.TCPFlags&TCPPacket::RST)==0) &&
                        (tcpConn.nonPSHDataPacketSeen[tcpPacket.direction]==false))
                        {
                           tcpConn.nonPSHDataPacketSeen[tcpPacket.direction]=true;
                           if (logLevel >= 5)
                           {
                              staple.logStream << " - first non-pushed DATA (MSS is reliable)";
                           }
                        }

                        // New packet
                        // ----------
                        if (tcpPacket.seq >= tcpConn.highestExpectedDataSeq[tcpPacket.direction])
                        {
                           // Insert it into the packet list
                           PacketTrainTCPPacket tmpPacket;
                           tmpPacket.Init();
                           tmpPacket.seq = tcpPacket.seq;
                           tmpPacket.len = tcpPacket.TCPPLLen;
                           tmpPacket.t = staple.actTime;
                           // By default, the packet is significant for AMP loss
                           tmpPacket.signAMP = true;
                           // Packets with PSH bit are not significant for BMP loss
                           tmpPacket.signBMP = ((tcpPacket.TCPFlags&TCPPacket::PSH)==0) ? true : false;

                           tcpConn.packetTrains[tcpPacket.direction].InsertPacket(tmpPacket);

                           // Place timestamp into tsReg for TS-based AMP loss verification
                           if (tcpConn.tsLossReliable==true)
                           {
                              TCPConn::TSRegEntry tsRegEntry;
                              tsRegEntry.ts[0] = ((tcpPacket.options&TCPPacket::TIMESTAMP)!=0) ? tcpPacket.tsValue : 0;
                              tsRegEntry.ts[1] = 0;
                              tsRegEntry.tsSeen[0] = ((tcpPacket.options&TCPPacket::TIMESTAMP)!=0) ? true : false;
                              tsRegEntry.tsSeen[1] = false;
                              tsRegEntry.rtxSeen = false;
                              tcpConn.tsReg[tcpPacket.direction].insert(std::make_pair(tcpPacket.seq,tsRegEntry));
                           }

                           // Logging
                           if (logLevel >= 3)
                           {
                              staple.logStream << " - highestSeq";
                           }

                           // Do we have to finish retransmission state? (this is because of e.g., for already ACK-ed RTX sometimes cannot be exited by a new ACK trigger)
                           if ((tcpConn.sndLossState[tcpPacket.direction] != TCPConn::NORMAL) &&
                           (tcpConn.sndLossState[tcpPacket.direction] != TCPConn::POSSIBLE_EWL) &&
                           (tcpConn.highestACKSeen[1-tcpPacket.direction] >= tcpConn.rtxHighestSeq[tcpPacket.direction]))
                           {
                              // Finish retransmission state (and enter POSSIBLE_EWL state if necessary)
                              FinishRetransmissionState(tcpConn,tcpPacket.direction);
                           }

                           // Other processing
                           HighestSeqTCPDataPacket(tcpPacket,tcpIndex,ipSession);

                           // Signal that payload processing will be necessary
                           newTCPPL = true;
                        }
                        // Old packet
                        // ----------
                        else
                        {
                           // Logging
                           if (logLevel >= 3)
                           {
                              staple.logStream << " - lowSeq";
                           }

                           // Update first RTT calc SEQ (retransmission invalidates all sent SEQs, safe reordering handling)
                           tcpConn.firstRTTCalcSeq[tcpPacket.direction] = tcpConn.highestExpectedSeq[tcpPacket.direction];
                           if (logLevel >= 3)
                           {
                              staple.logStream << " - updated first RTT calc seq to " << tcpConn.firstRTTCalcSeq[tcpPacket.direction];
                           }
                           // Quit RTT calc state
                           if (tcpConn.inRTTCalcState[tcpPacket.direction]==true)
                           {
                              tcpConn.inRTTCalcState[tcpPacket.direction]=false;
                              ipSession.DecreaseTCPsInRTTCalcState(tcpPacket.direction);
                              // Logging
                              if (logLevel >= 3)
                              {
                                 staple.logStream << " - RTT calc state exited";
                              }
                           }
                           // Zero flightsize
                           if (tcpConn.ongoingTransaction[tcpPacket.direction]==true)
                           {
                              // Get reference to the transaction
                              TCPTransaction& tcpTA = tcpConn.transactionList[tcpPacket.direction].back();

                              struct timeval timeDiff = AbsTimeDiff(staple.actTime, tcpTA.flightSizeLastTime);
                              double tDiff = ((tcpTA.flightSizeLastTime.tv_sec==0) && (tcpTA.flightSizeLastTime.tv_usec==0)) ? 0 :
                                             (timeDiff.tv_sec + (double)timeDiff.tv_usec/1000000);

                              tcpTA.flightSizeMean += tDiff * tcpTA.flightSizeLastValue;
                              tcpTA.flightSizeLastTime = staple.actTime;
                              tcpTA.flightSizeLastValue = 0;
                              tcpTA.flightSizeTimeSum += tDiff;
                           }
                           // Have we already seen it?
                           std::list<PacketTrain>::iterator overlapIndex;
                           overlapIndex = tcpConn.packetTrains[tcpPacket.direction].TestPartialOverlap(tcpPacket.seq,tcpPacket.seq+tcpPacket.TCPPLLen);
                           if (overlapIndex != tcpConn.packetTrains[tcpPacket.direction].packetTrainList.end())
                           {
                              // If we have an ongoing transaction and we have not reached the slow start end yet -> we reached it now...
                              if ((tcpConn.ongoingTransaction[tcpPacket.direction] == true) &&
                              (tcpConn.transactionList[tcpPacket.direction].back().ssEndACKTime.tv_sec==0) && (tcpConn.transactionList[tcpPacket.direction].back().ssEndACKTime.tv_usec==0))
                              {
                                 // Logging
                                 if (logLevel >= 3)
                                 {
                                    staple.logStream << " - slow start end reached (AMP loss)";
                                 }
                                 tcpConn.transactionList[tcpPacket.direction].back().ssEndACKTime = tcpConn.highestDataACKTime[1-tcpPacket.direction];
                                 tcpConn.transactionList[tcpPacket.direction].back().ssEndIPSessionBytes = tcpConn.highestDataACKIPSessionBytes[tcpPacket.direction];
                              }
                              // Packet overlaps with the packets seen
                              // -------------------------------------
                              std::list<PacketTrainTCPPacket>::iterator packetIndex = (*overlapIndex).TestPacket(tcpPacket.seq,tcpPacket.seq+tcpPacket.TCPPLLen);
                              if (packetIndex != (*overlapIndex).packetList.end())
                              {
                                 // Exact match with a packet
                                 // -------------------------
                                 // Logging
                                 if (logLevel >= 3)
                                 {
                                    staple.logStream << " - already seen";
                                 }
                                 // Look for timestamps for AMP loss validation (if BMP loss not yet detected)
                                 if ((tcpConn.tsLossReliable==true) && ((*packetIndex).lossInfo != PacketTrainTCPPacket::LOST_BMP))
                                 {
                                    // For ambigous retransmissions, update TSReg to find out retransmission necessity later
                                    if (tcpPacket.seq >= tcpConn.highestACKSeen[1-tcpPacket.direction])
                                    {
                                       // Look up the seq in the timestamp registry
                                       TCPConn::TSReg::iterator tsRegIndex = tcpConn.tsReg[tcpPacket.direction].find(tcpPacket.seq);
                                       if (tsRegIndex != tcpConn.tsReg[tcpPacket.direction].end())
                                       {
                                          TCPConn::TSRegEntry& tsRegEntry = (*tsRegIndex).second;
                                          // If it is the first retransmission, insert retransmission timestamp into the registry
                                          if (tsRegEntry.rtxSeen == false)
                                          {
                                             tsRegEntry.ts[1] = ((tcpPacket.options&TCPPacket::TIMESTAMP)!=0) ? tcpPacket.tsValue : 0;
                                             tsRegEntry.tsSeen[1] = ((tcpPacket.options&TCPPacket::TIMESTAMP)!=0) ? true : false;
                                             tsRegEntry.rtxSeen = true;
                                          }
                                          if (logLevel >= 3)
                                          {
                                             staple.logStream << " - TS AMP validation: retransmission timestamp inserted into TSReg";
                                          }
                                       }
                                       else
                                       {
                                          // Not found (timestamp-based AMP loss estimation becomes unreliable)
                                          if (logLevel >= 3)
                                          {
                                             staple.logStream << " - TS AMP validation: original seq (" << tcpPacket.seq << ") not found in TSReg (serious problem)";
                                          }
                                          tcpConn.tsLossReliable = false;
                                       }
                                    }
                                 }

                                 // Mark packet as AMP loss candidate (if not lost BMP & not yet marked)
                                 if (((*packetIndex).lossInfo != PacketTrainTCPPacket::LOST_BMP) && ((*packetIndex).ampLossCandidate == false))
                                 {
                                    (*packetIndex).ampLossCandidate = true;
                                    // Logging
                                    if (logLevel >= 3)
                                    {
                                       staple.logStream << " - marked as AMP loss candidate";
                                    }
                                 }
                                 else
                                 {
                                    // Logging
                                    if (logLevel >= 3)
                                    {
                                       staple.logStream << " - no AMP marking (already marked or BMP loss already detected)";
                                    }
                                 }
                                 // Calculate already seen PL bytes (spurious timeout upper bound)
                                 tcpConn.PLBytesAlreadySeen[tcpPacket.direction] += tcpPacket.TCPPLLen;

                                 // Set EWLFirstSeq in RTX and POSSIBLE_EWL state (if this is the first retransmission after the highest dupACK)
                                 if ((tcpConn.sndLossState[tcpPacket.direction]!=TCPConn::NORMAL) &&
                                 (tcpConn.rtxEWLFirstSeq[tcpPacket.direction]==0) &&
                                 (tcpPacket.seq>tcpConn.rtxDupACKSeq[tcpPacket.direction]) &&
                                 (tcpPacket.seq<tcpConn.rtxHighestSeq[tcpPacket.direction]))
                                 {
                                    tcpConn.rtxEWLFirstSeq[tcpPacket.direction]=tcpPacket.seq;
                                    // Logging
                                    if (logLevel >= 3)
                                    {
                                       staple.logStream << " - possible end-of-window loss first seq set to " << tcpPacket.seq;
                                    }
                                 }

                                 // Enter retransmission state (if not yet entered)
                                 // From POSSIBLE_EWL state we only enter if it is not an already ACKed retransmission
                                 if ((tcpConn.sndLossState[tcpPacket.direction]==TCPConn::NORMAL) ||
                                 ((tcpConn.sndLossState[tcpPacket.direction]==TCPConn::POSSIBLE_EWL) &&
                                  (tcpPacket.seq >= tcpConn.highestACKSeen[1-tcpPacket.direction])))
                                 {
                                    // Store sequence number bounds
                                    tcpConn.rtxFirstSeq[tcpPacket.direction]=tcpPacket.seq;
                                    tcpConn.rtxFirstSeqLossInfo[tcpPacket.direction]=PacketTrainTCPPacket::LOST_AMP;
                                    tcpConn.rtxHighestSeq[tcpPacket.direction]=tcpConn.highestExpectedSeq[tcpPacket.direction];
                                    // Initialize RTX dupACK and possible EWL related variables
                                    if (tcpConn.dupACKCount[1-tcpPacket.direction]>0)
                                    {
                                       // DupACK was seen
                                       tcpConn.rtxDupACKSeq[tcpPacket.direction] = tcpConn.highestACKSeen[1-tcpPacket.direction];
                                       // Invalidate possible EWL first SEQ (will be eventually filled out when a retransmission arrives)
                                       tcpConn.rtxEWLFirstSeq[tcpPacket.direction] = 0;
                                    }
                                    else
                                    {
                                       // No dupACK was seen (yet)
                                       tcpConn.rtxDupACKSeq[tcpPacket.direction] = 0;
                                       // Since we haven't seen dupACKs yet, a possible end-of-window loss may include all RTX packets
                                       tcpConn.rtxEWLFirstSeq[tcpPacket.direction] = tcpConn.rtxFirstSeq[tcpPacket.direction];
                                    }
                                    // Packet already ACKed
                                    if (tcpPacket.seq < tcpConn.highestACKSeen[1-tcpPacket.direction])
                                    {
                                       // Unnecessary retransmission
                                       tcpConn.sndLossState[tcpPacket.direction]=TCPConn::UNNECESSARY_RTX;
                                       // Logging
                                       if (logLevel >= 3)
                                       {
                                          staple.logStream << " - already ACKed retransmission - sndLossState: UNNECESSARY_RTX state entered";
                                       }
                                    }
                                    // Packet not yet ACKed
                                    else
                                    {
                                       // DupACK(s) seen
                                       if (tcpConn.dupACKCount[1-tcpPacket.direction]>0)
                                       {
                                          // Necessary retransmission
                                          tcpConn.sndLossState[tcpPacket.direction]=TCPConn::NECESSARY_RTX;
                                          tcpConn.rcvLossState[tcpPacket.direction]=TCPConn::HOLE;
                                          // Logging
                                          if (logLevel >= 3)
                                          {
                                             staple.logStream << " - dupACK(s) seen - sndLossState: NECESSARY_RTX state entered - rcvLossState: HOLE state entered";
                                          }
                                       }
                                       // DupACK(s) not (yet) seen
                                       else
                                       {
                                          // Necessity can not be decided yet
                                          tcpConn.sndLossState[tcpPacket.direction]=TCPConn::UNKNOWN_RTX;
                                          // Logging
                                          if (logLevel >= 3)
                                          {
                                             staple.logStream << " - dupACK(s) not (yet) seen - sndLossState: UNKNOWN_RTX state entered";
                                          }
                                       }
                                    }
                                 }
                              }
                              else
                              {
                                 // No exact match
                                 // --------------
                                 // The loss estimation becomes unreliable
                                 tcpConn.lossReliable = false;
                                 tcpConn.tsLossReliable = false;
                                 tcpConn.rtxDataOffset = true;
                                 // Update possible ongoing transaction as well
                                 if (tcpConn.ongoingTransaction[tcpPacket.direction]==true)
                                 {
                                    // Get reference to the transaction
                                    TCPTransaction& tcpTA = tcpConn.transactionList[tcpPacket.direction].back();
                                    tcpTA.lossReliable = false;
                                    tcpTA.rtxDataOffset = true;
                                 }
                                 // Logging
                                 if (logLevel >= 3)
                                 {
                                    staple.logStream << " - data offset (loss unreliable)";
                                 }
                              }
                           }
                           // No overlap with the first transmission list
                           // -------------------------------------------
                           else
                           {
                              // Logging
                              if (logLevel >= 3)
                              {
                                 staple.logStream << " - not yet seen";
                              }

                              // Prepare packet to insert into the packet list
                              PacketTrainTCPPacket tmpPacket;
                              tmpPacket.Init();
                              tmpPacket.seq = tcpPacket.seq;
                              tmpPacket.len = tcpPacket.TCPPLLen;
                              tmpPacket.t = staple.actTime;

                              // Determine whether the packet is reordered or not
                              unsigned short reorderDepth;
                              unsigned long reorderLowestSeq;
                              // Go through the highest seq list backwards to check IPIds
                              std::list<TCPConn::HighestSeqListEntry>::iterator listIndex = tcpConn.highestSeqList[tcpPacket.direction].end();
                              for (reorderDepth=0;reorderDepth<tcpConn.highestSeqList[tcpPacket.direction].size();reorderDepth++)
                              {
                                 listIndex--;
                                 if (tcpPacket.IPId > (*listIndex).ipId)
                                 {
                                    // This may be the lowest seq of an original transmission (at the time of the reordering)
                                    reorderLowestSeq = (*listIndex).seq + 1;
                                    break;
                                 }
                              }
                              // If the packet's IPId is lower than any unACKed packet's, the lowest possible seq is the highestACKSeen
                              if (reorderDepth == tcpConn.highestSeqList[tcpPacket.direction].size())
                              {
                                 reorderLowestSeq = tcpConn.highestACKSeen[1-tcpPacket.direction];
                              }

                              // Retransmitted packet (not reordered, or reordered but retransmitted)
                              // --------------------------------------------------------------------
                              if ((reorderDepth==0) || ((reorderDepth>0)&&(tcpPacket.seq<reorderLowestSeq)))
                              {
                                 // If we have an ongoing transaction and we have not reached the slow start end yet -> we reached it now...
                                 if ((tcpConn.ongoingTransaction[tcpPacket.direction] == true) &&
                                 (tcpConn.transactionList[tcpPacket.direction].back().ssEndACKTime.tv_sec==0) && (tcpConn.transactionList[tcpPacket.direction].back().ssEndACKTime.tv_usec==0))
                                 {
                                    // Logging
                                    if (logLevel >= 3)
                                    {
                                       staple.logStream << " - slow start end reached (BMP loss)";
                                    }
                                    tcpConn.transactionList[tcpPacket.direction].back().ssEndACKTime = tcpConn.highestDataACKTime[1-tcpPacket.direction];
                                    tcpConn.transactionList[tcpPacket.direction].back().ssEndIPSessionBytes = tcpConn.highestDataACKIPSessionBytes[tcpPacket.direction];
                                 }
                                 // Mark packet as lost BMP
                                 tmpPacket.lossInfo = PacketTrainTCPPacket::LOST_BMP;
                                 // Packets with PSH bit are not significant for BMP loss
                                 tmpPacket.signBMP = ((tcpPacket.TCPFlags&TCPPacket::PSH)==0) ? true : false;
                                 // Packet is not significant for AMP loss
                                 tmpPacket.signAMP = false;
                                 // Logging
                                 if (logLevel >= 3)
                                 {
                                    staple.logStream << " - signals BMP loss";
                                 }

                                 // Set EWLFirstSeq in RTX and POSSIBLE_EWL state (if this is the first retransmission after the highest dupACK)
                                 if ((tcpConn.sndLossState[tcpPacket.direction]!=TCPConn::NORMAL) &&
                                 (tcpConn.rtxEWLFirstSeq[tcpPacket.direction]==0) &&
                                 (tcpPacket.seq>tcpConn.rtxDupACKSeq[tcpPacket.direction]) &&
                                 (tcpPacket.seq<tcpConn.rtxHighestSeq[tcpPacket.direction]))
                                 {
                                    tcpConn.rtxEWLFirstSeq[tcpPacket.direction]=tcpPacket.seq;
                                    // Logging
                                    if (logLevel >= 3)
                                    {
                                       staple.logStream << " - possible end-of-window loss first seq set to " << tcpPacket.seq;
                                    }
                                 }

                                 // Enter retransmission state (if not yet entered)
                                 if ((tcpConn.sndLossState[tcpPacket.direction]==TCPConn::NORMAL) ||
                                 (tcpConn.sndLossState[tcpPacket.direction]==TCPConn::POSSIBLE_EWL))
                                 {
                                    // Store sequence number bounds
                                    tcpConn.rtxFirstSeq[tcpPacket.direction]=tcpPacket.seq;
                                    tcpConn.rtxFirstSeqLossInfo[tcpPacket.direction]=PacketTrainTCPPacket::LOST_BMP;
                                    tcpConn.rtxHighestSeq[tcpPacket.direction]=tcpConn.highestExpectedSeq[tcpPacket.direction];
                                    // Initialize RTX dupACK and possible EWL related variables
                                    if (tcpConn.dupACKCount[1-tcpPacket.direction]>0)
                                    {
                                       // DupACK was seen
                                       tcpConn.rtxDupACKSeq[tcpPacket.direction] = tcpConn.highestACKSeen[1-tcpPacket.direction];
                                       // Invalidate possible EWL first SEQ (will be eventually filled out when a retransmission arrives)
                                       tcpConn.rtxEWLFirstSeq[tcpPacket.direction] = 0;
                                    }
                                    else
                                    {
                                       // No dupACK was seen (yet)
                                       tcpConn.rtxDupACKSeq[tcpPacket.direction] = 0;
                                       // Since we haven't seen dupACKs yet, a possible end-of-window loss may include all RTX packets
                                       tcpConn.rtxEWLFirstSeq[tcpPacket.direction] = tcpConn.rtxFirstSeq[tcpPacket.direction];
                                    }
                                    // Necessary retransmission
                                    tcpConn.sndLossState[tcpPacket.direction]=TCPConn::NECESSARY_RTX;
                                    tcpConn.rcvLossState[tcpPacket.direction]=TCPConn::HOLE;
                                    // Logging
                                    if (logLevel >= 3)
                                    {
                                       staple.logStream << " - sndLossState: NECESSARY_RTX state entered - rcvLossState: HOLE state entered";
                                    }
                                 }
                              }
                              // Reordered packet (handle as normal)
                              // -----------------------------------
                              else
                              {
                                 // By default, the packet is significant for AMP loss
                                 tmpPacket.signAMP = true;
                                 // Packets with PSH bit are not significant for BMP loss
                                 tmpPacket.signBMP = ((tcpPacket.TCPFlags&TCPPacket::PSH)==0) ? true : false;
                                 // Set reordered flag
                                 tmpPacket.reordered = true;

                                 // Place timestamp into tsReg for TS-based AMP loss verification
                                 if (tcpConn.tsLossReliable==true)
                                 {
                                    TCPConn::TSRegEntry tsRegEntry;
                                    tsRegEntry.ts[0] = ((tcpPacket.options&TCPPacket::TIMESTAMP)!=0) ? tcpPacket.tsValue : 0;
                                    tsRegEntry.ts[1] = 0;
                                    tsRegEntry.tsSeen[0] = ((tcpPacket.options&TCPPacket::TIMESTAMP)!=0) ? true : false;
                                    tsRegEntry.tsSeen[1] = false;
                                    tsRegEntry.rtxSeen = false;
                                    tcpConn.tsReg[tcpPacket.direction].insert(std::make_pair(tcpPacket.seq,tsRegEntry));
                                 }

                                 // Logging
                                 if (logLevel >= 3)
                                 {
                                    staple.logStream << " - reordered packet";
                                 }
                              }

                              // Insert packet into the packet list
                              tcpConn.packetTrains[tcpPacket.direction].InsertPacket(tmpPacket);

                              // Signal that payload processing will be necessary
                              newTCPPL = true;
                           }
                        }

                        // Detect repeated data packet resends
                        if (tcpPacket.seq == tcpConn.lastDataPacketSeq[tcpPacket.direction])
                        {
                           tcpConn.lastDataPacketSeqCount[tcpPacket.direction]++;
                        }
                        else
                        {
                           if (tcpConn.lastDataPacketSeqCount[tcpPacket.direction] >= 1)
                           {
                              if (logLevel>=3)
                              {
                                 staple.logStream << " - seq seen " << (tcpConn.lastDataPacketSeqCount[tcpPacket.direction]+1) << " times";
                              }
                           }
                           tcpConn.lastDataPacketSeq[tcpPacket.direction] = tcpPacket.seq;
                           tcpConn.lastDataPacketSeqCount[tcpPacket.direction] = 0;
                        }
                        // Update number of data packets seen
                        tcpConn.dataPacketsSeen[tcpPacket.direction]++;
                     }

                     // General tasks for a set-up TCP connection
                     // -----------------------------------------
                     // Update receiver window stats (only at ACKs, RST excluded!)
                     if (((tcpPacket.TCPFlags&TCPPacket::ACK) != 0) && ((tcpPacket.TCPFlags&TCPPacket::RST) == 0))
                     {
                        // Calculate scaled window if necessary
                        unsigned long scaledRWnd = tcpPacket.rwnd;
                        if ((tcpConn.wndScaleSeen[0]==true) && (tcpConn.wndScaleSeen[1]==true))
                        {
                           scaledRWnd <<= tcpConn.wndScaleVal[tcpPacket.direction];
                        }
                        // Update init., min., max. and mean receiver window sizes
                        if (tcpConn.rwndsSeen[tcpPacket.direction] == 0)
                        {
                           tcpConn.initRWndSize[tcpPacket.direction] = scaledRWnd;
                        }
                        if ((scaledRWnd < tcpConn.minRWndSize[tcpPacket.direction]) || (tcpConn.rwndsSeen[tcpPacket.direction] == 0))
                        {
                           tcpConn.minRWndSize[tcpPacket.direction] = scaledRWnd;
                        }
                        if ((scaledRWnd > tcpConn.maxRWndSize[tcpPacket.direction]) || (tcpConn.rwndsSeen[tcpPacket.direction] == 0))
                        {
                           tcpConn.maxRWndSize[tcpPacket.direction] = scaledRWnd;
                        }
                        tcpConn.meanRWndSize[tcpPacket.direction] = ((tcpConn.meanRWndSize[tcpPacket.direction] * tcpConn.rwndsSeen[tcpPacket.direction]) + scaledRWnd) / (tcpConn.rwndsSeen[tcpPacket.direction]+1);
                        tcpConn.rwndsSeen[tcpPacket.direction]++;
                        // Logging
                        if (logLevel >= 5)
                        {
                           staple.logStream << " - RWnd stats:" << tcpConn.minRWndSize[tcpPacket.direction] << "|" << tcpConn.meanRWndSize[tcpPacket.direction] << "|" << tcpConn.maxRWndSize[tcpPacket.direction];
                        }
                     }

                     // ACK processing (RST excluded!)
                     // ------------------------------
                     if (((tcpPacket.TCPFlags&TCPPacket::ACK) != 0) && ((tcpPacket.TCPFlags&TCPPacket::RST) == 0))
                     {
                        // DupACK update (exclude window updates!)
                        if ((tcpPacket.ack == tcpConn.highestACKSeen[tcpPacket.direction]) &&
                        (tcpPacket.TCPPLLen == 0) &&
                        (tcpPacket.rwnd == tcpConn.lastWndSize[tcpPacket.direction]) &&
                        ((tcpPacket.TCPFlags&TCPPacket::SYN) == 0) &&
                        ((tcpPacket.TCPFlags&TCPPacket::FIN) == 0))
                        {
                           // Increase dupACK count
                           tcpConn.dupACKCount[tcpPacket.direction]++;

                           // Update dupACK SEQ in RTX and POSSIBLE_EWL state (for end-of-window loss detection)
                           if (tcpConn.sndLossState[1-tcpPacket.direction]!=TCPConn::NORMAL)
                           {
                              tcpConn.rtxDupACKSeq[1-tcpPacket.direction]=tcpPacket.ack;
                              tcpConn.rtxEWLFirstSeq[1-tcpPacket.direction]=0;
                           }

                           // If retransmission necessity was not decided yet, we do it now (we may also decide it at a new ACK)
                           if ((tcpConn.sndLossState[1-tcpPacket.direction] == TCPConn::UNKNOWN_RTX) &&
                           (tcpPacket.ack == tcpConn.rtxFirstSeq[1-tcpPacket.direction]))
                           {
                              // Necessary retransmission
                              tcpConn.sndLossState[1-tcpPacket.direction]=TCPConn::NECESSARY_RTX;
                              tcpConn.rcvLossState[1-tcpPacket.direction]=TCPConn::HOLE;
                              // Logging
                              if (logLevel >= 3)
                              {
                                 staple.logStream << " - dupACK(s) for rtxFirstSeq seen, decided retransmission necessity - sndLossState: NECESSARY_RTX state entered - rcvLossState: HOLE state entered";
                              }
                           }

                           // Check for dupACKs also in UNNECESSARY_RTX state
                           if ((tcpConn.sndLossState[1-tcpPacket.direction] == TCPConn::UNNECESSARY_RTX) &&
                           (tcpPacket.ack >= tcpConn.rtxFirstSeq[1-tcpPacket.direction]) &&
                           (tcpPacket.ack < tcpConn.rtxHighestSeq[1-tcpPacket.direction]))
                           {
                              // From now on, it is a necessary retransmission
                              tcpConn.sndLossState[1-tcpPacket.direction]=TCPConn::NECESSARY_RTX;
                              tcpConn.rcvLossState[1-tcpPacket.direction]=TCPConn::HOLE;
                              // Logging
                              if (logLevel >= 3)
                              {
                                 staple.logStream << " dupACK in UNNECESSARY_RTX - sndLossState: NECESSARY_RTX state entered - rcvLossState: HOLE state entered";
                              }
                           }

                           // Logging
                           if (logLevel >= 3)
                           {
                              staple.logStream << " - dupACK #" << tcpConn.dupACKCount[tcpPacket.direction];
                           }
                        }
                        // Highest ACK processing
                        if (tcpPacket.ack > tcpConn.highestACKSeen[tcpPacket.direction])
                        {
                           // Logging
                           if (logLevel >= 3)
                           {
                              staple.logStream << " - new ACK";
                           }

                           // Process timestamps of ACKed packets (AMP loss verification)
                           if (tcpConn.tsLossReliable==true)
                           {
                              TCPConn::TSReg::iterator highIndex = tcpConn.tsReg[1-tcpPacket.direction].lower_bound(tcpPacket.ack);
                              TCPConn::TSReg::iterator actIndex = tcpConn.tsReg[1-tcpPacket.direction].begin();
                              while (actIndex != highIndex)
                              {
                                 unsigned long actSeq = (*actIndex).first;
                                 TCPConn::TSRegEntry& tsRegEntry = (*actIndex).second;
                                 // Check whether there was a retransmission
                                 if (tsRegEntry.rtxSeen == true)
                                 {
                                    // Logging
                                    if (logLevel >= 3)
                                    {
                                       staple.logStream << " - TS AMP validation: checking retransmission with seq " << actSeq;
                                    }
                                    // Check whether we have seen all three timestamps (2 DATA packets and 1 ACK)
                                    if ((tsRegEntry.tsSeen[0]==true) && (tsRegEntry.tsSeen[1]==true) && ((tcpPacket.options&TCPPacket::TIMESTAMP)!=0))
                                    {
                                       // If the original and retransmitted packet has the same TS -> necessity cannot be decided (timestamp-based AMP loss estimation becomes unreliable)
                                       if (tsRegEntry.ts[0] == tsRegEntry.ts[1])
                                       {
                                          // Logging
                                          if (logLevel >= 3)
                                          {
                                             staple.logStream << " - retransmission still ambiguous";
                                          }
                                          tcpConn.tsLossReliable = false;
                                       }
                                       else
                                       {
                                          // Is the ACK for a packet that was earlier than the retransmission?
                                          if (tcpPacket.tsEcho < tsRegEntry.ts[1])
                                          {
                                             // Yes: retransmission was unnecessary
                                             if (logLevel >= 3)
                                             {
                                                staple.logStream << " - retransmission was unnecessary";
                                             }
                                          }
                                          else
                                          {
                                             // No: retransmission was necessary (AMP loss)
                                             if (logLevel >= 3)
                                             {
                                                staple.logStream << " - retransmission was necessary (AMP loss)";
                                             }
                                             // Mark the packet as lost AMP (TS-based loss detection)
                                             std::list<PacketTrain>::iterator overlapIndex = tcpConn.packetTrains[1-tcpPacket.direction].TestPartialOverlap(actSeq,actSeq);
                                             if (overlapIndex != tcpConn.packetTrains[1-tcpPacket.direction].packetTrainList.end())
                                             {
                                                // Got the train
                                                std::list<PacketTrainTCPPacket>::iterator packetIndex = (*overlapIndex).TestPacketSeq(actSeq);
                                                if (packetIndex != (*overlapIndex).packetList.end())
                                                {
                                                   // Got the packet
                                                   (*packetIndex).lossTSInfo = PacketTrainTCPPacket::LOST_AMP_TS;
                                                }
                                                else
                                                {
                                                   // Problem (should never occur)
                                                   staple.logStream << "TS-based loss estimation sanity check failed!";
                                                }
                                             }
                                             else
                                             {
                                                // Problem (should never occur)
                                                staple.logStream << "TS-based loss estimation sanity check failed!";
                                             }
                                          }
                                       }
                                    }
                                    else
                                    {
                                       // Missing timestamps (timestamp-based AMP loss estimation becomes unreliable)
                                       if (logLevel >= 3)
                                       {
                                          staple.logStream << " - missing timestamps";
                                       }
                                       tcpConn.tsLossReliable = false;
                                    }
                                 }
                                 // Next entry
                                 TCPConn::TSReg::iterator eraseIndex = actIndex++;
                                 // Erase the processed entry
                                 tcpConn.tsReg[1-tcpPacket.direction].erase(eraseIndex);
                              }
                           }

                           // If retransmission necessity was not decided yet, we do it now (we may also decide it at dupACKs)
                           if ((tcpConn.sndLossState[1-tcpPacket.direction] == TCPConn::UNKNOWN_RTX) &&
                           (tcpPacket.ack > tcpConn.rtxFirstSeq[1-tcpPacket.direction]))
                           {
                              // Unnecessary retransmission
                              tcpConn.sndLossState[1-tcpPacket.direction]=TCPConn::UNNECESSARY_RTX;
                              // Logging
                              if (logLevel >= 3)
                              {
                                 staple.logStream << " - new ACK (covering rtxFirstSeq) seen, decided retransmission necessity - sndLossState: UNNECESSARY_RTX state entered";
                              }
                           }

                           // Partial ACK processing in HOLE state: decide AMP loss of a loss candidate (must be before exiting retransmission state)
                           if ((tcpConn.rcvLossState[1-tcpPacket.direction] == TCPConn::HOLE) &&
                           (tcpConn.highestACKSeen[tcpPacket.direction] >= tcpConn.rtxFirstSeq[1-tcpPacket.direction]))
                           {
                              // Logging
                              if (logLevel >= 3)
                              {
                                 staple.logStream << " - retransmission state: checking packet with seq " << tcpConn.highestACKSeen[tcpPacket.direction];
                              }
                              // Check the packet that the >>>last<<< ACK requested
                              std::list<PacketTrain>::iterator overlapIndex;
                              overlapIndex = tcpConn.packetTrains[1-tcpPacket.direction].TestPartialOverlap(tcpConn.highestACKSeen[tcpPacket.direction],tcpConn.highestACKSeen[tcpPacket.direction]);
                              if (overlapIndex != tcpConn.packetTrains[1-tcpPacket.direction].packetTrainList.end())
                              {
                                 // Got the train
                                 std::list<PacketTrainTCPPacket>::iterator packetIndex = (*overlapIndex).TestPacketSeq(tcpConn.highestACKSeen[tcpPacket.direction]);
                                 if (packetIndex != (*overlapIndex).packetList.end())
                                 {
                                    // Got the packet
                                    if ((*packetIndex).ampLossCandidate == true)
                                    {
                                       // Mark packet as lost AMP
                                       (*packetIndex).lossInfo = PacketTrainTCPPacket::LOST_AMP;
                                       // Logging
                                       if (logLevel >= 3)
                                       {
                                          staple.logStream << " - lost AMP";
                                       }
                                    }
                                 }
                                 else
                                 {
                                    // ACK for a non-existent packet (or in the middle of a packet)
                                    tcpConn.lossReliable = false;
                                    tcpConn.tsLossReliable = false;
                                    tcpConn.rtxDataOffset = true;
                                    // Update possible ongoing transaction as well
                                    if (tcpConn.ongoingTransaction[1-tcpPacket.direction]==true)
                                    {
                                       // Get reference to the transaction
                                       TCPTransaction& tcpTA = tcpConn.transactionList[1-tcpPacket.direction].back();
                                       tcpTA.lossReliable = false;
                                       tcpTA.rtxDataOffset = true;
                                    }
                                    // Logging
                                    if (logLevel >= 3)
                                    {
                                       staple.logStream << " - ACK offset in the history (loss unreliable)!";
                                    }
                                 }
                              }
                              else
                              {
                                 // Misteriously missing packet (because we already have a higher ACK)
                                 tcpConn.lossReliable = false;
                                 tcpConn.tsLossReliable = false;
                                 tcpConn.captureLoss = true;
                                 // Update possible ongoing transaction as well
                                 if (tcpConn.ongoingTransaction[1-tcpPacket.direction]==true)
                                 {
                                    // Get reference to the transaction
                                    TCPTransaction& tcpTA = tcpConn.transactionList[1-tcpPacket.direction].back();
                                    tcpTA.lossReliable = false;
                                    tcpTA.captureLoss = true;
                                 }
                                 // Logging
                                 if (logLevel >= 3)
                                 {
                                    staple.logStream << " - missing packet from the history (loss unreliable)!";
                                 }
                              }
                              // Corrigate loss for SACK -> all retransmissions in HOLE state are necessary if SACK is used (even if we haven't received a partial ACK)
                              if (tcpConn.SACKSeen[tcpPacket.direction]==true)
                              {
                                 // All retransmissions were necessary if there were no dupACKs or SACK was used (but: disregard SACK retransmissions of reordered packets)
                                 SACKAMPLossCheck(tcpConn,1-tcpPacket.direction,tcpConn.highestACKSeen[tcpPacket.direction],tcpPacket.ack);
                                 // Logging
                                 if (logLevel >= 3)
                                 {
                                    staple.logStream << " - SACK loss correction";
                                 }
                              }
                           }

                           // Do we have to finish retransmission state? (Must be after partial ACK processing because there we always check the >>>last<<< ACK)
                           if ((tcpConn.sndLossState[1-tcpPacket.direction] != TCPConn::NORMAL) &&
                           (tcpConn.sndLossState[1-tcpPacket.direction] != TCPConn::POSSIBLE_EWL) &&
                           (tcpPacket.ack >= tcpConn.rtxHighestSeq[1-tcpPacket.direction]))
                           {
                              // Finish retransmission state (and enter POSSIBLE_EWL state if necessary)
                              FinishRetransmissionState(tcpConn,1-tcpPacket.direction);
                           }

                           // Detect end-of-window loss (trigger: _new_ ACK in POSSIBLE_EWL state)
                           // Must be after RTX state exit & POSSIBLE_EWL state enter (since present ACK can be high enough to exit POSSIBLE_EWL state as well)
                           if ((tcpConn.sndLossState[1-tcpPacket.direction] == TCPConn::POSSIBLE_EWL) &&
                           (tcpPacket.ack > tcpConn.rtxHighestSeq[1-tcpPacket.direction]))
                           {
                              // End-of-window loss (if we still have a valid rtxELWFirstSeq)
                              if (tcpConn.rtxEWLFirstSeq[1-tcpPacket.direction]!=0)
                              {
                                 EndOfWindowLoss(tcpConn,1-tcpPacket.direction,tcpConn.rtxEWLFirstSeq[1-tcpPacket.direction],tcpConn.rtxHighestSeq[1-tcpPacket.direction]);
                              }
                              // We can return to normal state
                              tcpConn.sndLossState[1-tcpPacket.direction] = TCPConn::NORMAL;
                           }

                           // Clear dupACK count
                           tcpConn.dupACKCount[tcpPacket.direction]=0;
                           // Highest DATA ACK seen (if the ACK is not an ACK of a single FIN packet without DATA)
                           if ((tcpPacket.ack > 1) && !((tcpConn.FINSent[1-tcpPacket.direction] == true) && (tcpPacket.ack == tcpConn.highestExpectedSeq[1-tcpPacket.direction]) && (tcpPacket.ack == (tcpConn.highestACKSeen[tcpPacket.direction]+1))))
                           {
                              // Update highest DATA ACK variables (for data TP & GP calculation)
                              tcpConn.highestDataACKTime[tcpPacket.direction] = staple.actTime;
                              tcpConn.highestDataACKSeen[tcpPacket.direction] = ((tcpConn.FINSent[1-tcpPacket.direction] == true) && (tcpPacket.ack == (tcpConn.highestExpectedSeq[1-tcpPacket.direction]))) ?
                                                                                (tcpPacket.ack - 1) :
                                                                                (tcpPacket.ack);
                              // Shrink highestSeqList
                              unsigned long ipSessionByteACKed=0;
                              unsigned long ipByteACKed=0;
                              unsigned long pipeSizeACKed=0;
                              struct timeval sendTime;
                              while (!tcpConn.highestSeqList[1-tcpPacket.direction].empty())
                              {
                                 if (tcpPacket.ack > tcpConn.highestSeqList[1-tcpPacket.direction].front().seq)
                                 {
                                    ipSessionByteACKed = tcpConn.highestSeqList[1-tcpPacket.direction].front().ipSessionByte;
                                    ipByteACKed = tcpConn.highestSeqList[1-tcpPacket.direction].front().ipByte;
                                    sendTime = tcpConn.highestSeqList[1-tcpPacket.direction].front().time;
                                    pipeSizeACKed = tcpConn.highestSeqList[1-tcpPacket.direction].front().pipeSize;
                                    tcpConn.highestSeqList[1-tcpPacket.direction].pop_front();
                                 }
                                 else break;
                              }
                              if (ipSessionByteACKed!=0)
                              {
                                 tcpConn.highestDataACKIPSessionBytes[1-tcpPacket.direction]=ipSessionByteACKed;
                              }

                              // Log flightsize to the TCP TA log
                              #ifdef WRITE_TCPTA_FILES
                                 if (tcpConn.ongoingTransaction[1-tcpPacket.direction]==true)
                                 {
                                    double t = actRelTime.tv_sec + (double)actRelTime.tv_usec/1e6;
                                    if ((ipSessionByteACKed!=0) && (tcpConn.inRTTCalcState[1-tcpPacket.direction]) && (tcpPacket.ack > tcpConn.firstRTTCalcSeq[1-tcpPacket.direction]))
                                    {
                                       fprintf (tcpConn.transactionList[1-tcpPacket.direction].back().logfile, "%f 1 %u\n", t, (tcpConn.highestExpectedSeq[1-tcpPacket.direction] - tcpConn.highestDataACKSeen[tcpPacket.direction]));
                                    }
                                    else
                                    {
                                       fprintf (tcpConn.transactionList[1-tcpPacket.direction].back().logfile, "%f 0 0\n", t);
                                    }
                                 }
                              #endif

                              // Can we calculate a valid RTT (=> and pipe size)?
                              if ((ipSessionByteACKed!=0) &&
                              (tcpConn.inRTTCalcState[1-tcpPacket.direction]) &&
                              (tcpPacket.ack > tcpConn.firstRTTCalcSeq[1-tcpPacket.direction]))
                              {
                                 // Calculate preliminary RTT
                                 struct timeval rttTVal = AbsTimeDiff(staple.actTime,sendTime);
                                 double rtt = rttTVal.tv_sec + (double)rttTVal.tv_usec/1000000;

                                 // Calculate IP pipe size
                                 unsigned long pipeSize = ipSession.bytesSeen[1-tcpPacket.direction]-ipSessionByteACKed;
                                 // Pipe is full and pipe tracking was continuous (or it is the first pipe measurement)?
                                 if ((pipeSize >= CHANNELRATE_MIN_PIPE) &&
                                 ((ipSessionByteACKed < ipSession.CRLastPipeCounter[1-tcpPacket.direction]) ||
                                 (ipSession.CRLastPipeCounter[1-tcpPacket.direction]==0)))
                                 {
                                    // Pipe has become full just now?
                                    if (ipSession.CRFirstByteCandidate[1-tcpPacket.direction]==0)
                                    {
                                       // Fill in first byte candidate
                                       ipSession.CRFirstByteCandidate[1-tcpPacket.direction] = ipSession.bytesSeen[1-tcpPacket.direction];
                                       // Logging
                                       if (logLevel >= 3)
                                       {
                                          staple.logStream << " - IP pipe became full (" << ((1-tcpPacket.direction==0)?"A->B":"B->A") << ")";
                                       }
                                    }
                                    // Pipe was already full
                                    else
                                    {
                                       // First byte candidate already reached?
                                       if (ipSessionByteACKed > ipSession.CRFirstByteCandidate[1-tcpPacket.direction])
                                       {
                                          // Fill in IP channel rate first byte and ACK time if necessary
                                          if (ipSession.CRFirstByte[1-tcpPacket.direction]==0)
                                          {
                                             ipSession.CRFirstByte[1-tcpPacket.direction]=ipSessionByteACKed;
                                             ipSession.CRFirstACKTime[1-tcpPacket.direction]=staple.actTime;
                                             // Logging
                                             if (logLevel >= 3)
                                             {
                                                staple.logStream << " - IP channel rate calc started at IP counter " << ipSessionByteACKed << " (" << ((1-tcpPacket.direction==0)?"A->B":"B->A") << ")";
                                             }
                                          }
                                          // Fill in IP channel rate last byte and ACK time
                                          ipSession.CRLastByte[1-tcpPacket.direction]=ipSessionByteACKed;
                                          ipSession.CRLastACKTime[1-tcpPacket.direction]=staple.actTime;
                                          // Check whether the time or data limit has been reached
                                          #ifdef CHANNELRATE_SHORT
                                          struct timeval timeDiff = AbsTimeDiff(ipSession.CRLastACKTime[1-tcpPacket.direction],ipSession.CRFirstACKTime[1-tcpPacket.direction]);
                                          double tDiff = timeDiff.tv_sec + (double)timeDiff.tv_usec/1000000;
                                          unsigned long CRBytes = ipSession.CRLastByte[1-tcpPacket.direction]-ipSession.CRFirstByte[1-tcpPacket.direction];
                                          if ((ipSession.CRLastByte[1-tcpPacket.direction] > ipSession.CRFirstByte[1-tcpPacket.direction]) &&
                                             ((CRBytes>=CHANNELRATE_MIN_DATA) || (tDiff>=CHANNELRATE_MIN_TIME)))
                                          {
                                             // Finish IP channel rate measurement
                                             ipSession.FinishChannelRateCalc(1-tcpPacket.direction,false);
                                             ipSession.CRFirstByte[1-tcpPacket.direction]=ipSessionByteACKed;
                                             // But continue it immediately
                                             ipSession.CRFirstACKTime[1-tcpPacket.direction]=staple.actTime;
                                             // Logging
                                             if (logLevel >= 3)
                                             {
                                                staple.logStream << " - IP channel rate calc re-started (" << ((1-tcpPacket.direction==0)?"A->B":"B->A") << ")";
                                             }
                                          }
                                          #endif
                                       }
                                    }
                                 }
                                 // Pipe is not full or pipe tracking was not continuous
                                 else
                                 {
                                    // Is IP channel rate calc ongoing?
                                    if (ipSession.CRFirstByteCandidate[1-tcpPacket.direction]!=0)
                                    {
                                       // Logging
                                       if (logLevel >= 3)
                                       {
                                          staple.logStream << " - IP pipe is not full anymore (" << ((1-tcpPacket.direction==0)?"A->B":"B->A") << ")";
                                       }
                                       // Finish IP channel rate measurement
                                       ipSession.FinishChannelRateCalc(1-tcpPacket.direction,true);
                                    }
                                 }

                                 // Update RTT statistics for the TCP
                                 if (pipeSize >= CHANNELRATE_MIN_PIPE)
                                 {
                                    tcpConn.largePipeRTT[tcpPacket.direction] += rtt;
                                    tcpConn.largePipeRTTSamples[tcpPacket.direction]++;
                                 }
                                 else
                                 {
                                    tcpConn.smallPipeRTT[tcpPacket.direction] += rtt;
                                    tcpConn.smallPipeRTTSamples[tcpPacket.direction]++;
                                 }
                                 // Update min. RTT for the entire TCP connection
                                 if ((tcpConn.minRTT[tcpPacket.direction]==-1) || (tcpConn.minRTT[tcpPacket.direction]>rtt))
                                 {
                                    tcpConn.minRTT[tcpPacket.direction]=rtt;
                                 }
                                 // Update max. RTT for the entire TCP connection
                                 if (tcpConn.maxRTT[tcpPacket.direction]<rtt)
                                 {
                                    tcpConn.maxRTT[tcpPacket.direction]=rtt;
                                 }
                                 // Update min. & max. RTT for the ongoing transactions
                                 for (int TADir=0;TADir<2;TADir++)
                                 {
                                    if ((tcpConn.ongoingTransaction[TADir] == true) &&
                                    ((tcpConn.transactionList[TADir].back().minRTT[tcpPacket.direction]==-1) ||
                                    (tcpConn.transactionList[TADir].back().minRTT[tcpPacket.direction]>rtt)))
                                    {
                                       tcpConn.transactionList[TADir].back().minRTT[tcpPacket.direction] = rtt;
                                    }
                                    if ((tcpConn.ongoingTransaction[TADir] == true) &&
                                    (tcpConn.transactionList[TADir].back().maxRTT[tcpPacket.direction]<rtt))
                                    {
                                       tcpConn.transactionList[TADir].back().maxRTT[tcpPacket.direction] = rtt;
                                    }
                                 }

                                 // Update IP pipe size and pipe measurement counter
                                 ipSession.CRPipeSize[1-tcpPacket.direction]=pipeSize;
                                 ipSession.CRLastPipeCounter[1-tcpPacket.direction]=ipSession.bytesSeen[1-tcpPacket.direction];
                                 // Logging
                                 if (logLevel >= 3)
                                 {
                                    staple.logStream << " - IP pipe size: " << pipeSize << " bytes, RTT: " << rtt << "s (" << ((1-tcpPacket.direction==0)?"A->B":"B->A") << ")";
                                 }
                                 // If all data ACKed -> exit RTT calc state
                                 if (tcpPacket.ack >= tcpConn.highestExpectedSeq[1-tcpPacket.direction])
                                 {
                                    tcpConn.inRTTCalcState[1-tcpPacket.direction]=false;
                                    ipSession.DecreaseTCPsInRTTCalcState(1-tcpPacket.direction);
                                    // Logging
                                    if (logLevel >= 3)
                                    {
                                       staple.logStream << " - RTT calc state exited (all data ACKed)";
                                    }
                                 }
                              }

                              // Update transaction (only after SEQ-IPSessionByte shrinking???)
                              if (tcpConn.ongoingTransaction[1-tcpPacket.direction] == true)
                              {
                                 // Update first data ACK
                                 if ((tcpConn.transactionList[1-tcpPacket.direction].back().firstDataACKTime.tv_sec==0) && (tcpConn.transactionList[1-tcpPacket.direction].back().firstDataACKTime.tv_usec==0))
                                 {
                                    tcpConn.transactionList[1-tcpPacket.direction].back().firstDataACKTime = staple.actTime;
                                    // Store info for reverse byte counts & TP calculation
                                    tcpConn.TAFirstIPByte[1-tcpPacket.direction][tcpPacket.direction] = tcpConn.IPBytes[tcpPacket.direction]-tcpPacket.IPPktLen;
                                    tcpConn.TAFirstIPSessionByte[1-tcpPacket.direction][tcpPacket.direction] = ipSession.bytesSeen[tcpPacket.direction]-tcpPacket.IPPktLen;
                                    // First DATA ACK candidate for the TCP TA TP report
                                    tcpConn.transactionList[1-tcpPacket.direction].back().reportFirstTime = staple.actTime;
                                    tcpConn.transactionList[1-tcpPacket.direction].back().reportFirstIPByte = tcpConn.TAFirstIPByte[1-tcpPacket.direction][1-tcpPacket.direction];
                                    tcpConn.transactionList[1-tcpPacket.direction].back().reportFirstIPSessionByte = tcpConn.TAFirstIPSessionByte[1-tcpPacket.direction][1-tcpPacket.direction];
                                    if (logLevel >= 3)
                                    {
                                       staple.logStream << " - TCP TA report first ACK candidate stored";
                                    }
                                 }
                                 // Not the first data ACK (but any consequent ACK)
                                 else
                                 {
                                    // Calculate time difference to the first DATA ACK
                                    struct timeval ackTimeDiff = AbsTimeDiff(staple.actTime,tcpConn.transactionList[1-tcpPacket.direction].back().firstDataACKTime);
                                    double ackTDiff = ackTimeDiff.tv_sec + (double)ackTimeDiff.tv_usec/1000000;
                                    // Update the first ACK of the TCP TA report (if needed)
                                    if ((tcpConn.transactionList[1-tcpPacket.direction].back().reportStartValid==false) && (ipSessionByteACKed>0))
                                    {
                                       if (ackTDiff<ACK_COMPRESSION_TIME)
                                       {
                                          // ACK compression: update the candidate ACK info
                                          tcpConn.transactionList[1-tcpPacket.direction].back().reportFirstTime = staple.actTime;
                                          tcpConn.transactionList[1-tcpPacket.direction].back().reportFirstIPByte = ipByteACKed;
                                          tcpConn.transactionList[1-tcpPacket.direction].back().reportFirstIPSessionByte = ipSessionByteACKed;
                                          if (logLevel >= 3)
                                          {
                                             staple.logStream << " - ACK compression: storing new TCP TA report first ACK candidate";
                                          }
                                       }
                                       else
                                       {
                                          // No ACK compression: the previous ACK is the right one!
                                          tcpConn.transactionList[1-tcpPacket.direction].back().reportStartValid=true;
                                          if (logLevel >= 3)
                                          {
                                             staple.logStream << " - TCP TA report first ACK validated";
                                          }
                                          // If slow start end is already reached (the first packet was retransmitted) corrigate ssEnd (so that it will not be earlier than first report start time)
                                          if ((tcpConn.transactionList[1-tcpPacket.direction].back().ssEndACKTime.tv_sec!=0) || (tcpConn.transactionList[1-tcpPacket.direction].back().ssEndACKTime.tv_usec!=0))
                                          {
                                             // Slow start end is first report start time
                                             tcpConn.transactionList[1-tcpPacket.direction].back().ssEndIPSessionBytes = tcpConn.transactionList[1-tcpPacket.direction].back().reportFirstIPSessionByte;
                                             tcpConn.transactionList[1-tcpPacket.direction].back().ssEndACKTime = tcpConn.transactionList[1-tcpPacket.direction].back().reportFirstTime;
                                             tcpConn.transactionList[1-tcpPacket.direction].back().ssEndACKTime.tv_usec += 1000; // not to confuse etambor scripts
                                             tcpConn.transactionList[1-tcpPacket.direction].back().ssEndValid=true;
                                             if (logLevel >= 3)
                                             {
                                                staple.logStream << " - slow start end shifted past the TCP TA report first ACK";
                                             }
                                          }
                                       }
                                    }
                                    // Slow start end candidate already found?
                                    if (((tcpConn.transactionList[1-tcpPacket.direction].back().ssEndACKTime.tv_sec!=0) || (tcpConn.transactionList[1-tcpPacket.direction].back().ssEndACKTime.tv_usec!=0)) &&
                                       (tcpConn.transactionList[1-tcpPacket.direction].back().ssEndValid==false) && (ipSessionByteACKed>0))
                                    {
                                       ackTimeDiff = AbsTimeDiff(staple.actTime,tcpConn.transactionList[1-tcpPacket.direction].back().ssEndACKTime);
                                       ackTDiff = ackTimeDiff.tv_sec + (double)ackTimeDiff.tv_usec/1000000;
                                       // Check for ACK compression at the slow start end
                                       if (ackTDiff<ACK_COMPRESSION_TIME)
                                       {
                                          // ACK compression: we have a new candidate
                                          tcpConn.transactionList[1-tcpPacket.direction].back().ssEndIPSessionBytes = ipSessionByteACKed;
                                          tcpConn.transactionList[1-tcpPacket.direction].back().ssEndACKTime = staple.actTime;
                                          if (logLevel >= 3)
                                          {
                                             staple.logStream << " - ACK compression: storing new slow start end candidate";
                                          }
                                       }
                                       else
                                       {
                                          // No ACK compression: the previous ACK is the right one!
                                          tcpConn.transactionList[1-tcpPacket.direction].back().ssEndValid=true;
                                          if (logLevel >= 3)
                                          {
                                             staple.logStream << " - slow start end validated";
                                          }
                                       }
                                    }
                                 }
                                 // Update highest ACK related variables (only if we have IPSessionByteACKed - we skip lossy sequences at the end)
                                 if (ipSessionByteACKed!=0)
                                 {
                                    // Update ssEndACKTime
                                    if (((tcpConn.transactionList[1-tcpPacket.direction].back().ssEndACKTime.tv_sec==0) &&
                                    (tcpConn.transactionList[1-tcpPacket.direction].back().ssEndACKTime.tv_usec==0)) &&
                                    (tcpConn.highestExpectedDataSeq[1-tcpPacket.direction]-tcpConn.highestDataACKSeen[tcpPacket.direction]>TCPTA_SSMAXFS))
                                    {
                                       // Logging
                                       if (logLevel >= 3)
                                       {
                                          staple.logStream << " - slow start end reached (flight size)";
                                       }

                                       tcpConn.transactionList[1-tcpPacket.direction].back().ssEndACKTime = staple.actTime;
                                       tcpConn.transactionList[1-tcpPacket.direction].back().ssEndIPSessionBytes = ipSessionByteACKed;
                                    }
                                    if (((tcpConn.transactionList[1-tcpPacket.direction].back().ssEndACKTime.tv_sec==0) &&
                                    (tcpConn.transactionList[1-tcpPacket.direction].back().ssEndACKTime.tv_usec==0)) &&
                                    (tcpPacket.ack >= tcpConn.transactionList[1-tcpPacket.direction].back().firstDataPacketSeq + TCPTA_SSTHRESH))
                                    {
                                       // Logging
                                       if (logLevel >= 3)
                                       {
                                          staple.logStream << " - slow start end reached (byte limit)";
                                       }
                                       tcpConn.transactionList[1-tcpPacket.direction].back().ssEndACKTime = staple.actTime;
                                       tcpConn.transactionList[1-tcpPacket.direction].back().ssEndIPSessionBytes = ipSessionByteACKed;
                                    }
                                    // Update last but highest data ACK
                                    tcpConn.transactionList[1-tcpPacket.direction].back().lastButHighestDataACKTime = tcpConn.transactionList[1-tcpPacket.direction].back().highestDataACKTime;
                                    tcpConn.transactionList[1-tcpPacket.direction].back().lastButHighestDataACKSeen = tcpConn.transactionList[1-tcpPacket.direction].back().highestDataACKSeen;
                                    // Update highest data ACK
                                    tcpConn.transactionList[1-tcpPacket.direction].back().highestDataACKTime = staple.actTime;
                                    tcpConn.transactionList[1-tcpPacket.direction].back().highestDataACKSeen = tcpConn.highestDataACKSeen[tcpPacket.direction];
                                    // Update IPSessionBytes
                                    tcpConn.transactionList[1-tcpPacket.direction].back().lastButHighestACKedIPSessionByte[1-tcpPacket.direction] = tcpConn.transactionList[1-tcpPacket.direction].back().highestACKedIPSessionByte[1-tcpPacket.direction];
                                    tcpConn.transactionList[1-tcpPacket.direction].back().lastButHighestACKedIPSessionByte[tcpPacket.direction] = tcpConn.transactionList[1-tcpPacket.direction].back().highestACKedIPSessionByte[tcpPacket.direction];
                                    tcpConn.transactionList[1-tcpPacket.direction].back().highestACKedIPSessionByte[1-tcpPacket.direction] = ipSessionByteACKed;
                                    tcpConn.transactionList[1-tcpPacket.direction].back().highestACKedIPSessionByte[tcpPacket.direction] = ipSession.bytesSeen[tcpPacket.direction];
                                    tcpConn.transactionList[1-tcpPacket.direction].back().lastButHighestACKedIPByte[1-tcpPacket.direction] = tcpConn.transactionList[1-tcpPacket.direction].back().highestACKedIPByte[1-tcpPacket.direction];
                                    tcpConn.transactionList[1-tcpPacket.direction].back().lastButHighestACKedIPByte[tcpPacket.direction] = tcpConn.transactionList[1-tcpPacket.direction].back().highestACKedIPByte[tcpPacket.direction];
                                    tcpConn.transactionList[1-tcpPacket.direction].back().highestACKedIPByte[1-tcpPacket.direction] = ipByteACKed;
                                    tcpConn.transactionList[1-tcpPacket.direction].back().highestACKedIPByte[tcpPacket.direction] = tcpConn.IPBytes[tcpPacket.direction];
                                    // Last but highest DATA ACK already seen?
                                    if ((tcpConn.transactionList[1-tcpPacket.direction].back().lastButHighestDataACKTime.tv_sec!=0) || (tcpConn.transactionList[1-tcpPacket.direction].back().lastButHighestDataACKTime.tv_usec!=0))
                                    {
                                       struct timeval ackTimeDiff = AbsTimeDiff(tcpConn.transactionList[1-tcpPacket.direction].back().lastButHighestDataACKTime, tcpConn.transactionList[1-tcpPacket.direction].back().highestDataACKTime);
                                       double ackTDiff = ackTimeDiff.tv_sec + (double)ackTimeDiff.tv_usec/1000000;
                                       // ACK compression?
                                       if (ackTDiff>=ACK_COMPRESSION_TIME)
                                       {
                                          // No ACK compression: update TCP TA report end time
                                          tcpConn.transactionList[1-tcpPacket.direction].back().reportLastTime = tcpConn.transactionList[1-tcpPacket.direction].back().lastButHighestDataACKTime;
                                          tcpConn.transactionList[1-tcpPacket.direction].back().reportLastIPByte = tcpConn.transactionList[1-tcpPacket.direction].back().lastButHighestACKedIPByte[1-tcpPacket.direction];
                                          tcpConn.transactionList[1-tcpPacket.direction].back().reportLastIPSessionByte = tcpConn.transactionList[1-tcpPacket.direction].back().lastButHighestACKedIPSessionByte[1-tcpPacket.direction];
                                          if (logLevel >= 3)
                                          {
                                             staple.logStream << " - TCP TA report end updated (no ACK compression)";
                                          }
                                       }
                                    }
                                    // Print transaction progress report periodically (if we have a valid report start & end time)
                                    if (((tcpConn.transactionList[1-tcpPacket.direction].back().reportLastTime.tv_sec!=0) || (tcpConn.transactionList[1-tcpPacket.direction].back().reportLastTime.tv_usec!=0)) &&
                                    (tcpConn.transactionList[1-tcpPacket.direction].back().reportStartValid==true))
                                    {
                                       struct timeval timeDiff;
                                       if ((tcpConn.transactionList[1-tcpPacket.direction].back().lastReport.time.tv_sec==0) && (tcpConn.transactionList[1-tcpPacket.direction].back().lastReport.time.tv_usec==0))
                                       {
                                          // First progress report
                                          timeDiff = AbsTimeDiff(tcpConn.transactionList[1-tcpPacket.direction].back().reportLastTime, tcpConn.transactionList[1-tcpPacket.direction].back().reportFirstTime);
                                       }
                                       else
                                       {
                                          // Not the first progress report
                                          timeDiff = AbsTimeDiff(tcpConn.transactionList[1-tcpPacket.direction].back().reportLastTime, tcpConn.transactionList[1-tcpPacket.direction].back().lastReport.time);
                                       }
                                       double tDiff = timeDiff.tv_sec + (double)timeDiff.tv_usec/1000000;
                                       if (tDiff >= TCPTA_ROP)
                                       {
                                          PrintTCPTAStatistics(tcpIndex,tcpConn.transactionList[1-tcpPacket.direction].back(),1-tcpPacket.direction,false,false);
                                       }
                                    }
                                 }
                                 if ((tcpConn.ongoingTransaction[1-tcpPacket.direction]==true) && (tcpConn.sndLossState[1-tcpPacket.direction]==TCPConn::NORMAL))
                                 {
                                    // Get reference to the transaction
                                    TCPTransaction& tcpTA = tcpConn.transactionList[1-tcpPacket.direction].back();

                                    struct timeval timeDiff = AbsTimeDiff(staple.actTime,tcpTA.flightSizeLastTime);
                                    double tDiff = ((tcpTA.flightSizeLastTime.tv_sec==0) && (tcpTA.flightSizeLastTime.tv_usec==0)) ? 0 :
                                                   (timeDiff.tv_sec + (double)timeDiff.tv_usec/1000000);

                                    tcpTA.flightSizeMean += tDiff * tcpTA.flightSizeLastValue;
                                    tcpTA.flightSizeLastValue = tcpConn.highestExpectedDataSeq[1-tcpPacket.direction] - tcpConn.highestDataACKSeen[tcpPacket.direction];
                                    tcpTA.flightSizeLastTime = staple.actTime;
                                    tcpTA.flightSizeTimeSum += tDiff;
                                 }
                                 // Finish transaction if necessary
                                 if ((tcpPacket.ack >= tcpConn.highestExpectedSeq[1-tcpPacket.direction]) &&
                                 (((tcpConn.nonPSHDataPacketSeen[1-tcpPacket.direction] == true) && (tcpConn.transactionList[1-tcpPacket.direction].back().highestSeqIPLength <= tcpConn.maxDataPacketIPLen[1-tcpPacket.direction]-40)) ||
                                 (tcpConn.nonPSHDataPacketSeen[1-tcpPacket.direction] == false)))
                                 {
                                    FinishTCPTransaction(tcpIndex,ipSession,1-tcpPacket.direction);
                                 }
                              }
                              // TCP ACKed payload processing (e.g., FLV)
                              TCPPayloadACKed(tcpIndex,tcpPacket);
                              // Advance payload cache with the processed payload
                              tcpConn.payloadCache[1-tcpPacket.direction].SetFirstSeq(tcpConn.payloadPos[1-tcpPacket.direction]);
                           }
                           // Update highest ACK seen
                           tcpConn.highestACKSeen[tcpPacket.direction] = tcpPacket.ack;
                        }
                     }

                     // Update highest expected SEQ (RST & SYN & zero payload excluded, FIN included)
                     unsigned long actSeq = tcpPacket.seq + tcpPacket.TCPPLLen + (((tcpPacket.TCPFlags&TCPPacket::FIN) != 0) ? 1 : 0);
                     if ((actSeq > tcpConn.highestExpectedSeq[tcpPacket.direction]) &&
                     ((tcpPacket.TCPPLLen > 0) || ((tcpPacket.TCPFlags&TCPPacket::FIN) != 0)) &&
                     ((tcpPacket.TCPFlags&TCPPacket::RST) == 0) &&
                     ((tcpPacket.TCPFlags&TCPPacket::SYN) == 0))
                     {
                        tcpConn.highestExpectedSeq[tcpPacket.direction] = actSeq;
                        tcpConn.highestExpectedDataSeq[tcpPacket.direction] = (((tcpPacket.TCPFlags&TCPPacket::FIN) != 0) ? (actSeq-1) : (actSeq));
                     }

                     // Handle FIN
                     if ((tcpPacket.TCPFlags&TCPPacket::FIN) != 0)
                     {
                        // Update FIN state
                        tcpConn.FINSent[tcpPacket.direction]=true;
                     }
                     // Check whether the TCP connection has to be released
                     if ((tcpConn.FINSent[0] == true) && (tcpConn.FINSent[1] == true) && (tcpConn.highestACKSeen[0] >= tcpConn.highestExpectedSeq[1]) && (tcpConn.highestACKSeen[1] >= tcpConn.highestExpectedSeq[0]))
                     {
                        tcpConn.termination = TCPConn::TERM_FIN;
                        releaseTCP = true;
                     }
                  }
               }
            }

            // General tasks for a TCP connection (either set up successfully/not yet set up)
            // ------------------------------------------------------------------------------
            if (tcpIndex != staple.tcpConnReg.end())
            {
               TCPConn &tcpConn = tcpIndex->second;

               // Update SACK permitted & SACK block seen status
               if ((tcpPacket.options&TCPPacket::SACK)!=0) tcpConn.SACKSeen[tcpPacket.direction] = true;
               if ((tcpPacket.options&TCPPacket::SACKPERM)!=0) tcpConn.SACKPermitted[tcpPacket.direction] = true;

               // Update timestamp seen status
               if ((tcpPacket.options&TCPPacket::TIMESTAMP)!=0) tcpConn.TSSeen[tcpPacket.direction] = true;

               // Store last packet time
               tcpConn.lastPacketTime[tcpPacket.direction] = staple.actTime;

               // Store last window size (for dupACK<->window update differentiation)
               tcpConn.lastWndSize[tcpPacket.direction] = tcpPacket.rwnd;

               // Increase number of seen packets
               tcpConn.packetsSeen[tcpPacket.direction]++;

               // Handle RST
               if ((tcpPacket.TCPFlags&TCPPacket::RST) != 0)
               {
                  tcpConn.termination = TCPConn::TERM_RST;
                  releaseTCP = true;
               }

               // Apply history size limits
               ApplyHistorySizeLimits(tcpIndex,tcpPacket.direction);

               // TCP level logging is finished
               if (logLevel>=3) staple.logStream << "\n";

               // TCP payload processing
               // ----------------------
               if (tcpPacket.TCPPLLen>0)
               {
                  // Assemble TCP payload for processing it later
                  AssembleTCPPayload(tcpIndex, tcpPacket);
               }

               // TCP packet processing on HTTP layer
               // -----------------------------------
               httpEngine.processPacket(tcpPacket);

               // Write PCAP dump if needed
               if (staple.outputDumpGiven == true)
               {
                  if (((tcpConn.contentFound[1]==false) && (tcpConn.payloadPos[1]<MAX_SIGNATURE_LIMIT)) || (tcpConn.writeDump==true))
                  {
                     staple.packetDumpFile.WriteActualPacket();
                  }
               }

               // Release TCP connection if needed
               if (releaseTCP == true)
               {
                  ReleaseTCPConnection(tcpIndex);
               }
            }
         }

         if (((ipPacket.l3Type&L3Packet::TCP) == 0) && ((ipPacket.l3Type&L3Packet::UDP) == 0))
         {
            // Non-TCP and non-UDP IP packets
            // ------------------------------
            IPPacket& ipPacket = *((IPPacket*)pL3Packet);
         }
      }

      // Logging (only matching IP packets)
      if ((staple.logLevel >= 3) && ((pL3Packet->l3Type&L3Packet::IP) != 0))
      {
         if (((IPPacket*)pL3Packet)->match == true)
         {
            staple.logStream << "   ";
            pL3Packet->Print(staple.logStream);
         }
      }
   }
}

void Parser::HighestSeqTCPDataPacket(TCPPacket& tcpPacket, TCPConnReg::iterator& tcpHighIndex, IPSession& ipSession)
{
   // Get TCP connection
   TCPConn& tcpConn = tcpHighIndex->second;
   const TCPConnId& tcpConnId = tcpHighIndex->first;

   // Start new TCP transaction if necessary
   if ((tcpPacket.seq == tcpConn.highestACKSeen[1-tcpPacket.direction]) &&
      (tcpConn.ongoingTransaction[tcpPacket.direction] == false))
   {
      // Create and insert new transaction into the list
      TCPTransaction newTA;
      newTA.Init();
      newTA.firstDataPacketTime = staple.actTime;
      newTA.firstDataPacketSeq = tcpPacket.seq;
      tcpConn.TAFirstIPByte[tcpPacket.direction][tcpPacket.direction] = tcpConn.IPBytes[tcpPacket.direction]-tcpPacket.IPPktLen;
      tcpConn.TAFirstIPSessionByte[tcpPacket.direction][tcpPacket.direction] = ipSession.bytesSeen[tcpPacket.direction]-tcpPacket.IPPktLen;
      tcpConn.TAFirstSmallPipeRTT[tcpPacket.direction][0] = tcpConn.smallPipeRTT[0];
      tcpConn.TAFirstSmallPipeRTT[tcpPacket.direction][1] = tcpConn.smallPipeRTT[1];
      tcpConn.TAFirstSmallPipeRTTSamples[tcpPacket.direction][0] = tcpConn.smallPipeRTTSamples[0];
      tcpConn.TAFirstSmallPipeRTTSamples[tcpPacket.direction][1] = tcpConn.smallPipeRTTSamples[1];
      tcpConn.TAFirstLargePipeRTT[tcpPacket.direction][0] = tcpConn.largePipeRTT[0];
      tcpConn.TAFirstLargePipeRTT[tcpPacket.direction][1] = tcpConn.largePipeRTT[1];
      tcpConn.TAFirstLargePipeRTTSamples[tcpPacket.direction][0] = tcpConn.largePipeRTTSamples[0];
      tcpConn.TAFirstLargePipeRTTSamples[tcpPacket.direction][1] = tcpConn.largePipeRTTSamples[1];
      bool firstTA=tcpConn.transactionList[tcpPacket.direction].empty();

      // Open TCP TA file
      #ifdef WRITE_TCPTA_FILES
         char ta_name[200];
         sprintf(ta_name, "%s/%u.%u.%u.%u_%u-%u.%u.%u.%u_%u-%u.TAlog",perfmonDirName.c_str(),tcpConnId.netAIP.byte[3], tcpConnId.netAIP.byte[2], tcpConnId.netAIP.byte[1], tcpConnId.netAIP.byte[0],tcpConnId.netAPort,tcpConnId.netBIP.byte[3], tcpConnId.netBIP.byte[2], tcpConnId.netBIP.byte[1], tcpConnId.netBIP.byte[0],tcpConnId.netBPort,tcpPacket.seq);
         newTA.logfile = fopen(ta_name,"w");
         if (newTA.logfile==NULL)
         {
            printf("Error opening log file %s\n",strerror(errno));
            exit(-1);
         }
      #endif

      // HACK: check for BitTorrent pieces
      if ((tcpPacket.TCPPLLen>=14) && (tcpPacket.payloadSavedLen>=6) &&
      (tcpPacket.payload[0]==0x00) &&
      (tcpPacket.payload[3]==0x09) &&
      (tcpPacket.payload[4]==0x07) &&
      (tcpPacket.payload[5]==0x00))
      {
         tcpConn.isTorrent = true;
         if (staple.logLevel >= 3)
         {
            staple.logStream << " - BitTorrent piece found";
         }
      }

      // Add last HTTP request URI, host, and content-type to the transaction
      newTA.lastRevReqURI = tcpConn.lastReqURI[1-tcpPacket.direction];
      newTA.lastRevReqHost = tcpConn.lastReqHost[1-tcpPacket.direction];
      newTA.contentType = tcpConn.contentType;

      tcpConn.transactionList[tcpPacket.direction].push_back(newTA);
      tcpConn.ongoingTransaction[tcpPacket.direction] = true;
      // Logging
      if (staple.logLevel >= 3)
      {
         staple.logStream << " - Transaction begins " << ((tcpPacket.direction==0)?"(A->B)":"(B->A)");
      }
   }

   // Update transaction with the highest seq. IP packet size & TCP flags (to determine end)
   if (tcpConn.ongoingTransaction[tcpPacket.direction] == true)
   {
      tcpConn.transactionList[tcpPacket.direction].back().highestSeqIPLength = tcpPacket.IPPktLen;
      tcpConn.transactionList[tcpPacket.direction].back().highestSeqTCPFlags = tcpPacket.TCPFlags;
   }

   // Enter RTT calc state
   if (tcpConn.inRTTCalcState[tcpPacket.direction]==false)
   {
      tcpConn.inRTTCalcState[tcpPacket.direction]=true;
      ipSession.IncreaseTCPsInRTTCalcState(tcpPacket.direction);
      // Logging
      if (staple.logLevel >= 3)
      {
         staple.logStream << " - RTT calc state entered";
      }
   }

   // Add entry to the highest SEQ list (for RTT, channel rate calc.)
   TCPConn::HighestSeqListEntry entry;
   entry.seq = tcpPacket.seq;
   entry.time = staple.actTime;
   entry.ipSessionByte = ipSession.bytesSeen[tcpPacket.direction];
   entry.ipByte = tcpConn.IPBytes[tcpPacket.direction];
   entry.ipId = tcpPacket.IPId;
   entry.pipeSize = (tcpConn.inRTTCalcState[tcpPacket.direction]==true) ? (ipSession.bytesSeen[tcpPacket.direction]-tcpConn.highestDataACKIPSessionBytes[tcpPacket.direction]) : 0;
   tcpConn.highestSeqList[tcpPacket.direction].push_back(entry);

   // Calculate average flightsize
   if ((tcpConn.ongoingTransaction[tcpPacket.direction]==true) && (tcpConn.sndLossState[tcpPacket.direction]==TCPConn::NORMAL))
   {
      // Get reference to the transaction
      TCPTransaction& tcpTA = tcpConn.transactionList[tcpPacket.direction].back();

      struct timeval timeDiff = AbsTimeDiff(staple.actTime,tcpTA.flightSizeLastTime);
      double tDiff = ((tcpTA.flightSizeLastTime.tv_sec==0) && (tcpTA.flightSizeLastTime.tv_usec==0)) ? 0 :
                     (timeDiff.tv_sec + (double)timeDiff.tv_usec/1000000);

      tcpTA.flightSizeMean += tDiff * tcpTA.flightSizeLastValue;
      tcpTA.flightSizeLastValue = (tcpConn.highestExpectedDataSeq[tcpPacket.direction]-tcpConn.highestDataACKSeen[1-tcpPacket.direction]);
      tcpTA.flightSizeLastTime = staple.actTime;
      tcpTA.flightSizeTimeSum += tDiff;
   }
}

void Parser::AssembleTCPPayload(TCPConnReg::iterator& tcpAssIndex, TCPPacket& tcpPacket)
{
   // Get TCP connection
   TCPConn& tcpConn = tcpAssIndex->second;
   const TCPConnId& tcpConnId = tcpAssIndex->first;

   // Only web ports will be analyzed
   if (!((tcpConnId.netBPort == 80) || (tcpConnId.netBPort == 81) || (tcpConnId.netBPort == 8000) || (tcpConnId.netBPort == 8001) ||
      (tcpConnId.netBPort == 8080) || (tcpConnId.netBPort == 8888) || (tcpConnId.netBPort == 3128)))
   {
      return;
   }

// ethpbo HACK CPU
/*
   // Insert packet to the payload range list
   tcpConn.payloadRanges[tcpPacket.direction].InsertRange(tcpPacket.seq, tcpPacket.seq+tcpPacket.TCPPLLen);
*/
   // At the first DATA packet -> allocate payload cache
   if (tcpConn.dataPacketsSeen[tcpPacket.direction]==1)
   {
      tcpConn.payloadCache[tcpPacket.direction].Allocate(TCP_PL_CACHE_INIT_SIZE,1);
   }
   // Copy payload to the cache
   unsigned short copyLen = (tcpPacket.payloadSavedLen < tcpPacket.TCPPLLen) ? tcpPacket.payloadSavedLen : tcpPacket.TCPPLLen;
   while (!tcpConn.payloadCache[tcpPacket.direction].CopyTo(tcpPacket.seq, copyLen, (unsigned char*)(tcpPacket.payload)))
   {
      // If the cache is used for payload processing, try expand it to accomodate new data
      if (tcpConn.payloadCache[tcpPacket.direction].size>0)
      {
         // Logging
         if (staple.logLevel >= FLVLOGLEVEL)
         {
            staple.logStream << " - payload buffer too small";
         }
         // Can we expand it (without reaching the limit)?
         if ((2*tcpConn.payloadCache[tcpPacket.direction].size) <= TCP_PL_CACHE_MAX_SIZE)
         {
            tcpConn.payloadCache[tcpPacket.direction].Extend(2*tcpConn.payloadCache[tcpPacket.direction].size);
            // Logging
            if (staple.logLevel >= FLVLOGLEVEL)
            {
               staple.logStream << " - doubling it";
            }
         }
         else
         {
            // Stop payload processing
            tcpConn.payloadCache[tcpPacket.direction].Free();
            // Logging
            if (staple.logLevel >= FLVLOGLEVEL)
            {
               staple.logStream << " - maximum size reached (payload processing stopped)";
            }
            break;
         }
      }
      // Cache is not used
      else
      {
         break;
      }
   }
}

void Parser::TCPPayloadACKed(TCPConnReg::iterator& tcpACKIndex, TCPPacket& tcpPacket)
{
   // Get TCP connection
   TCPConn& tcpConn = tcpACKIndex->second;
   const TCPConnId& tcpConnId = tcpACKIndex->first;

   unsigned long& plPos = tcpConn.payloadPos[1-tcpPacket.direction];
   CircularBuffer& plCache = tcpConn.payloadCache[1-tcpPacket.direction];

   // Payload processing not possible
   if (plCache.size==0) return;

   // Payload processing not needed anymore (no signatures found in the first MAX_SIGNATURE_LIMIT bytes)
   if ((tcpConn.contentFound[1-tcpPacket.direction]==false) && (plPos>=MAX_SIGNATURE_LIMIT))
   {
      // Free up payload cache if not yet done
      if (plCache.size>0) plCache.Free();
      return;
   }

   // Sanity check of ACK - DATA reordering (if an ACK covers a not yet seen DATA packet)
   if (tcpConn.highestDataACKSeen[tcpPacket.direction] > tcpConn.highestExpectedDataSeq[1-tcpPacket.direction])
   {
      // Logging
      if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - payload processing: not yet seen payload ACKed (will retry at a higher ACK)";
      return;
   }

   // TBD: check for monitoring loss (with payloadRanges)

   FLVStats& flvStats = staple.flvStats;
   MP4Stats& mp4Stats = staple.mp4Stats;
   
   // Content signature search
   // ------------------------
   if (tcpConn.contentFound[1-tcpPacket.direction]==false)
   {
      # define MAX_SIGNATURE_LENGTH 8
      while ((plPos<MAX_SIGNATURE_LIMIT) && (tcpConn.highestDataACKSeen[tcpPacket.direction]>=(plPos+MAX_SIGNATURE_LENGTH)))
      {
         // Look for MP4 signature in the first MP4_SIGNATURE_LIMIT bytes
         if ((plPos<MP4_SIGNATURE_LIMIT) && (plCache[plPos]=='f') && (plCache[plPos+1]=='t') && (plCache[plPos+2]=='y') && (plCache[plPos+3]=='p') &&
         (plCache[plPos+4]=='m') && (plCache[plPos+5]=='p') && (plCache[plPos+6]=='4') && (plCache[plPos+7]=='2'))
         {
            // Signature found
            tcpConn.mp4[1-tcpPacket.direction].found=true;
            tcpConn.contentFound[1-tcpPacket.direction]=true;
            mp4Stats.sessionsSeen[1-tcpPacket.direction]++;
            // Free up payload cache (we do not decode MP4 yet)
            if (plCache.size>0) plCache.Free();
            // Logging
            if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - MP4 signature found";
staple.logStream << "MP4 video starts\n";
tcpConnId.Print(staple.logStream);
staple.logStream << " - URI: " << tcpConn.lastReqURI[tcpPacket.direction] << "\n";
            break;
         }
         // Look for FLV signature in the first FLV_SIGNATURE_LIMIT bytes
         if ((plPos<FLV_SIGNATURE_LIMIT) && (plCache[plPos]=='F') && (plCache[plPos+1]=='L') && (plCache[plPos+2]=='V'))
         {
            // Signature found
            tcpConn.flv[1-tcpPacket.direction].found=true;
            tcpConn.contentFound[1-tcpPacket.direction]=true;
            flvStats.sessionsSeen[1-tcpPacket.direction]++;
            // Store FLV signature position & FLV start time
            tcpConn.flv[1-tcpPacket.direction].startPos=plPos;
            tcpConn.flv[1-tcpPacket.direction].startTime=staple.actTime;
            // Increase payload cache size (to accomodate whole FLV frames later)
            plCache.Extend(TCP_PL_CACHE_NORMAL_SIZE);
            // We processed the FLV signature
            plPos += 3;
            // Write PCAP for FLV TCPs
            tcpConn.writeDump=true;
            // Logging
            if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - FLV signature found";
staple.logStream << "Flash video starts\n";
tcpConnId.Print(staple.logStream);
staple.logStream << " - URI: " << tcpConn.lastReqURI[tcpPacket.direction] << "\n";
            break;
         }
         plPos++;
      }
   }

   // ==============
   // FLV processing
   // ==============
   // FLV BODY processing
   // -------------------
   if (tcpConn.flv[1-tcpPacket.direction].found==true)
   {
      FLV& flv = tcpConn.flv[1-tcpPacket.direction];
      // Decode FLV header
      // -----------------
      if (plPos == (flv.startPos+3))
      {
         // Check if we have all the header data in the payload cache
         if (tcpConn.highestDataACKSeen[tcpPacket.direction] >= plPos+6)
         {
            // Logging
            if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - FLV header";

            int version = plCache[plPos++];
            if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - version " << version;
            // Unknown version (possible false positive for FLV signature)
            if (version != 1)
            {
               // Stop & revert FLV processing
               tcpConn.flv[1-tcpPacket.direction].found=false;
               flvStats.sessionsSeen[1-tcpPacket.direction]--;
               if (plCache.size>0) plCache.Free();
               // Logging
               if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " (unknown)";
               return;
            }

            int type = plCache[plPos++];
            if ((type&4) && (staple.logLevel >= FLVLOGLEVEL)) staple.logStream << " - audio present";
            if ((type&1) && (staple.logLevel >= FLVLOGLEVEL)) staple.logStream << " - video present";

            unsigned long dataOffset = (unsigned long)(plCache[plPos++])<<24;
            dataOffset |= (unsigned long)(plCache[plPos++])<<16;
            dataOffset |= (unsigned long)(plCache[plPos++])<<8;
            dataOffset |= (unsigned long)(plCache[plPos++]);
            if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - dataOffset " << dataOffset;

            // Sanity check of dataOffset
            if (dataOffset > 1e7)
            {
               // Stop & revert FLV processing
               tcpConn.flv[1-tcpPacket.direction].found=false;
               flvStats.sessionsSeen[1-tcpPacket.direction]--;
               if (plCache.size>0) plCache.Free();
               // Logging
               if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - insane start offset (possible capture loss/reordering)";
staple.logStream << "Insane start offset: " <<  dataOffset << " (possible capture loss/reordering)\n";
               return;
            }

            // Jump to the first FLV frame
            plPos += (dataOffset-9);
         }
         else
         {
            // Wait for more data
            return;
         }
      }

      // Process FLV frames
      // ------------------
      // Can we decode a complete FLV frame TAG header? (4 bytes previous TAG size + 11 bytes TAG header + 1 byte video/audio header)
      while (tcpConn.highestDataACKSeen[tcpPacket.direction] >= plPos+16)
      {
         // Frame decoding
         // --------------
         // Determine relative frame transport timestamp
         struct timeval packetTSTV = AbsTimeDiff (staple.actTime, flv.startTime);
         double packetTS = packetTSTV.tv_sec + (double)packetTSTV.tv_usec/1000000;
         flv.lastTransportTS = packetTS;
         // Previous TAG size
         unsigned long prevTagSize = (unsigned long)(plCache[plPos++])<<24;
         prevTagSize |= (unsigned long)(plCache[plPos++])<<16;
         prevTagSize |= (unsigned long)(plCache[plPos++])<<8;
         prevTagSize |= (unsigned long)(plCache[plPos++]);
         if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - prevTagSize " << prevTagSize;

         // FLV TAG
         unsigned short tagType = plCache[plPos++];
         if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - found TAG (type " << tagType << ")";
         // Closing TAG?
         if ((tagType==0) || (tagType==72))
         {
            // Finish FLV decoding
            flv.loadedOK = true;
            if (plCache.size>0) plCache.Free();
            // Logging
            if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - FLV fully downloaded";
            break;
         }
         // Unknown TAG?
         if (!((tagType==8) || (tagType==9) || (tagType==18)))
         {
            // Stop FLV decoding
            if (plCache.size>0) plCache.Free();
            // Logging
            if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - unknown TAG type " << tagType;
            break;
         }
         // Get TAG data size
         unsigned long dataSize = (unsigned long)(plCache[plPos++])<<16;
         dataSize |= (unsigned long)(plCache[plPos++])<<8;
         dataSize |= (unsigned long)(plCache[plPos++]);
         if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - dataSize " << dataSize;
         // Skip non-audio & non-video frames (otherwise timestamps get screwed)
         if ((tagType!=8) && (tagType!=9))
         {
            plPos += dataSize+7;
            continue;
         }
         // Decode frame timestamp
         unsigned long tmpTS = (unsigned long)(plCache[plPos++])<<16;
         tmpTS |= (unsigned long)(plCache[plPos++])<<8;
         tmpTS |= (unsigned long)(plCache[plPos++]);
         double ts = ((double)tmpTS)/1000;
         if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - ts " << ts;
         // Skip TS extension and stream ID
         plPos += 4;
         // Audio frame
         if (tagType==8)
         {
            // At the first audio frame, store audio stream info
            if (flv.audioBytes==0)
            {
               flv.soundFormat = ((plCache[plPos])&0xf0)>>4;
               flv.soundRate = ((plCache[plPos])&0x0c)>>2;
               flv.soundType = ((plCache[plPos])&0x01);
               if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - audio: sound format " << flv.soundFormat << " sound rate " << flv.soundRate << " sound type " << flv.soundType;
            }
            flv.audioBytes += dataSize;
         }
         // Video frame
         if (tagType==9)
         {
            // At the first video frame, store video stream info
            if (flv.videoBytes==0)
            {
               flv.videoCodec = (plCache[plPos])&0x0f;
               if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - video: codec " << flv.videoCodec;
            }
            flv.videoBytes += dataSize;
         }
         // Rebuffering estimation
         // ----------------------
         // At the first packet, initialize rebuffering start TS and media start TS
         if (flv.rebuffTransportTS==0) flv.rebuffTransportTS = packetTS;
         if (flv.startMediaTS<0) flv.startMediaTS = ts;
         // Calculate relative timestamp (for those files, where the initial TS is not zero)
         ts -= flv.startMediaTS;
         flv.lastMediaTS = ts;
         if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - relative media TS: " << ts << " transport TS: " << packetTS;
         // Rebuffering is in progress
         // --------------------------
         if(flv.rebuffFlag==true)
         {
            if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - rebuffering in progress (buffered time " << (ts - flv.rebuffMediaTS) << " s)";

            // Check if rebuffering is finished
            if (ts - flv.rebuffMediaTS >= FLV_REBUFF_THRESH)
            {
               flv.rebuffFlag = false;
               if (flv.rebuffInit==0)
               {
                  flv.rebuffInit = packetTS;
                  if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - initial buffering time " << flv.rebuffInit << " s";
staple.logStream << "Initial buffering time: " << flv.rebuffInit << " s\n";
               }
               else
               {
staple.logStream << "Rebuffering finished\n";
                  flv.rebuffNum++;
                  flv.rebuffTime += packetTS - flv.rebuffTransportTS;
                  if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - " << flv.rebuffNum << ". rebuffering finished (buffering time " << packetTS - flv.rebuffTransportTS << " s)";
               }
               flv.rebuffTransportTS = packetTS;
            }
         }
         // No rebuffering
         // --------------
         else
         {
            double bufferedTime = ts - flv.rebuffMediaTS - (packetTS - flv.rebuffTransportTS);
            if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - buffered time " << bufferedTime << " s";

            // Check if rebuffering needed
            if(bufferedTime<0)
            {
               flv.rebuffFlag = true;
               flv.rebuffTransportTS = packetTS;
               flv.rebuffMediaTS = ts;
staple.logStream << "Rebuffering starts\n";
            }
         }
         // Calculate QoE
         // -------------
         // TODO: if initial buffering lasts longer than the measTime, a wrong QoE is calculated!!!
         // Wallclock time includes initial buffering
         double wallTS = ts + flv.rebuffInit + flv.rebuffTime + ((flv.rebuffFlag) ? (packetTS-flv.rebuffTransportTS) : 0);
         if ((wallTS-flv.lastQoETimestamp) >= FLV_QOE_TIME)
         {
            double cleanMax = 4.8;
            double alpha = 0.003;
            double rebuffTime = fabs((wallTS-ts) - flv.lastQoERebuffTime);
            double bufferingRatio = rebuffTime/FLV_QOE_TIME;
            double bufferingDeg = 1 - (0.435 * sqrt(bufferingRatio + ((flv.lastQoETimestamp==0) ? (0.273*pow(flv.rebuffInit, 0.0651)) : 0)));
            double qoe = (cleanMax-1) * (1-exp((-alpha * (8*flv.videoBytes/1000)) / ts)) * bufferingDeg + 1;
            // Insert QoE to the list (if it can be calculated)
            if ((flv.videoBytes!=0) && (ts!=0))
            {
               flv.qoeList.push_back(qoe);
               flv.qoeTime.push_back(flv.lastQoETransportTS);
               if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - QoE " << qoe << " (rate " << 8*flv.videoBytes/ts << " bps)";
            }
            flv.lastQoETimestamp = wallTS;
            flv.lastQoETransportTS = packetTS;
            flv.lastQoERebuffTime = wallTS - ts;
         }

         if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << "\n";

         plPos += dataSize;
      }
   }
   return;
}

// All TCP connections have to be erased first!
bool Parser::ReleaseIPSession(IPSessionReg::iterator& releaseIndex)
{
   // Sanity check
   if (releaseIndex == staple.ipSessionReg.end()) return false;

   // Erase session entry
   staple.ipSessionReg.erase(releaseIndex);

   return true;
}

bool Parser::ReleaseTCPConnection(TCPConnReg::iterator& releaseIndex)
{
   // Sanity check
   if (releaseIndex == staple.tcpConnReg.end()) return false;

   const TCPConnId& tcpConnId = releaseIndex->first;
   TCPConn& tcpConn = releaseIndex->second;

   // Find its IP session
   IPAddressId ipSessionId;
   ipSessionId.IP = tcpConnId.netAIP;
   IPSession& ipSession = staple.ipSessionReg[ipSessionId];

   // Finish RTT calc states if necessary (and possibly IP channel rate calc)
   if (tcpConn.inRTTCalcState[0]==true) ipSession.DecreaseTCPsInRTTCalcState(0);
   if (tcpConn.inRTTCalcState[1]==true) ipSession.DecreaseTCPsInRTTCalcState(1);

   // TCP was FIN terminated
   if (tcpConn.termination == TCPConn::TERM_FIN)
   {
      // Finish possible end-of-window loss detection
      if (tcpConn.sndLossState[0]==TCPConn::POSSIBLE_EWL) EndOfWindowLoss(tcpConn,0,tcpConn.rtxEWLFirstSeq[0],tcpConn.rtxHighestSeq[0]);
      if (tcpConn.sndLossState[1]==TCPConn::POSSIBLE_EWL) EndOfWindowLoss(tcpConn,1,tcpConn.rtxEWLFirstSeq[1],tcpConn.rtxHighestSeq[1]);
   }
   // TCP was not terminated with a FIN
   {
      // Remove unACKed packets from the significant set for AMP and BMP packet loss estimation
      RemovePacketsFromSignificantSet(tcpConn,0,tcpConn.highestACKSeen[1],true,true);
      RemovePacketsFromSignificantSet(tcpConn,1,tcpConn.highestACKSeen[0],true,true);
   }

   // Finish possible ongoing transactions (both directions)
   FinishTCPTransaction(releaseIndex,ipSession,0);
   FinishTCPTransaction(releaseIndex,ipSession,1);

   // Clean up history (must be before transaction merge because we use stored iterators to transactions)
   while (RemovePacketFromHistory(releaseIndex,0));
   while (RemovePacketFromHistory(releaseIndex,1));

   // Calculate mean RTT (must be after ending transactions)
   tcpConn.smallPipeRTT[0] = (tcpConn.smallPipeRTTSamples[0]!=0) ?
      tcpConn.smallPipeRTT[0]/tcpConn.smallPipeRTTSamples[0] :
      0;
   tcpConn.smallPipeRTT[1] = (tcpConn.smallPipeRTTSamples[1]!=0) ?
      tcpConn.smallPipeRTT[1]/tcpConn.smallPipeRTTSamples[1] :
      0;
   tcpConn.largePipeRTT[0] = (tcpConn.largePipeRTTSamples[0]!=0) ?
      tcpConn.largePipeRTT[0]/tcpConn.largePipeRTTSamples[0] :
      0;
   tcpConn.largePipeRTT[1] = (tcpConn.largePipeRTTSamples[1]!=0) ?
      tcpConn.largePipeRTT[1]/tcpConn.largePipeRTTSamples[1] :
      0;

   // Determine close time
   if (tcpConn.lastPacketTime[0].tv_sec == tcpConn.lastPacketTime[1].tv_sec)
   {
      tcpConn.closeTime = (tcpConn.lastPacketTime[0].tv_usec > tcpConn.lastPacketTime[1].tv_usec) ?
                          tcpConn.lastPacketTime[0] :
                          tcpConn.lastPacketTime[1];
   }
   else if (tcpConn.lastPacketTime[0].tv_sec > tcpConn.lastPacketTime[1].tv_sec)
   {
      tcpConn.closeTime = tcpConn.lastPacketTime[0];
   }
   else
   {
      tcpConn.closeTime = tcpConn.lastPacketTime[1];
   }

   // Calculate the "real" IPSessionBytes during the TCP connection
   tcpConn.IPSessionBytes[0] = ipSession.bytesSeen[0] - tcpConn.IPSessionBytes[0];
   tcpConn.IPSessionBytes[1] = ipSession.bytesSeen[1] - tcpConn.IPSessionBytes[1];

   // If setup was failed, determine setup load
   if ((tcpConn.setupSuccess == false) && (tcpConn.unloadedSetup == true) &&
      (((tcpConn.IPSessionBytes[0]-tcpConn.IPBytes[0]) > UNLOADED_MAXDATA_DURING) || ((tcpConn.IPSessionBytes[1]-tcpConn.IPBytes[1]) > UNLOADED_MAXDATA_DURING)))
   {
      tcpConn.unloadedSetup = false;
   }

   // Finish possible FLV sessions
   FinishFLV(releaseIndex, 0);
   FinishFLV(releaseIndex, 1);

   // Update overall TCP statistics
   if (tcpConn.termination != TCPConn::TERM_ALIVE)
   {
      TCPStats& tcpStats = staple.tcpStats;
      
      tcpStats.tcpsSeen++;
      if ((tcpConn.SACKPermitted[0]==true) && (tcpConn.SACKPermitted[1]==true))
      {
         tcpStats.SACKPermitted++;
      }
      if ((tcpConn.TSSeen[0]==true) && (tcpConn.TSSeen[1]==true))
      {
         tcpStats.TSSeen++;
      }
      double aloneRatio = (double)(tcpConn.IPSessionBytes[0]+tcpConn.IPSessionBytes[1])/(tcpConn.IPBytes[0]+tcpConn.IPBytes[1]) - 1;
      tcpStats.standalone += (aloneRatio < 0.01) ? 1 : 0;
      tcpStats.termFIN += (tcpConn.termination == TCPConn::TERM_FIN) ? 1 : 0;
      tcpStats.termRST += (tcpConn.termination == TCPConn::TERM_RST) ? 1 : 0;
      tcpStats.termTO += (tcpConn.termination == TCPConn::TERM_TO) ? 1 : 0;
      for (int dir=0;dir<2;dir++)
      {
         tcpStats.dataPacketsSeen[dir] += tcpConn.dataPacketsSeen[dir];
         tcpStats.mssLow[dir] += ((tcpConn.maxDataPacketIPLen[dir]>=400) && (tcpConn.maxDataPacketIPLen[dir]<600)) ? 1 : 0;
         tcpStats.mssHigh[dir] += ((tcpConn.maxDataPacketIPLen[dir]>=1400) && (tcpConn.maxDataPacketIPLen[dir]<1600)) ? 1 : 0;
         tcpStats.wndLow[dir] += (tcpConn.maxRWndSize[dir]<10000) ? 1 : 0;
         tcpStats.wndMed[dir] += ((tcpConn.maxRWndSize[dir]>=10000) && (tcpConn.maxRWndSize[dir]<20000)) ? 1 : 0;
         tcpStats.wndHigh[dir] += (tcpConn.maxRWndSize[dir]>=20000) ? 1 : 0;
      }
      // If loss estimation is reliable, update loss related variables
      if (tcpConn.lossReliable == true)
      {
         for (int dir=0;dir<2;dir++)
         {
            // If timestamp-based loss validation is reliable too, update those stats too
            if (tcpConn.tsLossReliable == true)
            {
               tcpStats.signPacketsSeenAMPTS[dir] += tcpConn.signPacketsSeenAMP[dir];
               tcpStats.signPacketsLostAMPTSOriginal[dir] += tcpConn.signPacketsLostAMP[dir];
               tcpStats.signPacketsLostAMPTSValidation[dir] += tcpConn.signPacketsLostAMPTS[dir];
            }
            tcpStats.signPacketsSeenBMP[dir] += tcpConn.signPacketsSeenBMP[dir];
            tcpStats.signPacketsSeenAMP[dir] += tcpConn.signPacketsSeenAMP[dir];
            tcpStats.signPacketsLostBMP[dir] += tcpConn.signPacketsLostBMP[dir];
            tcpStats.signPacketsLostAMP[dir] += tcpConn.signPacketsLostAMP[dir];
            tcpStats.bytesPL[dir]+=tcpConn.PLBytes[dir];
            if (tcpStats.bytesPL[dir]>>10 != 0)
            {
               tcpStats.kBytesPL[dir] += tcpStats.bytesPL[dir]>>10;
               tcpStats.bytesPL[dir] &= 0x3ff;
            }
            tcpStats.bytesPLAlreadySeen[dir]+=tcpConn.PLBytesAlreadySeen[dir];
            if (tcpStats.bytesPLAlreadySeen[dir]>>10 != 0)
            {
               tcpStats.kBytesPLAlreadySeen[dir] += tcpStats.bytesPLAlreadySeen[dir]>>10;
               tcpStats.bytesPLAlreadySeen[dir] &= 0x3ff;
            }
            tcpStats.rtxPeriods[dir] += tcpConn.rtxPeriods[dir];

            // [For Reiner] Go through the RTX period list of large DL TCPs
            if ((dir==1) && (tcpConn.highestDataACKSeen[1-dir]>1000000))
            {
               std::list<TCPConn::RTXPeriodListEntry>::iterator listIndex = tcpConn.rtxPeriodList[dir].begin();
               while (listIndex != tcpConn.rtxPeriodList[dir].end())
               {
                  // Print SRTX event start seq
                  if (((*listIndex).type == 2) && ((*listIndex).seq<1000000)) staple.logStream << "SRTXSEQ " << (unsigned short)((*listIndex).lossInfo) << " " << (*listIndex).seq << "\n";
                  // Print necessary RTX event start seq
                  if (((*listIndex).type == 3) && ((*listIndex).seq<1000000)) staple.logStream << "NRTXSEQ " << (unsigned short)((*listIndex).lossInfo) << " " << (*listIndex).seq << "\n";
                  listIndex++;
               }
            }
            // [\For Reiner]
         }
         tcpStats.lossReliable++;
         tcpStats.tsLossReliable += (tcpConn.tsLossReliable == true) ? 1 : 0;
      }
      tcpStats.rtxDataOffset += (tcpConn.rtxDataOffset == true) ? 1 : 0;
      tcpStats.captureLoss += (tcpConn.captureLoss == true) ? 1 : 0;

      // Logging
      if (staple.logLevel >= 2)
      {
         // Print statistics for the exiting connection
         PrintTCPStatistics(releaseIndex, staple.logStream);
      }
   }

   // Remove TCP from IP session
   ipSession.RemoveTCPConnection(tcpConnId);

   // If a HTTP session exists, remove TCP from it
   httpEngine.finishTCPSession(tcpConnId);

   // Erase TCP connection entry
   staple.tcpConnReg.erase(releaseIndex);

   return true;
}

void Parser::FinishFLV(TCPConnReg::iterator& tcpFinishIndex, unsigned short direction)
{
   // Get TCP connection
   TCPConn& tcpConn = tcpFinishIndex->second;
   const TCPConnId& tcpConnId = tcpFinishIndex->first;

   // Sanity check
   if (tcpConn.flv[direction].found==false) return;

   FLV& flv = tcpConn.flv[direction];

   // Check if FLV is fully decoded (only 4 bytes [previous TAG size] remained at the end)
   if (tcpConn.highestDataACKSeen[1-direction] == (tcpConn.payloadPos[direction]+4))
   {
      flv.loadedOK = true;
      if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - FLV fully downloaded";
   }

   // Calculate QoE for the last partial window
   double wallTS = flv.lastMediaTS + flv.rebuffInit + flv.rebuffTime + ((flv.rebuffFlag) ? (flv.lastTransportTS-flv.rebuffTransportTS) : 0);
   double measTime = fabs(wallTS - flv.lastQoETimestamp);
   double cleanMax = 4.8;
   double alpha = 0.003;
   double rebuffTime = fabs((wallTS-flv.lastMediaTS) - flv.lastQoERebuffTime);
   double bufferingRatio = rebuffTime/measTime;
   double bufferingDeg = 1 - (0.435 * sqrt(bufferingRatio + ((flv.lastQoETimestamp==0) ? (0.273*pow(flv.rebuffInit, 0.0651)) : 0)));
   double qoe = (cleanMax-1) * (1-exp((-alpha * (8*flv.videoBytes/1000)) / flv.lastMediaTS)) * bufferingDeg + 1;
   // Insert QoE to the list (if it can be calculated)
   if ((flv.videoBytes!=0) && (flv.lastMediaTS!=0))
   {
      flv.qoeList.push_back(qoe);
      flv.qoeTime.push_back(flv.lastQoETransportTS);
      if (staple.logLevel >= FLVLOGLEVEL) staple.logStream << " - QoE " << qoe << " (rate " << 8*flv.videoBytes/flv.lastMediaTS << " bps)";
   }

   // Calculate rates
   double mediaRate = (flv.lastMediaTS>1) ?
      8*(double)(flv.videoBytes)/flv.lastMediaTS :
      -1;
   double rate = (flv.lastTransportTS>1) ?
      8*(double)(tcpConn.payloadPos[direction]-flv.startPos) / flv.lastTransportTS :
      -1;

   // Update statistics
   FLVStats& flvStats = staple.flvStats;
   flvStats.bytes[direction] += tcpConn.payloadPos[direction]-flv.startPos;
   if (flvStats.bytes[direction]>>10 != 0)
   {
      flvStats.kBytes[direction] += flvStats.bytes[direction]>>10;
      flvStats.bytes[direction] &= 0x3ff;
   }
   flvStats.duration[direction] += flv.lastMediaTS;

   // Log to Perfmon file
   long double tstart = flv.startTime.tv_sec + flv.startTime.tv_usec/1e6;

   char lineStr[1000];
   char* lineStrPos = lineStr;
   lineStrPos += sprintf(lineStrPos, "%u.%u.%u.%u\t",tcpConnId.netAIP.byte[3], tcpConnId.netAIP.byte[2], tcpConnId.netAIP.byte[1], tcpConnId.netAIP.byte[0]);
   lineStrPos += sprintf(lineStrPos, "%u\t", tcpConnId.netAPort);
   lineStrPos += sprintf(lineStrPos, "%u.%u.%u.%u\t",tcpConnId.netBIP.byte[3], tcpConnId.netBIP.byte[2], tcpConnId.netBIP.byte[1], tcpConnId.netBIP.byte[0]);
   lineStrPos += sprintf(lineStrPos, "%u\t", tcpConnId.netBPort);
   lineStrPos += sprintf(lineStrPos, "%lu\t", tcpConn.payloadPos[direction]-flv.startPos);
   lineStrPos += sprintf(lineStrPos, "%f\t", mediaRate);
   lineStrPos += sprintf(lineStrPos, "%f\t", rate);
   lineStrPos += sprintf(lineStrPos, "%f\t", flv.rebuffInit);
   lineStrPos += sprintf(lineStrPos, "%hu\t", flv.rebuffNum);
   lineStrPos += sprintf(lineStrPos, "%f\t", flv.rebuffTime);

   if (flv.loadedOK) lineStrPos += sprintf(lineStrPos, "OK\t");
   else if (tcpConn.termination==TCPConn::TERM_RST) lineStrPos += sprintf(lineStrPos, "RST\t");
   else if (tcpConn.termination==TCPConn::TERM_TO) lineStrPos += sprintf(lineStrPos, "TO\t");
   else
   {
      lineStrPos += sprintf(lineStrPos, "unknown\t");
   }

   if (flv.videoBytes>0)
   {
      if(flv.videoCodec==1) lineStrPos += sprintf(lineStrPos, "JPEG\t");
      else if(flv.videoCodec==2) lineStrPos += sprintf(lineStrPos, "Sorenson H.263\t");
      else if(flv.videoCodec==3) lineStrPos += sprintf(lineStrPos, "Screen video\t");
      else if(flv.videoCodec==4) lineStrPos += sprintf(lineStrPos, "ON2 VP6\t");
      else if(flv.videoCodec==5) lineStrPos += sprintf(lineStrPos, "ON2 VP6 with alpha channel\t");
      else if(flv.videoCodec==6) lineStrPos += sprintf(lineStrPos, "Screen video version 2\t");
      else if(flv.videoCodec==7) lineStrPos += sprintf(lineStrPos, "AVC\t");
      else lineStrPos += sprintf(lineStrPos, "Unknown\t");

   } else lineStrPos += sprintf(lineStrPos, "\\N\t");

   if (flv.audioBytes>0)
   {
      if (flv.soundFormat==0) lineStrPos += sprintf(lineStrPos, "Linear PCM platform endian\t");
      else if(flv.soundFormat==1) lineStrPos += sprintf(lineStrPos, "ADPCM\t");
      else if(flv.soundFormat==2) lineStrPos += sprintf(lineStrPos, "MP3\t");
      else if(flv.soundFormat==3) lineStrPos += sprintf(lineStrPos, "Linear PCM little endian\t");
      else if(flv.soundFormat==4) lineStrPos += sprintf(lineStrPos, "Nellymoser 16-kHz mono\t");
      else if(flv.soundFormat==5) lineStrPos += sprintf(lineStrPos, "Nellymoser 8-kHz mono\t");
      else if(flv.soundFormat==6) lineStrPos += sprintf(lineStrPos, "Nellymoser\t");
      else if(flv.soundFormat==7) lineStrPos += sprintf(lineStrPos, "G.711 A-law logarithmic PCM\t");
      else if(flv.soundFormat==8) lineStrPos += sprintf(lineStrPos, "G.711 mu-law logarithmic PCM\t");
      else if(flv.soundFormat==9) lineStrPos += sprintf(lineStrPos, "reserved\t");
      else if(flv.soundFormat==10) lineStrPos += sprintf(lineStrPos, "AAC\t");
      else if(flv.soundFormat==14) lineStrPos += sprintf(lineStrPos, "MP3 8-kHz\t");
      else if(flv.soundFormat==15) lineStrPos += sprintf(lineStrPos, "Device specific sound\t");
      else lineStrPos += sprintf(lineStrPos, "Unknown\t");

      if (flv.soundRate==0) lineStrPos += sprintf(lineStrPos, "5.5\t");
      else if (flv.soundRate==1) lineStrPos += sprintf(lineStrPos, "11\t");
      else if (flv.soundRate==2) lineStrPos += sprintf(lineStrPos, "22\t");
      else if (flv.soundRate==3) lineStrPos += sprintf(lineStrPos, "44\t");
      else lineStrPos += sprintf(lineStrPos, "Unknown\t");

      if (flv.soundType==0) lineStrPos += sprintf(lineStrPos, "mono\t");
      else if (flv.soundType==1) lineStrPos += sprintf(lineStrPos, "stereo\t");
      else lineStrPos += sprintf(lineStrPos, "Unknown\t");

   } else lineStrPos += sprintf(lineStrPos, "\\N\t\\N\t\\N\t");

   lineStrPos += sprintf(lineStrPos, "%hu\t", direction);
   double aloneRatio = ((double)tcpConn.IPSessionBytes[direction]/tcpConn.IPBytes[direction])-1;
   lineStrPos += sprintf(lineStrPos, "%f\t", aloneRatio);
   lineStrPos += sprintf(lineStrPos, "%u\t", tcpConn.maxRWndSize[0]);
   if ((tcpConn.initialRTT[0]!=-1) && (tcpConn.unloadedSetup==true)) lineStrPos += sprintf(lineStrPos, "%f\t", tcpConn.initialRTT[0]);
   else lineStrPos += sprintf(lineStrPos, "\\N\t");
   if (tcpConn.initialRTT[1]!=-1) lineStrPos += sprintf(lineStrPos, "%f\t", tcpConn.initialRTT[1]);
   else lineStrPos += sprintf(lineStrPos, "\\N\t");
   lineStrPos += sprintf(lineStrPos, "%u\t", tcpConn.maxDataPacketIPLen[0] > tcpConn.maxDataPacketIPLen[1] ? tcpConn.maxDataPacketIPLen[0] : tcpConn.maxDataPacketIPLen[1]);
   if (tcpConn.lossReliable==true)
   {
      if (direction==0)
      {
         if (tcpConn.signPacketsSeenBMP[direction]!=0)
         {
            lineStrPos += sprintf(lineStrPos, "%f\t",((double)tcpConn.signPacketsLostBMP[direction])/tcpConn.signPacketsSeenBMP[direction]);
         }
         else
         {
            lineStrPos += sprintf(lineStrPos, "\\N\t");
         }
         if (tcpConn.signPacketsSeenAMP[direction]!=0)
         {
            lineStrPos += sprintf(lineStrPos, "%f\t",((double)tcpConn.signPacketsLostAMP[direction])/tcpConn.signPacketsSeenAMP[direction]);
         }
         else
         {
            lineStrPos += sprintf(lineStrPos, "\\N\t");
         }
      }
      else
      {
         if (tcpConn.signPacketsSeenAMP[direction]!=0)
         {
            lineStrPos += sprintf(lineStrPos, "%f\t",((double)tcpConn.signPacketsLostAMP[direction])/tcpConn.signPacketsSeenAMP[direction]);
         }
         else
         {
            lineStrPos += sprintf(lineStrPos, "\\N\t");
         }
         if (tcpConn.signPacketsSeenBMP[direction]!=0)
         {
            lineStrPos += sprintf(lineStrPos, "%f\t",((double)tcpConn.signPacketsLostBMP[direction])/tcpConn.signPacketsSeenBMP[direction]);
         }
         else
         {
            lineStrPos += sprintf(lineStrPos, "\\N\t");
         }
      }
   }
   else
   {
      lineStrPos += sprintf(lineStrPos, "\\N\t\\N\t");
   }

   // Write full MOS logfile
   // ----------------------
   pthread_mutex_lock(&perfmonFileMutex);
   if (perfmonFLVFile)
   {
	  std::ostringstream event;
      event << std::fixed << std::setprecision(6)
                        << tstart << "\t" << flv.lastTransportTS << "\t" << lineStr;

      double avgQoE=0;
      double avgQoEBody=0;
      unsigned short qoeNum=0;
      std::list<double>::iterator qoeIndex=flv.qoeList.begin();
      event << "{";
      while (qoeIndex!=flv.qoeList.end())
      {
         if (qoeIndex!=flv.qoeList.begin()) event << ",";
         event << (*qoeIndex);
         // Update stats
         avgQoE += (*qoeIndex);
         avgQoEBody += ((qoeNum==0) ? 0 : (*qoeIndex));
         qoeNum++;
         flvStats.qoe[direction] += (*qoeIndex);
         flvStats.qoeNum[direction]++;
         qoeIndex++;
      }
      event << "}\t";

      if (qoeNum!=0)
         event << avgQoE/qoeNum;
      else
    	  event << "\\N";
      event << "\t";
      
      if (qoeNum>1)
    	  event << avgQoEBody/(qoeNum-1);
      else
         event << "\\N";
      event << "\t";
      
      event << qoeNum << "\t";

      std::list<double>::iterator qoeTimeIndex=flv.qoeTime.begin();
      event << "{";
      while (qoeTimeIndex!=flv.qoeTime.end())
      {
         event << (qoeTimeIndex!=flv.qoeTime.begin() ? "," : "")
                           << (*qoeTimeIndex);
         qoeTimeIndex++;
      }
      event << "}\t";

      qoeTimeIndex=flv.qoeTime.begin();
      std::list<double>::iterator qoeNextTimeIndex=flv.qoeTime.begin();
      qoeNextTimeIndex++;
      event << "{";
      while (qoeTimeIndex!=flv.qoeTime.end())
      {
         if (qoeTimeIndex!=flv.qoeTime.begin()) event << ",";
         if (qoeNextTimeIndex!=flv.qoeTime.end())
         {
            event << ((*qoeNextTimeIndex)-(*qoeTimeIndex));
         }
         else
         {
            event << flv.lastTransportTS-(*qoeTimeIndex);
         }
         qoeTimeIndex++;
         qoeNextTimeIndex++;
      }

      event << "}\n";

      if (writeToFile){
    	  (*perfmonFLVFile) << event.str();
      }
      if (hazelcastPublish){
    	  StapleJniImpl stapleJni;
    	  stapleJni.publishEvent(stapleJni.FLV_FULL, event.str());
      }

   }
   
   // Write splitted MOS logfile
   // --------------------------
   if (perfmonFLVPartialFile)
   {
      std::list<double>::iterator qoeIndex=flv.qoeList.begin();
      std::list<double>::iterator qoeTimeIndex=flv.qoeTime.begin();
      std::list<double>::iterator qoeNextTimeIndex=flv.qoeTime.begin();
      qoeNextTimeIndex++;
      unsigned short seqNum=0;
      while (qoeIndex!=flv.qoeList.end())
      {
    	 std::ostringstream event;
    	 event << std::fixed << std::setprecision(6) << tstart+(*qoeTimeIndex) << "\t"
                 << (qoeNextTimeIndex!=flv.qoeTime.end() ? ((*qoeNextTimeIndex)-(*qoeTimeIndex)) : flv.lastTransportTS-(*qoeTimeIndex)) << "\t"
                 << lineStr
                 << seqNum << "\t"
                 << (*qoeIndex) << "\n";

         if (writeToFile){
        	 (*perfmonFLVPartialFile) << event.str();
         }
         if (hazelcastPublish){
        	 StapleJniImpl stapleJni;
        	 stapleJni.publishEvent(stapleJni.FLV_PARTIAL, event.str());
         }
         seqNum++;
         qoeIndex++;
         qoeTimeIndex++;
         qoeNextTimeIndex++;
      }
   }
   
   pthread_mutex_unlock(&perfmonFileMutex);
}

bool Parser::FinishTCPTransaction(TCPConnReg::iterator& tcpFinishIndex, IPSession& ipSession, unsigned short direction)
{
   // Get TCP connection
   TCPConn& tcpConn = tcpFinishIndex->second;
   const TCPConnId& tcpConnId = tcpFinishIndex->first;
   // Sanity check
   if ((tcpConn.ongoingTransaction[direction]==false) || (tcpConn.transactionList[direction].empty())) return false;
   // Get reference to the transaction
   TCPTransaction& tcpTA = tcpConn.transactionList[direction].back();

   tcpConn.ongoingTransaction[direction] = false;

   // Close TCP TA logfile
   #ifdef WRITE_TCPTA_FILES
      fclose(tcpTA.logfile);
      char logfileName[200];
      sprintf(logfileName, "%s/%u.%u.%u.%u_%u-%u.%u.%u.%u_%u-%u.TAlog",perfmonDirName.c_str(),tcpConnId.netAIP.byte[3], tcpConnId.netAIP.byte[2], tcpConnId.netAIP.byte[1], tcpConnId.netAIP.byte[0],tcpConnId.netAPort,tcpConnId.netBIP.byte[3], tcpConnId.netBIP.byte[2], tcpConnId.netBIP.byte[1], tcpConnId.netBIP.byte[0],tcpConnId.netBPort,tcpTA.firstDataPacketSeq);
   #endif

   // If no ACK has been received, ignore transaction
   if (tcpTA.highestDataACKSeen == 0)
   {
      tcpConn.transactionList[direction].pop_back();
      // Logging
      if (staple.logLevel >= 3)
      {
         staple.logStream << " - Transaction ends " << ((direction==0)?"(A->B)":"(B->A)") << " (invalid)";
      }
      // Do not keep TCP TA log file
      #ifdef WRITE_TCPTA_FILES
         remove(logfileName);
      #endif
      return false;
   }

   // Too short transactions are deleted
   unsigned long dataReceived = (tcpTA.lastButHighestDataACKSeen!=0) ? (tcpTA.lastButHighestDataACKSeen-tcpTA.firstDataPacketSeq) : 0;
   if ((dataReceived<=TCPTA_MINSIZE) &&
   ((tcpTA.lastReport.time.tv_sec==0) && (tcpTA.lastReport.time.tv_usec==0)))
   {
      tcpConn.transactionList[direction].pop_back();
      // Do not keep TCP TA log file
      #ifdef WRITE_TCPTA_FILES
         remove(logfileName);
      #endif
      return false;
   }
   else
   {
      if (staple.logLevel>=3)
      {
         staple.logStream << " - Transaction is kept";
      }
   }

   // Do not keep TCP TA log file
   #ifdef WRITE_TCPTA_FILES
      if (dataReceived<500000) remove(logfileName);
   #endif

   // Print the last partial report before finishing the transaction
   if ((tcpTA.lastButHighestDataACKTime.tv_sec!=tcpTA.lastReport.time.tv_sec) || (tcpTA.lastButHighestDataACKTime.tv_usec!=tcpTA.lastReport.time.tv_usec))
   {
      PrintTCPTAStatistics(tcpFinishIndex,tcpTA,direction,false,true);
   }

   // For both directions calculate some variables (use "i" as index, since we already have a direction variable!!!)
   for (int i=0;i<2;i++)
   {
      // Calculate IP data amounts
      tcpTA.IPBytes[i]=(tcpTA.lastButHighestACKedIPByte[i]!=0) ? (tcpTA.lastButHighestACKedIPByte[i]-tcpConn.TAFirstIPByte[direction][i]) : 0;
      tcpTA.IPSessionBytes[i] = (tcpTA.lastButHighestACKedIPSessionByte[i]!=0) ? (tcpTA.lastButHighestACKedIPSessionByte[i]-tcpConn.TAFirstIPSessionByte[direction][i]) : 0;
      // Calculate mean RTT
      tcpTA.smallPipeRTTSamples[i] = tcpConn.smallPipeRTTSamples[i] - tcpConn.TAFirstSmallPipeRTTSamples[direction][i];
      tcpTA.smallPipeRTT[i] = (tcpTA.smallPipeRTTSamples[i]!=0) ?
         (tcpConn.smallPipeRTT[i] - tcpConn.TAFirstSmallPipeRTT[direction][i]) / tcpTA.smallPipeRTTSamples[i] :
         0;
      tcpTA.largePipeRTTSamples[i] = tcpConn.largePipeRTTSamples[i] - tcpConn.TAFirstLargePipeRTTSamples[direction][i];
      tcpTA.largePipeRTT[i] = (tcpTA.largePipeRTTSamples[i]!=0) ?
         (tcpConn.largePipeRTT[i] - tcpConn.TAFirstLargePipeRTT[direction][i]) / tcpTA.largePipeRTTSamples[i] :
         0;
   }
   tcpTA.ssEndIPSessionBytes = (tcpTA.reportLastIPSessionByte!=0) ? (tcpTA.reportLastIPSessionByte - tcpTA.ssEndIPSessionBytes) : 0;

   // Logging
   if (staple.logLevel >= 3)
   {
      staple.logStream << " - Transaction ends " << ((direction==0)?"(A->B)":"(B->A)") << " (" << (tcpTA.highestDataACKSeen-tcpTA.firstDataPacketSeq) << " PL bytes, " << tcpTA.IPSessionBytes[direction] << " IP session bytes)";
   }

   return true;
}

bool Parser::EndOfWindowLoss(TCPConn& tcpConn, unsigned short direction, unsigned long firstSeq, unsigned long highestSeq)
{
   // Logging
   if (staple.logLevel >= 3)
   {
      staple.logStream << " - checking end-of-window loss in [" << firstSeq << "," << highestSeq << "]";
   }

   // [For Reiner] Change RTX period info in case of EWL
   tcpConn.rtxPeriodList[direction].back().type = TCPConn::NECESSARY_RTX;

   return AMPLossRange(tcpConn,direction,firstSeq,highestSeq,false);
}

bool Parser::SACKAMPLossCheck(TCPConn& tcpConn, unsigned short direction, unsigned long firstSeq, unsigned long highestSeq)
{
   // Logging
   if (staple.logLevel >= 3)
   {
      staple.logStream << " - all AMP retransmissions since the last partial ACK [" << firstSeq << "," << highestSeq << "] considered to be lost (SACK usage)";
   }
   return AMPLossRange(tcpConn,direction,firstSeq,highestSeq,true);
}

bool Parser::AMPLossRange(TCPConn& tcpConn, unsigned short direction, unsigned long firstSeq, unsigned long highestSeq, bool skipReordered)
{
   // Reconsider the loss of packets in the EWL range (only packets that have been retransmitted)
   std::list<PacketTrain>::iterator overlapIndex;
   overlapIndex = tcpConn.packetTrains[direction].TestPartialOverlap(firstSeq,firstSeq);
   if (overlapIndex != tcpConn.packetTrains[direction].packetTrainList.end())
   {
      // Got the train
      std::list<PacketTrainTCPPacket>::iterator packetIndex = (*overlapIndex).TestPacketSeq(firstSeq);
      if (packetIndex != (*overlapIndex).packetList.end())
      {
         // Got the first packet -> go through the EWL range
         while ((*packetIndex).seq<highestSeq)
         {
            // Corrigate loss of AMP loss candidate packets (originally considered not lost)
            if (((*packetIndex).lossInfo==PacketTrainTCPPacket::NOT_LOST) && ((*packetIndex).ampLossCandidate==true))
            {
               // We may skip reordered packets
               if ((skipReordered==false) || ((*packetIndex).reordered==false))
               {
                  // Mark packet as lost AMP
                  (*packetIndex).lossInfo = PacketTrainTCPPacket::LOST_AMP;
               }
            }
            // Calculate highest processed seq (for packet history hole test)
            unsigned long highestSeqProcessed = (*packetIndex).seq+(*packetIndex).len;
            // Next packet
            packetIndex++;
            // Reached the end?
            if (packetIndex == (*overlapIndex).packetList.end())
            {
               // Check whether all packets have been parsed
               if (highestSeqProcessed < highestSeq)
               {
                  // Hole in the packet history (loss invalidation will occur only at the time of packet removal from the history -> may cause problems if the [reordered] packet arrives in the meantime)
                  if (staple.logLevel >= 3)
                  {
                     staple.logStream << " - hole in the packet history (loss unreliable)";
                  }
               }
               // Finish processing
               break;
            }
         }
      }
      else
      {
         // Hole in the packet history (loss invalidation will occur only at the time of packet removal from the history -> may cause problems if the [reordered] packet arrives in the meantime)
         if (staple.logLevel >= 3)
         {
            staple.logStream << " - hole in the packet history (loss unreliable)";
         }
      }
   }
   else
   {
      // Hole in the packet history (loss invalidation will occur only at the time of packet removal from the history -> may cause problems if the [reordered] packet arrives in the meantime)
      if (staple.logLevel >= 3)
      {
         staple.logStream << " - hole in the packet history (loss unreliable)";
      }
   }

   return true;
}

void Parser::RemovePacketsFromSignificantSet(TCPConn& tcpConn, unsigned short direction, unsigned long firstSeq, bool amp, bool bmp)
{
   // Logging
   if (staple.logLevel >= 3)
   {
      staple.logStream << " - removing packets starting at seq " << firstSeq << " from " << ((amp==true) ? "AMP " : " ") << ((bmp==true) ? "BMP " : " ") << "significant set";
   }

   // Is the history empty?
   if (tcpConn.packetTrains[direction].packetTrainList.empty()) return;

   // Remove packets starting from the last packet train
   std::list<PacketTrain>::iterator actTrainIndex = --(tcpConn.packetTrains[direction].packetTrainList.end());
   while (1)
   {
      // Remove packets starting from the last packet of the train (no empty trains allowed!)
      std::list<PacketTrainTCPPacket>::iterator actPacketIndex = --((*actTrainIndex).packetList.end());
      while (1)
      {
         // Check if we have passed the first SEQ
         if ((*actPacketIndex).seq < firstSeq) break;
         // Remove packets from AMP/BMP significant set
         if (amp==true) (*actPacketIndex).signAMP=false;
         if (bmp==true) (*actPacketIndex).signBMP=false;
         // Check if we have to exit (processed the first packet in the actual train)
         if (actPacketIndex == (*actTrainIndex).packetList.begin()) break;
         // If not yet, process the preceding packet
         actPacketIndex--;
      }
      // Check if we have to exit (passed the first SEQ or processed the first packet train)
      if (((*actPacketIndex).seq < firstSeq) ||
         (actTrainIndex == tcpConn.packetTrains[direction].packetTrainList.begin()))
         break;
      // If not yet, travel backwards on the packet train list
      actTrainIndex--;
   }

   return;
}

// Finish RTX state and enter POSSIBLE_EWL state if necessary
bool Parser::FinishRetransmissionState(TCPConn& tcpConn, unsigned short direction)
{
   // Logging
   if (staple.logLevel >= 3)
   {
      staple.logStream << " - retransmission state exited";
   }

   // [For Reiner] - Insert RTX period info into the list (later, EWL may change this info!)
   TCPConn::RTXPeriodListEntry rtxEntry;
   rtxEntry.seq = tcpConn.rtxFirstSeq[direction];
   rtxEntry.type = tcpConn.sndLossState[direction];
   rtxEntry.lossInfo = tcpConn.rtxFirstSeqLossInfo[direction];
   tcpConn.rtxPeriodList[direction].push_back(rtxEntry);
   // [\For Reiner]

   // Go into possible end-of-window loss detection (if no dupACKs were seen or if we have a valid rtxELWFirstSeq)
   if (tcpConn.rtxEWLFirstSeq[direction]!=0)
   {
      // Enter end-of-window loss detect state
      tcpConn.sndLossState[direction]=TCPConn::POSSIBLE_EWL;
      // Logging
      if (staple.logLevel >= 3)
      {
         staple.logStream << " - POSSIBLE_EWL state entered";
      }
   }
   // Otherwise, we can return to normal state
   else
   {
      tcpConn.sndLossState[direction]=TCPConn::NORMAL;
   }

   // HOLE state will be exited in all cases
   tcpConn.rcvLossState[direction]=TCPConn::NO_HOLE;
   // Update RTX state counter
   tcpConn.rtxPeriods[direction]++;

   return true;
}


void Parser::ApplyHistorySizeLimits(TCPConnReg::iterator& index, unsigned short direction)
{
   // Get TCP connection
   TCPConn& tcpConn = index->second;

   // Maximum history size upper limit is always enforced
   while ((tcpConn.packetTrains[direction].lastSeq - tcpConn.packetTrains[direction].firstSeq) > MAX_HISTORY_RANGE)
   {
      RemovePacketFromHistory(index,direction);
   }

   // We may remove packets until they are already ACKed and older than a threshold
   struct timeval timeDiff;
   double tDiff;
   while (!tcpConn.packetTrains[direction].packetTrainList.empty())
   {
      // Get reference to the first packet (no empty trains allowed!)
      PacketTrainTCPPacket& firstPacket = tcpConn.packetTrains[direction].packetTrainList.front().packetList.front();
      
      timeDiff = AbsTimeDiff(staple.actTime, firstPacket.t);
      tDiff = timeDiff.tv_sec + (double)timeDiff.tv_usec/1000000;
      // Packet already ACKed and older than HISTORY_MAX_ACKED_AGE?
      if (((firstPacket.seq+firstPacket.len) <= tcpConn.highestDataACKSeen[1-direction]) && (tDiff>=HISTORY_MAX_ACKED_AGE))
      {
         RemovePacketFromHistory(index,direction);
      }
      // Stop the iteration otherwise
      else break;
   }
}

// History cleanup
// ---------------
bool Parser::RemovePacketFromHistory(TCPConnReg::iterator& index, unsigned short direction)
{
   // Get TCP connection
   TCPConn& tcpConn = index->second;

   // Is the packet list empty?
   if (tcpConn.packetTrains[direction].packetTrainList.empty()) return false;

   // Get reference to the first packet (no empty trains allowed!)
   PacketTrainTCPPacket& firstPacket = tcpConn.packetTrains[direction].packetTrainList.front().packetList.front();

   // Select the (possible) TCP transaction to which this sequence number belongs
   bool taFound=false;
   // Sanity check: there are transactions...
   while (!tcpConn.transactionList[direction].empty())
   {
      // Packet to be removed falls into the oldest transaction?
      if ((firstPacket.seq >= tcpConn.transactionList[direction].front().firstDataPacketSeq) &&
      ((firstPacket.seq+firstPacket.len) <= tcpConn.transactionList[direction].front().highestDataACKSeen))
      {
         // We found the TA
         taFound=true;
         break;
      }
      // Is the oldest transaction older than the packet to be removed (and not the ongoing transaction)?
      else if ((firstPacket.seq >= tcpConn.transactionList[direction].front().highestDataACKSeen) &&
      !((tcpConn.transactionList[direction].front().firstDataPacketSeq == tcpConn.transactionList[direction].back().firstDataPacketSeq) && (tcpConn.ongoingTransaction[direction]==true)))
      {
         // Remove the transaction and print it (overall report only - last partial report is written at FinishTCPTA())
         PrintTCPTAStatistics(index,tcpConn.transactionList[direction].front(),direction,true,true);
         tcpConn.transactionList[direction].pop_front();
      }
      else
      {
         break;
      }
   }

   // Update significant AMP loss related variables
   if (firstPacket.signAMP == true)
   {
      // Update TCP connections
      tcpConn.signPacketsSeenAMP[direction]++;
      tcpConn.signPacketsLostAMP[direction] += (firstPacket.lossInfo == PacketTrainTCPPacket::LOST_AMP) ? 1 : 0;
      tcpConn.signPacketsLostAMPTS[direction] += (firstPacket.lossTSInfo == PacketTrainTCPPacket::LOST_AMP_TS) ? 1 : 0;
      tcpConn.signPacketsRetrAMP[direction] += (firstPacket.ampLossCandidate == true) ? 1 : 0;
      // Update TCP transaction as well (if there is one)
      if (taFound==true)
      {
         tcpConn.transactionList[direction].front().signPacketsSeenAMP++;
         tcpConn.transactionList[direction].front().signPacketsLostAMP += (firstPacket.lossInfo == PacketTrainTCPPacket::LOST_AMP) ? 1 : 0;
         tcpConn.transactionList[direction].front().signPacketsLostAMPTS += (firstPacket.lossTSInfo == PacketTrainTCPPacket::LOST_AMP_TS) ? 1 : 0;
         tcpConn.transactionList[direction].front().signPacketsRetrAMP += (firstPacket.ampLossCandidate == true) ? 1 : 0;
      }
   }
   // Update significant BMP loss related variables
   if (firstPacket.signBMP == true)
   {
      // Update TCP connections
      tcpConn.signPacketsSeenBMP[direction]++;
      tcpConn.signPacketsLostBMP[direction] += (firstPacket.lossInfo == PacketTrainTCPPacket::LOST_BMP) ? 1 : 0;
      tcpConn.signPacketsReorderedBMP[direction] += (firstPacket.reordered == true) ? 1 : 0;
      // Update TCP transaction as well (if there is one)
      if (taFound==true)
      {
         tcpConn.transactionList[direction].front().signPacketsSeenBMP++;
         tcpConn.transactionList[direction].front().signPacketsLostBMP += (firstPacket.lossInfo == PacketTrainTCPPacket::LOST_BMP) ? 1 : 0;
         tcpConn.transactionList[direction].front().signPacketsReorderedBMP += (firstPacket.reordered == true) ? 1 : 0;
      }
   }
   // Calculate next expected SEQ for consecutiveness check
   unsigned long expectedSeq = firstPacket.seq + firstPacket.len;

   // Remove the first packet
   tcpConn.packetTrains[direction].RemoveFirstPacket();

   // Check consecutiveness for already ACKed packets (if the list is not empty)
   if ((!tcpConn.packetTrains[direction].packetTrainList.empty()) && (expectedSeq < tcpConn.highestACKSeen[1-direction]))
   {
      if (tcpConn.packetTrains[direction].packetTrainList.front().packetList.front().seq > expectedSeq)
      {
         // Hole in the packet history -> invalidate loss
         tcpConn.lossReliable = false;
         tcpConn.tsLossReliable = false;
         tcpConn.captureLoss = true;
         // Update possible transaction as well
         if (taFound==true)
         {
            tcpConn.transactionList[direction].front().lossReliable = false;
            tcpConn.transactionList[direction].front().captureLoss = true;
         }
         // Logging
         if (staple.logLevel >= 3)
         {
            staple.logStream << " - hole in the packet history (loss unreliable)";
         }
      }
   }

   return true;
}

// Finish all connections (when parsing is completed)
void Parser::FinishConnections()
{
   tcpIndex = staple.tcpConnReg.begin();
   while (tcpIndex != staple.tcpConnReg.end())
   {
      TCPConnReg::iterator eraseIndex = tcpIndex++;
      ReleaseTCPConnection(eraseIndex);
   }
   // Finish ongoing IP sessions
   ipIndex = staple.ipSessionReg.begin();
   while (ipIndex != staple.ipSessionReg.end())
   {
      IPSessionReg::iterator eraseIndex = ipIndex++;
      ReleaseIPSession(eraseIndex);
   }
}

bool Parser::PrintTCPStatistics (TCPConnReg::iterator& tcpPrintIndex, std::ostream& outStream)
{
   // Get TCP connection
   TCPConn& tcpConn = tcpPrintIndex->second;
   for (unsigned short dir=0;dir<=1;dir++)
   {
      // Print statistics for remaining TCP transactions
      // -----------------------------------------------
      while (!tcpConn.transactionList[dir].empty())
      {
         // Print overall reports only (last partial report is written at FinishTCPTA())
         PrintTCPTAStatistics(tcpPrintIndex,tcpConn.transactionList[dir].front(),dir,true,true);
         tcpConn.transactionList[dir].pop_front();
      }
   }
   return true;
}

bool Parser::PrintTCPTAStatistics (TCPConnReg::iterator& tcpPrintIndex, TCPTransaction& tcpTA, unsigned short dir, bool overall, bool last)
{
   // Get TCP connection
   TCPConn& tcpConn = tcpPrintIndex->second;
   const TCPConnId& tcpConnId = tcpPrintIndex->first;

   // Calculate report boundary variables: the last report is up to the lastButHighestDataACK (irrespective to ACK compression)
   struct timeval reportLastTime = ((last==true) ? tcpTA.lastButHighestDataACKTime : tcpTA.reportLastTime);
   unsigned long reportLastIPByte = ((last==true) ? tcpTA.lastButHighestACKedIPByte[dir] : tcpTA.reportLastIPByte);
   unsigned long reportLastIPSessionByte = ((last==true) ? tcpTA.lastButHighestACKedIPSessionByte[dir] : tcpTA.reportLastIPSessionByte);
   // The overall report and the first partial report is relative to the first valid ACK time (other partial reports are relative to the last report time)
   bool fromTAStart = (overall || (tcpTA.lastReport.time.tv_sec==0 && tcpTA.lastReport.time.tv_usec==0));
   struct timeval reportFirstTime = ((fromTAStart==true) ? tcpTA.reportFirstTime : tcpTA.lastReport.time);
   unsigned long reportFirstIPByte = ((fromTAStart==true) ? tcpTA.reportFirstIPByte : tcpTA.lastReport.reportLastIPByte);
   unsigned long reportFirstIPSessionByte = ((fromTAStart==true) ? tcpTA.reportFirstIPSessionByte : tcpTA.lastReport.reportLastIPSessionByte);

   struct timeval timeDiff = AbsTimeDiff(reportLastTime, reportFirstTime);
   double tDiff = timeDiff.tv_sec + (double)timeDiff.tv_usec/1000000;
   // dataReceived is cumulative
   unsigned long dataReceived = (tcpTA.lastButHighestDataACKSeen!=0) ? (tcpTA.lastButHighestDataACKSeen-tcpTA.firstDataPacketSeq) : 0;

   // Print report if (report is progress report [but not the one & only] || we already had a report for this flow || flow is valid and long enough)
   if (((overall==false) && !((last==true) && ((tcpTA.lastReport.time.tv_sec==0)&&(tcpTA.lastReport.time.tv_usec==0)))) ||
      ((tcpTA.lastReport.time.tv_sec!=0)||(tcpTA.lastReport.time.tv_usec!=0)) ||
      (((tcpTA.reportLastTime.tv_sec!=0)||(tcpTA.reportLastTime.tv_usec!=0)) && (tDiff>0) && (dataReceived>TCPTA_MINSIZE)))
   {
      #define MINTDIFF     0.010 // Min. time intervall for which a meaningful TP calculation can be made (recommended: 0.050)
      unsigned long MINDATA = 1; // Min. amount of data for which a meaningful TP calculation can be made (recommended: 50K)
      // Start time is first valid DATA ACK time -or- last report time
      long double tstart =  reportFirstTime.tv_sec + reportFirstTime.tv_usec/1e6;

      // Calculate IP bytes related variables
      unsigned long IPBytes = (reportLastIPByte!=0) ? (reportLastIPByte-reportFirstIPByte) : 0;
      unsigned long IPSessionBytes = (reportLastIPSessionByte!=0) ? (reportLastIPSessionByte-reportFirstIPSessionByte) : 0;
      double tcpTP = 8*(double)IPBytes/tDiff;
      double tcpSessionTP = 8*(double)IPSessionBytes/tDiff;
//      double revTP = 8*(double)IPBytes[1-dir]/tDiff;
//      double revSessionTP = 8*(double)IPSessionBytes[1-dir]/tDiff;
      double aloneRatio = (((double)IPSessionBytes)/IPBytes)-1;

      // Calculate ssEnd related variables
      bool ssEndReached = (((tcpTA.ssEndACKTime.tv_sec!=0) || (tcpTA.ssEndACKTime.tv_usec!=0)) &&
                          ((tcpTA.ssEndACKTime.tv_sec<reportLastTime.tv_sec) || ((tcpTA.ssEndACKTime.tv_sec==reportLastTime.tv_sec) && (tcpTA.ssEndACKTime.tv_usec<reportLastTime.tv_usec))));
      bool ssEndReported = ((!overall) &&
                           ((tcpTA.lastReport.time.tv_sec >= tcpTA.ssEndACKTime.tv_sec) || ((tcpTA.lastReport.time.tv_sec == tcpTA.ssEndACKTime.tv_sec) && (tcpTA.lastReport.time.tv_usec >= tcpTA.ssEndACKTime.tv_usec))));
      // tSS is absolute value
      struct timeval ss = AbsTimeDiff(tcpTA.ssEndACKTime, tcpTA.reportFirstTime);
      double tSS = ss.tv_sec + (double)ss.tv_usec/1000000;
      // Calculate nonSS-TP
      unsigned long ssEndIPSessionBytes;
      double nonSSTDiff;
      // Partial report?
      if (overall==false)
      {
         // First report after slow start ended?
         if (ssEndReported==false)
         {
            ssEndIPSessionBytes = (reportLastIPSessionByte!=0) ? (reportLastIPSessionByte - tcpTA.ssEndIPSessionBytes) : 0;
            struct timeval timeDiff = AbsTimeDiff(reportLastTime, tcpTA.ssEndACKTime);
            nonSSTDiff = timeDiff.tv_sec + (double)timeDiff.tv_usec/1000000;
         }
         else
         {
            ssEndIPSessionBytes = IPSessionBytes;
            nonSSTDiff = tDiff;
         }
      }
      else
      {
         ssEndIPSessionBytes = tcpTA.ssEndIPSessionBytes;
         nonSSTDiff = tDiff-tSS;
      }
      double tcpSessionTPNoSS = 8*(double)ssEndIPSessionBytes/nonSSTDiff;

      // Store values for the next report
      if ((overall==false) && (last==false))
      {
         tcpTA.lastReport.reportLastIPByte = reportLastIPByte;
         tcpTA.lastReport.reportLastIPSessionByte = reportLastIPSessionByte;
         tcpTA.lastReport.time = reportLastTime;
      }

      // Update TCPTA log stats
      TCPStats& tcpStats = staple.tcpStats;
      tcpStats.allTCPTALogNum++;
      struct timeval reordDiff = AbsTimeDiff(reportLastTime, staple.actTime);
      double tReordDiff = reordDiff.tv_sec + (double)reordDiff.tv_usec/1000000;
      if (tReordDiff>=60)
      {
         tcpStats.old60TCPTALogNum++;
      }

      // Print
      if (!(overall ? perfmonTCPTAFile : perfmonTCPTAPartialFile))
         return true;
      
      pthread_mutex_lock(&perfmonFileMutex);

      std::ostringstream event;

      event << std::setprecision(6) << std::fixed
              << tstart << "\t" << tDiff << "\t"
              << (unsigned) (tcpConnId.netAIP.byte[3]) << "." << (unsigned) (tcpConnId.netAIP.byte[2]) << "."
              << (unsigned) (tcpConnId.netAIP.byte[1]) << "." << (unsigned) (tcpConnId.netAIP.byte[0]) << "\t"
              << tcpConnId.netAPort << "\t"
              << (unsigned) (tcpConnId.netBIP.byte[3]) << "." << (unsigned) (tcpConnId.netBIP.byte[2]) << "."
              << (unsigned) (tcpConnId.netBIP.byte[1]) << "." << (unsigned) (tcpConnId.netBIP.byte[0]) << "\t"
              << tcpConnId.netBPort << "\t"
              << dir << "\t"
              << dataReceived << "\t";
      
      if ((tDiff>=MINTDIFF) && (IPBytes>=MINDATA))
         event << tcpTP;
      else
         event << "\\N";
      event << "\t";
      
      if ((tDiff>=MINTDIFF) && (IPSessionBytes>=MINDATA))
         event << tcpSessionTP;
      else
         event << "\\N";
      event << "\t";
      
      if ((ssEndReached) && (nonSSTDiff>=MINTDIFF) && (ssEndIPSessionBytes>=MINDATA))
         event << tcpSessionTPNoSS;
      else
         event << "\\N";
      event << "\t";
         
      if (tcpTA.CRDuration > 0)
         event << tcpTA.CRMeanTP/tcpTA.CRDuration;
      else
         event << "\\N";
      event << "\t";
      
//      fprintf(event, "\\N\t"); // burst_throughput
//      fprintf(event, "\\N\t"); // burst_duration
//      fprintf(event, "%f\t", revTP);        // rev_tp
//      fprintf(event, "%f\t", revSessionTP); // rev_tp
      event << aloneRatio << "\t";
/*
      fprintf(event, "%u\t", tcpConn.initRWndSize[0]); // rwin_tcpini
      fprintf(event, "\\N\t"); // rwin_ini
      fprintf(event, "\\N\t"); // rwin_min
      // rwin_avg
      if (tcpTA.flightSizeTimeSum>0)
      {
         fprintf(event, "%f\t",tcpTA.flightSizeMean/tcpTA.flightSizeTimeSum);
      }
      else
      {
         fprintf(event, "\\N\t");
      }
*/
      event << tcpConn.maxRWndSize[0] << "\t"; // TBD!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! (change to TA)
/*
      // scf_client
      if (tcpConn.wndScaleSeen[0])
      {
         fprintf(event, "%u\t", (unsigned int)tcpConn.wndScaleVal[0]);
      }
      else
      {
         fprintf(event, "\\N\t");
      }
      // scf_serv
      if (tcpConn.wndScaleSeen[1])
      {
         fprintf(event, "%u\t", (unsigned int)tcpConn.wndScaleVal[1]);
      }
      else
      {
         fprintf(event, "\\N\t");
      }
*/
      if ((tcpConn.initialRTT[0]!=-1) && (tcpConn.unloadedSetup==true))
         event << tcpConn.initialRTT[0] << "\t";
      else
         event << "\\N\t";
      if (tcpConn.initialRTT[1]!=-1)
         event << tcpConn.initialRTT[1] << "\t";
      else
         event << "\\N\t";
      event << (tcpConn.maxDataPacketIPLen[0] > tcpConn.maxDataPacketIPLen[1] ? tcpConn.maxDataPacketIPLen[0] : tcpConn.maxDataPacketIPLen[1]) << "\t";
      
      if ((WRITE_SRTO_STATS==true) || (tcpTA.lossReliable==true))
      {
         // Calculate srtxperiod, nrtxperiod, ampnrtxperiod, bmpnrtxperiod
         std::list<TCPConn::RTXPeriodListEntry>::iterator listIndex = tcpConn.rtxPeriodList[dir].begin();
         unsigned long srtxperiod=0;
         unsigned long nrtxperiod=0;
         unsigned long ampnrtxperiod=0;
         unsigned long bmpnrtxperiod=0;
         while (listIndex != tcpConn.rtxPeriodList[dir].end())
         {
            // Only process RTX periods within the TCPTA bounds
            if ((*listIndex).seq < tcpTA.firstDataPacketSeq)
            {
               listIndex++;
               continue;
            }
            if ((*listIndex).seq >= tcpTA.lastButHighestDataACKSeen) break;
            // RTX period is within the transaction
            srtxperiod += (((*listIndex).type==2) ? 1 : 0);
            nrtxperiod += (((*listIndex).type==3) ? 1 : 0);
            ampnrtxperiod += ((((*listIndex).type == 3) && ((unsigned short)((*listIndex).lossInfo) == 2)) ? 1 : 0);
            bmpnrtxperiod += ((((*listIndex).type == 3) && ((unsigned short)((*listIndex).lossInfo) == 1)) ? 1 : 0);
            // Next
            listIndex++;
         }
         if (dir==0)
         {
            if (tcpTA.signPacketsSeenBMP!=0)
               event << ((double)tcpTA.signPacketsLostBMP)/tcpTA.signPacketsSeenBMP << "\t";
            else
               event << "\\N\t";
            if (tcpTA.signPacketsSeenAMP!=0)
               event << ((double)tcpTA.signPacketsLostAMP)/tcpTA.signPacketsSeenAMP << "\t";
            else
               event << "\\N\t";
            if (WRITE_SRTO_STATS==true) event << srtxperiod << "\t" << nrtxperiod << "\t" << bmpnrtxperiod << "\t" << ampnrtxperiod << "\t"
                                                << (unsigned short)(tcpTA.rtxDataOffset) << "\t" << (unsigned short)(tcpTA.captureLoss) << "\t";
         }
         else
         {
            if (tcpTA.signPacketsSeenAMP!=0)
               event << ((double)tcpTA.signPacketsLostAMP)/tcpTA.signPacketsSeenAMP << "\t";
            else
               event << "\\N\t";
            if (tcpTA.signPacketsSeenBMP!=0)
               event << ((double)tcpTA.signPacketsLostBMP)/tcpTA.signPacketsSeenBMP << "\t";
            else
               event << "\\N\t";
            if (WRITE_SRTO_STATS==true) event << srtxperiod << "\t" << nrtxperiod << "\t" << ampnrtxperiod << "\t" << bmpnrtxperiod << "\t"
                                                << (unsigned short)(tcpTA.rtxDataOffset) << "\t" << (unsigned short)(tcpTA.captureLoss) << "\t";
         }
      }
      else
      {
         event << "\\N\t\\N\t";
         if (WRITE_SRTO_STATS==true) event << "\\N\t\\N\t\\N\t\\N\t\\N\t\\N\t";
      }
      
      if (!tcpTA.contentType.empty())
      {
         event << tcpTA.contentType << "\t";
      }
      else if (tcpConn.isTorrent)
      {
         event << "BitTorrent\t";
      }
      else
      {
         event << "\\N\t";
      }
      if (!tcpTA.lastRevReqHost.empty())
      {
         event << tcpTA.lastRevReqHost << "\t";
      }
      else
      {
         event << "\\N\t";
      }
      if (!tcpTA.lastRevReqURI.empty())
      {
         // Extract file extension from URI
         std::string::size_type pos = tcpTA.lastRevReqURI.rfind('.');
         std::string::size_type uriLen = tcpTA.lastRevReqURI.length();
         if ((pos != std::string::npos) && ((uriLen-(pos+1)) <= 10) && (pos != (uriLen-1)))
         {
            std::string ext = tcpTA.lastRevReqURI.substr(pos+1,uriLen-(pos+1));
            event << ext;
         }
         else
         {
            event << "\\N";
         }
      }
      else
      {
         event << "\\N";
      }
/*
      if (!tcpConn.userAgent.empty())
      {
         fprintf(event, "%s", tcpConn.userAgent.c_str());
      }
      else
      {
         fprintf(event, "\\N");
      }
*/
      event << "\n";

      if (writeToFile){
          std::ostream & actFile = *(overall ? perfmonTCPTAFile : perfmonTCPTAPartialFile);
    	  actFile << event.str();
      }
      if (hazelcastPublish){
    	  StapleJniImpl staple;
    	  staple.publishEvent((overall ? staple.TCPTA : staple.TCPTA_PARTIAL), event.str());
      }


      pthread_mutex_unlock(&perfmonFileMutex);
      return true;
   }
   else
   {
      return false;
   }
}

void Parser::PrintOverallStatistics (std::ostream& outStream)
{
   IPStats& ipStats = staple.ipStats;
   TCPStats& tcpStats = staple.tcpStats;
   UDPStats& udpStats = staple.udpStats;
   ICMPStats& icmpStats = staple.icmpStats;

   // This must be called to update the stats.
   httpEngine.finishAllTCPSessions();
   const HTTPStats& httpStats(httpEngine.getStats());
   FLVStats& flvStats = staple.flvStats;
   MP4Stats& mp4Stats = staple.mp4Stats;

   
   outStream << "Overall summary\n";
   outStream << "===============\n";
   outStream << "Trace:\n";
   outStream << "------\n";
   long double traceStart = staple.traceStartTime.tv_sec + (double) staple.traceStartTime.tv_usec/1000000;
   long double traceEnd = staple.actTime.tv_sec + (double)staple.actTime.tv_usec/1000000;
   outStream << "Trace interval: from " << staple.traceStartTime.tv_sec << "s to " << staple.actTime.tv_sec << "s (duration: " << traceEnd-traceStart << "s)\n";
   outStream << "Timestamp reorderings: " << (long) staple.tsMinorReorderingNum + (long) staple.tsMajorReorderingNum << " times\n";
   outStream << "   -major (>=" << TS_MAJOR_REORDERING_THRESH << "s): " << staple.tsMajorReorderingNum << " times\n";
   outStream << "   -minor (<" << TS_MAJOR_REORDERING_THRESH << "s): " << staple.tsMinorReorderingNum << " times\n";
   outStream << "Timestamp jumps (>" << TS_JUMP_THRESH << "s): " << staple.tsJumpNum << " times (" << staple.tsJumpLen << "s)\n";
   outStream << "Overall number of packets read from file: " << staple.packetsRead << "\n";
   outStream << "   IP:           " << ipStats.packetsRead << " (" << ipStats.kBytesRead << " Kbytes)\n";
   outStream << "   -TCP:         " << tcpStats.packetsRead << " (" << tcpStats.kBytesRead << " Kbytes)\n";
   outStream << "   -UDP:         " << udpStats.packetsRead << " (" << udpStats.kBytesRead << " Kbytes)\n";
   outStream << "   -ICMP:        " << icmpStats.packetsRead << " (" << icmpStats.kBytesRead << " Kbytes)\n";
   outStream << "   -Other:       " << (ipStats.packetsRead-tcpStats.packetsRead-udpStats.packetsRead-icmpStats.packetsRead) << " (" << (ipStats.kBytesRead-tcpStats.kBytesRead-udpStats.kBytesRead-icmpStats.kBytesRead) << " Kbytes)\n";
   if (staple.ignoreL2Duplicates)
   {
      outStream << "L2 duplicate stats (every second L2 duplicate decoding was " << ((DECODE_EVERY_SECOND_L2_DUPLICATE==true) ? "ON" : "OFF") << "):\n";
      for (int i=0;i<DUPSTATS_MAX;i++)
      {
         outStream << "   -" << i << "  dups: " << staple.packetsDuplicated[i] << " (all), " << ipStats.packetsDuplicated[i] << " (IP)\n";
      }
      outStream << "   -" << DUPSTATS_MAX << "+ dups: " << staple.packetsDuplicated[DUPSTATS_MAX] << " (all), " << ipStats.packetsDuplicated[DUPSTATS_MAX] << " (IP)\n";
   }
   outStream << "Overall number of matching IP packets seen:\n";
   outStream << "   IP      A->B: " << ipStats.packetsMatched[0] << " (" << ipStats.kBytesMatched[0] << " Kbytes)\n";
   outStream << "   IP      B->A: " << ipStats.packetsMatched[1] << " (" << ipStats.kBytesMatched[1] << " Kbytes)\n";
   outStream << "   -TCP    A->B: " << tcpStats.packetsMatched[0] << " (" << tcpStats.kBytesMatched[0] << " Kbytes)\n";
   outStream << "   -TCP    B->A: " << tcpStats.packetsMatched[1] << " (" << tcpStats.kBytesMatched[1] << " Kbytes)\n";
   outStream << "   -UDP    A->B: " << udpStats.packetsMatched[0] << " (" << udpStats.kBytesMatched[0] << " Kbytes)\n";;
   outStream << "   -UDP    B->A: " << udpStats.packetsMatched[1] << " (" << udpStats.kBytesMatched[1] << " Kbytes)\n";
   outStream << "   -ICMP   A->B: " << icmpStats.packetsMatched[0] << " (" << icmpStats.kBytesMatched[0] << " Kbytes)\n";
   outStream << "   -ICMP   B->A: " << icmpStats.packetsMatched[1] << " (" << icmpStats.kBytesMatched[1] << " Kbytes)\n";
   outStream << "   -Other: A->B: " << (ipStats.packetsMatched[0]-tcpStats.packetsMatched[0]-udpStats.packetsMatched[0]-icmpStats.packetsMatched[0]) << " (" << (ipStats.kBytesMatched[0]-tcpStats.kBytesMatched[0]-udpStats.kBytesMatched[0]-icmpStats.kBytesMatched[0]) << " Kbytes)\n";
   outStream << "   -Other: B->A: " << (ipStats.packetsMatched[1]-tcpStats.packetsMatched[1]-udpStats.packetsMatched[1]-icmpStats.packetsMatched[1]) << " (" << (ipStats.kBytesMatched[1]-tcpStats.kBytesMatched[1]-udpStats.kBytesMatched[1]-icmpStats.kBytesMatched[1]) << " Kbytes)\n";
   outStream << "TCP:\n";
   outStream << "----\n";
   outStream << "Overall number of TCP connections seen: " << tcpStats.tcpsSeen << "\n";
   outStream << "   -standalone: " << tcpStats.standalone << "\n";
   outStream << "   -both ends SACK permitted: " << tcpStats.SACKPermitted << "\n";
   outStream << "   -both ends supporting TCP timestamps: " << tcpStats.TSSeen << "\n";
   outStream << "   -low MSS:     A->B " << tcpStats.mssLow[0] <<  " B->A " << tcpStats.mssLow[1] << "\n";
   outStream << "   -high MSS:    A->B " << tcpStats.mssHigh[0] << " B->A " << tcpStats.mssHigh[1] << "\n";
   outStream << "   -low window:  A->B " << tcpStats.wndLow[0] << " B->A " << tcpStats.wndLow[1] << "\n";
   outStream << "   -med window:  A->B " << tcpStats.wndMed[0] << " B->A " << tcpStats.wndMed[1] << "\n";
   outStream << "   -high window: A->B " << tcpStats.wndHigh[0] << " B->A " << tcpStats.wndHigh[1] << "\n";
   outStream << "   -FIN terminated: " << tcpStats.termFIN << "\n";
   outStream << "   -RST terminated: " << tcpStats.termRST << "\n";
   outStream << "   -timeout terminated: " << tcpStats.termTO << "\n";
   outStream << "Overall number of TCP data packets seen:\n";
   outStream << "   A->B: " << tcpStats.dataPacketsSeen[0] << "\n";
   outStream << "   B->A: " << tcpStats.dataPacketsSeen[1] << "\n";
   outStream << "Overall number of TCP connections seen reliable for loss estimation: " << tcpStats.lossReliable << "\n";
   outStream << "Overall number of TCP connections seen reliable for timestamp-based loss estimation: " << tcpStats.tsLossReliable << "\n";
   outStream << "Overall number of significant TCP packets seen:\n";
   outStream << "   A->B: NetA (BMP) " << tcpStats.signPacketsSeenBMP[0] << " NetB (AMP) " << tcpStats.signPacketsSeenAMP[0] << "\n";
   outStream << "   B->A: NetA (AMP) " << tcpStats.signPacketsSeenAMP[1] << " NetB (BMP) " << tcpStats.signPacketsSeenBMP[1] << "\n";
   outStream << "Overall estimated TCP packet loss:\n";

   double ratioNetA = 0, ratioNetB = 0;
   if (tcpStats.signPacketsSeenBMP[0] != 0)
   {
      ratioNetA = ((double)tcpStats.signPacketsLostBMP[0])/tcpStats.signPacketsSeenBMP[0];
   }
   if (tcpStats.signPacketsSeenAMP[0] != 0)
   {
      ratioNetB = ((double)tcpStats.signPacketsLostAMP[0])/tcpStats.signPacketsSeenAMP[0];
   }
   outStream << "   A->B NetA (BMP) " << tcpStats.signPacketsLostBMP[0] << " [" << 100*ratioNetA << "%] NetB (AMP) " << tcpStats.signPacketsLostAMP[0] << " [" << 100*ratioNetB << "%]\n";

   ratioNetA = 0; ratioNetB = 0;
   if (tcpStats.signPacketsSeenAMP[1] != 0)
   {
      ratioNetA = ((double)tcpStats.signPacketsLostAMP[1])/tcpStats.signPacketsSeenAMP[1];
   }
   if (tcpStats.signPacketsSeenBMP[1] != 0)
   {
      ratioNetB = ((double)tcpStats.signPacketsLostBMP[1])/tcpStats.signPacketsSeenBMP[1];
   }
   outStream << "   B->A NetA (AMP) " << tcpStats.signPacketsLostAMP[1] << " [" << 100*ratioNetA << "%] NetB (BMP) " << tcpStats.signPacketsLostBMP[1] << " [" << 100*ratioNetB << "%]\n";

   outStream << "Overall timestamp-based significant TCP packet loss (AMP):\n";

   double ratioOriginal = 0;
   double ratioValidation = 0;
   if (tcpStats.signPacketsSeenAMPTS[0] != 0)
   {
      ratioOriginal = ((double)tcpStats.signPacketsLostAMPTSOriginal[0])/tcpStats.signPacketsSeenAMPTS[0];
      ratioValidation = ((double)tcpStats.signPacketsLostAMPTSValidation[0])/tcpStats.signPacketsSeenAMPTS[0];
   }
   outStream << "   A->B original " << tcpStats.signPacketsLostAMPTSOriginal[0] << " [" << 100*ratioOriginal << "%] validation " << tcpStats.signPacketsLostAMPTSValidation[0] << " [" << 100*ratioValidation << "%]\n";
   if (tcpStats.signPacketsSeenAMPTS[1] != 0)
   {
      ratioOriginal = ((double)tcpStats.signPacketsLostAMPTSOriginal[1])/tcpStats.signPacketsSeenAMPTS[1];
      ratioValidation = ((double)tcpStats.signPacketsLostAMPTSValidation[1])/tcpStats.signPacketsSeenAMPTS[1];
   }
   outStream << "   B->A original " << tcpStats.signPacketsLostAMPTSOriginal[1] << " [" << 100*ratioOriginal << "%] validation " << tcpStats.signPacketsLostAMPTSValidation[1] << " [" << 100*ratioValidation << "%]\n";
   outStream << "Overall number of retransmission periods:\n";
   outStream << "   A->B: " << tcpStats.rtxPeriods[0] << " (" << (double)tcpStats.rtxPeriods[0]/tcpStats.lossReliable << " retransmission events/TCP)\n";
   outStream << "   B->A: " << tcpStats.rtxPeriods[1] << " (" << (double)tcpStats.rtxPeriods[1]/tcpStats.lossReliable << " retransmission events/TCP)\n";
   outStream << "Overall loss reliable payload seen:\n";
   outStream << "   A->B: " << tcpStats.kBytesPL[0] << " Kbytes (already seen: " << tcpStats.kBytesPLAlreadySeen[0] << " Kbytes [" << (100*(double)tcpStats.kBytesPLAlreadySeen[0]/tcpStats.kBytesPL[0]) << "%])\n";
   outStream << "   B->A: " << tcpStats.kBytesPL[1] << " Kbytes (already seen: " << tcpStats.kBytesPLAlreadySeen[1] << " Kbytes [" << (100*(double)tcpStats.kBytesPLAlreadySeen[1]/tcpStats.kBytesPL[1]) << "%])\n";
   outStream << "HTTP:\n";
   outStream << "-----\n";
   outStream << "Overall number of HTTP sessions seen: " << httpStats.sessionsSeen << "\n";
   outStream << "Overall number of HTTP pages seen: " << httpStats.pagesSeen << " (" << ((double)httpStats.pagesSeen/httpStats.sessionsSeen) << " pages/session)\n";
   outStream << "Overall number of HTTP session IP packets seen:\n";
   outStream << "   A->B: " << httpStats.packetsSeen[0] << " packets (" << httpStats.IPBytes[0]/1024 << " Kbytes)\n";
   outStream << "         " << ((double)httpStats.packetsSeen[0]/httpStats.sessionsSeen) << " packets/session (" << (httpStats.IPBytes[0]/1024.0/httpStats.sessionsSeen) << " Kbytes/session)\n";
   outStream << "         " << ((double)httpStats.packetsSeen[0]/httpStats.pagesSeen) << " packets/page (" << (httpStats.IPBytes[0]/1024.0/httpStats.pagesSeen) << " Kbytes/page)\n";
   outStream << "   B->A: " << httpStats.packetsSeen[1] << " packets (" << httpStats.IPBytes[1]/1024 << " Kbytes)\n";
   outStream << "         " << ((double)httpStats.packetsSeen[1]/httpStats.sessionsSeen) << " packets/session (" << (httpStats.IPBytes[1]/1024.0/httpStats.sessionsSeen) << " Kbytes/session)\n";
   outStream << "         " << ((double)httpStats.packetsSeen[1]/httpStats.pagesSeen) << " packets/page (" << (httpStats.IPBytes[1]/1024.0/httpStats.pagesSeen) << " Kbytes/page)\n";
   outStream << "Overall amount of application data transferred:\n";
   outStream << "   A->B: " << httpStats.httpBytes[0]/1024 << " Kbytes (" << (httpStats.httpBytes[0]/1024.0/httpStats.sessionsSeen) << " Kbytes/session, " << ((double)httpStats.httpBytes[0]/1024.0/httpStats.pagesSeen) << " Kbytes/page)\n";
   outStream << "   B->A: " << httpStats.httpBytes[1]/1024 << " Kbytes (" << (httpStats.httpBytes[1]/1024.0/httpStats.sessionsSeen) << " Kbytes/session, " << ((double)httpStats.httpBytes[1]/1024.0/httpStats.pagesSeen) << " Kbytes/page)\n";
   outStream << "Overall number of TCP connections seen: " << httpStats.tcpNum << " (" << ((double)httpStats.tcpNum/httpStats.sessionsSeen) << " TCP/session, " << ((double)httpStats.tcpNum/httpStats.pagesSeen) << " TCP/page)\n";
   outStream << "Overall number of HTTP requests seen: " << httpStats.reqNum << " (" << ((double)httpStats.reqNum/httpStats.sessionsSeen) << " REQ/session, " << ((double)httpStats.reqNum/httpStats.pagesSeen) << " REQ/page)\n";
   outStream << "Overall number of HTTP responses seen: " << httpStats.rspNum << " (" << ((double)httpStats.rspNum/httpStats.sessionsSeen) << " RSP/session, " << ((double)httpStats.rspNum/httpStats.pagesSeen) << " RSP/page)\n";
   outStream << "FLV:\n";
   outStream << "----\n";
   outStream << "Overall number of FLV sessions seen:\n";
   outStream << "   A->B: " << flvStats.sessionsSeen[0] << "\n";
   outStream << "   B->A: " << flvStats.sessionsSeen[1] << "\n";
   outStream << "Overall amount of FLV data transferred:\n";
   outStream << "   A->B: " << flvStats.kBytes[0] << " Kbytes (" << ((double)flvStats.kBytes[0]/flvStats.sessionsSeen[0]) << " Kbytes/session)\n";
   outStream << "   B->A: " << flvStats.kBytes[1] << " Kbytes (" << ((double)flvStats.kBytes[1]/flvStats.sessionsSeen[1]) << " Kbytes/session)\n";
   outStream << "Average FLV transport duration:\n";
   outStream << "   A->B: " << ((double)flvStats.duration[0]/flvStats.sessionsSeen[0]) << " s\n";
   outStream << "   B->A: " << ((double)flvStats.duration[1]/flvStats.sessionsSeen[1]) << " s\n";
   outStream << "Average QoE score:\n";
   outStream << "   A->B: " << (flvStats.qoe[0]/flvStats.qoeNum[0]) << " (" << flvStats.qoeNum[0] << " reports)\n";
   outStream << "   B->A: " << (flvStats.qoe[1]/flvStats.qoeNum[1]) << " (" << flvStats.qoeNum[1] << " reports)\n";
   outStream << "MP4:\n";
   outStream << "----\n";
   outStream << "Overall number of MP4 sessions seen:\n";
   outStream << "   A->B: " << mp4Stats.sessionsSeen[0] << "\n";
   outStream << "   B->A: " << mp4Stats.sessionsSeen[1] << "\n";
   // Processing speed
   struct timeval stopRealTime;
   struct timezone tmpZone;
   gettimeofday(&stopRealTime,&tmpZone);
   struct timeval timeDiff = AbsTimeDiff(stopRealTime, staple.startRealTime);
   double tDiff = timeDiff.tv_sec + (double)timeDiff.tv_usec/1000000;
   outStream << "Processing time: " << tDiff << " s\n";
   outStream << "   " << ipStats.packetsRead/tDiff << " overall IP packets/s (" << ipStats.kBytesRead/tDiff << " Kbytes/s)\n";
   outStream << "   " << (ipStats.packetsMatched[0]+ipStats.packetsMatched[1])/tDiff << " matching IP packets/s (" << (ipStats.kBytesMatched[0]+ipStats.kBytesMatched[1])/tDiff << " Kbytes/s)\n";

   // Overall Excel table line (summary info)
   outStream << "---Delimiter---\n";
   unsigned long ipPktNum = ipStats.packetsMatched[0]+ipStats.packetsMatched[1];
   unsigned long ipKBytes = ipStats.kBytesMatched[0]+ipStats.kBytesMatched[1];
   outStream.precision(2);
   outStream.setf(std::ios::fixed);
   outStream << ((traceEnd-traceStart)/3600) << "h "
             << ipPktNum << " "
             << (100*(double)(httpStats.packetsSeen[0]+httpStats.packetsSeen[1])/ipPktNum) << "% "
             << (100*(double)(tcpStats.packetsMatched[0]+tcpStats.packetsMatched[1])/ipPktNum) << "% "
             << (100*(double)(udpStats.packetsMatched[0]+udpStats.packetsMatched[1])/ipPktNum) << "% "
             << ((double)ipKBytes/1048576) << "GB "
             << (100*(double)(httpStats.IPBytes[0]/1024.0+httpStats.IPBytes[1]/1024.0)/ipKBytes) << "% "
             << (100*(double)(tcpStats.kBytesMatched[0]+tcpStats.kBytesMatched[1])/ipKBytes) << "% "
             << (100*(double)(udpStats.kBytesMatched[0]+udpStats.kBytesMatched[1])/ipKBytes) << "%\n";

   // TCP Excel table line (summary info)
   outStream << "---Delimiter---\n";
   outStream << tcpStats.tcpsSeen << " "
             << tcpStats.standalone << " "
             << tcpStats.SACKPermitted << " "
             << tcpStats.TSSeen << " "
             << tcpStats.mssLow[1] << " "
             << tcpStats.mssHigh[1] << " "
             << tcpStats.wndLow[0] << " "
             << tcpStats.wndMed[0] << " "
             << tcpStats.wndHigh[0] << " "
             << tcpStats.termFIN << " "
             << tcpStats.termRST << " "
             << tcpStats.termTO << " "
             << "\n";

   httpEngine.printTestOutput();
   return;
}

void Parser::setHTTPPageLog(bool log)
{
   httpEngine.setPageLog(log);
}

void Parser::setHTTPRequestLog(bool log)
{
   httpEngine.setRequestLog(log);
}

void Parser::setHTTPPageLogStream(std::ostream* s)
{
   httpEngine.setPageLogStream(s);
}

void Parser::setHTTPRequestLogStream(std::ostream* s)
{
   httpEngine.setRequestLogStream(s);
}
