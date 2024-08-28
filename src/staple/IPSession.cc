#include <staple/IPSession.h>
#include <staple/Staple.h>
#include "Util.h"

void IPSession::Init(Staple& s)
{
   pStaple = &s;

   packetsSeen[0]=0;
   packetsSeen[1]=0;
   bytesSeen[0]=0;
   bytesSeen[1]=0;
   firstPacketTime[0].tv_sec = 0;
   firstPacketTime[0].tv_usec = 0;
   firstPacketTime[1].tv_sec = 0;
   firstPacketTime[1].tv_usec = 0;
   lastPacketTime[0].tv_sec = 0;
   lastPacketTime[0].tv_usec = 0;
   lastPacketTime[1].tv_sec = 0;
   lastPacketTime[1].tv_usec = 0;
   lastButOnePacketTime[0].tv_sec = 0;
   lastButOnePacketTime[0].tv_usec = 0;
   lastButOnePacketTime[1].tv_sec = 0;
   lastButOnePacketTime[1].tv_usec = 0;

   nTCPsInRTTCalcState[0]=0;
   nTCPsInRTTCalcState[1]=0;
   CRPipeSize[0]=0;
   CRPipeSize[1]=0;
   CRLastPipeCounter[0]=0;
   CRLastPipeCounter[1]=0;
   CRFirstByteCandidate[0]=0;
   CRFirstByteCandidate[1]=0;
   CRFirstByte[0]=0;
   CRFirstByte[1]=0;
   CRFirstACKTime[0].tv_sec=0;
   CRFirstACKTime[0].tv_usec=0;
   CRFirstACKTime[1].tv_sec=0;
   CRFirstACKTime[1].tv_usec=0;
   CRLastByte[0]=0;
   CRLastByte[1]=0;
   CRLastACKTime[0].tv_sec=0;
   CRLastACKTime[0].tv_usec=0;
   CRLastACKTime[1].tv_sec=0;
   CRLastACKTime[1].tv_usec=0;
   CRAllBytes[0]=0;
   CRAllBytes[1]=0;
   CRAllDuration[0]=0;
   CRAllDuration[1]=0;

   lastPacketLength[0] = 0;
   lastPacketLength[1] = 0;
   lastButOnePacketLength[0] = 0;
   lastButOnePacketLength[1] = 0;
   lastIPIdSeen[0]=0;
   lastIPIdSeen[1]=0;
   lastSlotData[0]=0;
   lastSlotData[1]=0;
   actSlotStartTime=0;
   actSlotData[0]=0;
   actSlotData[1]=0;
   tcpReg.clear();
}

bool IPSession::AddTCPConnection(TCPConnId& tcpConnId)
{
   tcpReg[tcpConnId] = 0;
   return true;
}

bool IPSession::RemoveTCPConnection(const TCPConnId& tcpConnId)
{
   tcpReg.erase(tcpConnId);
   return true;
}

void IPSession::IncreaseTCPsInRTTCalcState(unsigned short direction)
{
   nTCPsInRTTCalcState[direction]++;
   return;
}

void IPSession::DecreaseTCPsInRTTCalcState(unsigned short direction)
{
   nTCPsInRTTCalcState[direction]--;
   // If no more TCPs in RTT calc state & channel rate calc is ongoing -> finish channel rate calc
   if ((nTCPsInRTTCalcState[direction]==0) && (CRFirstByteCandidate[direction]!=0)) FinishChannelRateCalc(direction,true);
   return;
}

void IPSession::FinishChannelRateCalc(unsigned short direction, bool reset)
{
   Staple& staple = *pStaple;

   // There was no actual measurement
   if (CRFirstByte[direction]==0)
   {
      CRFirstByteCandidate[direction]=0;
      return;
   }
   
   // Logging
   if (staple.logLevel >= 3)
   {
      staple.logStream << " - IP channel rate calc finished at IP counter " << CRLastByte[direction] << " (" << ((direction==0)?"A->B":"B->A") << ")";
   }

   unsigned long CRBytes = CRLastByte[direction]-CRFirstByte[direction];
   struct timeval timeDiff = AbsTimeDiff(CRLastACKTime[direction],CRFirstACKTime[direction]);
   double tDiff = timeDiff.tv_sec + (double)timeDiff.tv_usec/1000000;
   // Enough time or data collected to calculate rate precisely? (and there was no ipSessionByte reordering so that channel rate end byte is after the begin byte)
   if ((CRLastByte[direction]>CRFirstByte[direction]) && ((CRBytes>=CHANNELRATE_MIN_DATA) || (tDiff>=CHANNELRATE_MIN_TIME)))
   {
      double TP = ((double)8*CRBytes/tDiff);
      // Logging
      if (staple.logLevel >= 3)
      {
         staple.logStream << "(" << CRBytes << " bytes with " << TP << " bps)";
      }
      CRAllBytes[direction] += CRBytes;
      CRAllDuration[direction] += tDiff;

      // Update ongoing transactions of all TCP flows for this IP session (what about timeouted ones?)
      TCPReg::iterator tcpIndex = tcpReg.begin();
      while (tcpIndex != tcpReg.end())
      {
         TCPConn& tcpConn = staple.tcpConnReg[(*tcpIndex).first];
         // Is there an ongoing transaction, which started earlier (or at the same time) than this channel rate measurement?
         if ((tcpConn.ongoingTransaction[direction]==true) && (tcpConn.TAFirstIPByte[direction][direction] <= CRFirstByte[direction]))
         {
            TCPTransaction& tcpTA = tcpConn.transactionList[direction].back();
            // Update the max. channel rate
            if (tcpTA.CRMaxTP < TP)
            {
               tcpTA.CRMaxTP = TP;
            }
            tcpTA.CRDuration += tDiff;
            tcpTA.CRMeanTP += (double)8*CRBytes;
         }
         // Next TCP
         tcpIndex++;
      }
   }
   
   if (reset==true)
   {
      // Reset channel rate calc variables
      CRFirstByteCandidate[direction]=0;
      CRFirstByte[direction]=0;
      CRFirstACKTime[direction].tv_sec=0;
      CRFirstACKTime[direction].tv_usec=0;
      CRLastByte[direction]=0;
      CRLastACKTime[direction].tv_sec=0;
      CRLastACKTime[direction].tv_usec=0;
   }

   return;
}
