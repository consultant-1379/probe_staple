#ifndef TCPCONN_H
#define TCPCONN_H

#include <staple/Type.h>
#include <staple/Packet.h>
#include <staple/PacketTrainList.h>
#include <staple/RangeList.h>
#include <staple/CircularBuffer.h>

#include <sys/time.h>
#include <list>
#include <map>

// Key for identifying TCP connections
// -----------------------------------
class TCPConnId {

public:
   DoubleWord        netAIP;
   DoubleWord        netBIP;
   unsigned short    netAPort;
   unsigned short    netBPort;

   // Needed for comparison (HTTP uses it)
   bool operator ==(const TCPConnId& x) const
   {
      return ((netAPort == x.netAPort) && (netBPort == x.netBPort) && (netAIP.data == x.netAIP.data) && (netBIP.data == x.netBIP.data));
   };
   void Print(std::ostream& outStream) const
   {
      outStream << (unsigned)netAIP.byte[3] << "." << (unsigned)netAIP.byte[2] << "." << (unsigned)netAIP.byte[1] << "." << (unsigned)netAIP.byte[0] << " " << netAPort << " ";
      outStream << (unsigned)netBIP.byte[3] << "." << (unsigned)netBIP.byte[2] << "." << (unsigned)netBIP.byte[1] << "." << (unsigned)netBIP.byte[0] << " " << netBPort;
   }

   bool operator< (const TCPConnId& o) const
   {
      if (netAPort != o.netAPort) return (netAPort < o.netAPort);
      if (netBPort != o.netBPort) return (netBPort < o.netBPort);
      if (netAIP.data != o.netAIP.data) return (netAIP.data < o.netAIP.data);
      return (netBIP.data < o.netBIP.data);
   }
};

std::ostream& operator<<(std::ostream& o, const TCPConnId& p);

struct TCPConnIdTraits {
#if defined(USE_HASH_MAP)
   // Hash function for TCPConnId (needed by hash_map)
   size_t operator()(const TCPConnId& x) const
   {
      return std::hash< u_int32_t >()((u_int32_t)x.netAIP.data ^ (u_int32_t)x.netBIP.data ^ (u_int32_t)x.netAPort ^ (u_int32_t)x.netBPort);
   };
   // Equality function for TCPConnId (needed by hash_map)
   bool operator()(const TCPConnId& x, const TCPConnId& y) const
   {
      return ((x.netAPort==y.netAPort) && (x.netBPort==y.netBPort) && (x.netAIP.data==y.netAIP.data) && (x.netBIP.data==y.netBIP.data));
   };
#else
   // Sorting (needed by std::map)
   bool operator() (const TCPConnId& x, const TCPConnId& y) const
   {
      if (x.netAPort != y.netAPort) return (x.netAPort < y.netAPort);
      if (x.netBPort != y.netBPort) return (x.netBPort < y.netBPort);
      if (x.netAIP.data != y.netAIP.data) return (x.netAIP.data < y.netAIP.data);
      return (x.netBIP.data < y.netBIP.data);
   }
#endif
};

inline std::size_t hash_value(const TCPConnId& x)
{
   return std::hash< u_int32_t >()((u_int32_t)x.netAIP.data ^ (u_int32_t)x.netBIP.data ^ (u_int32_t)x.netAPort ^ (u_int32_t)x.netBPort);
}

namespace std
{
   template <>
   struct hash<TCPConnId>
   {
      typedef TCPConnId argument_type;
      typedef std::size_t result_type;
      std::size_t operator() (const TCPConnId& ip) const
      {
         return hash_value(ip);
      }
   };
}

// TCP transaction data
// --------------------
class TCPTransaction {

public:
   // TCP perfmon
   std::string    contentType;
   std::string    lastRevReqURI;
   std::string    lastRevReqHost;
   #ifdef WRITE_TCPTA_FILES
      FILE*          logfile;                 // Logfile used for TCP TA log
   #endif
   typedef struct
   {
      struct timeval time;
      unsigned long  reportLastIPByte;        // needed for tcpTA.IPSessionBytes calculation
      unsigned long  reportLastIPSessionByte; // needed for tcpTA.IPBytes calculation
   } LastReport;
   LastReport     lastReport;                 // Information on the last printout

   struct timeval reportFirstTime;            // The timestamp of the first DATA ACK for which the TP report is calculated (ACK compression skipped!)
   struct timeval reportLastTime;             // The timestamp of the last DATA ACK for which the TP report is calculated (ACK compression skipped!)
   unsigned long  reportFirstIPByte;          // The IP byte counter at the first DATA packet for which the TP report is calculated
   unsigned long  reportLastIPByte;           // The IP byte counter at the last DATA packet for which the TP report is calculated
   unsigned long  reportFirstIPSessionByte;   // The IP session byte counter at the first DATA packet for which the TP report is calculated
   unsigned long  reportLastIPSessionByte;    // The IP session byte counter at the last DATA packet for which the TP report is calculated
   bool           reportStartValid;           // True if a report start ACK has been found where the next ACK was not too close in time

   struct timeval ssEndACKTime;               // The timestamp of the ACK that ends the slow start phase
   unsigned long  ssEndIPSessionBytes;        // The amount of IP session data sent AFTER the slow start phase [bytes]
   bool           ssEndValid;                 // True if slow start end time is not subject to ACK compression

   unsigned long  firstDataPacketSeq;         // The sequence number of the first DATA packet
   struct timeval firstDataPacketTime;        // The time of the first DATA packet
   struct timeval firstDataACKTime;           // The time of the first ACK that ACKs a DATA packet
   unsigned long  lastButHighestDataACKSeen;  // The acknowledge number of the ACK that acks the last but highest seq DATA packet (for filtering out the last - possibly delayed - ACK)
   struct timeval lastButHighestDataACKTime;  // The time of the ACK that acks the last but highest seq DATA packet (for filtering out the last - possibly delayed - ACK)
   unsigned long  highestDataACKSeen;         // The acknowledge number of the ACK that acks the highest seq DATA packet
   struct timeval highestDataACKTime;         // The time of the ACK that acks the highest seq DATA packet

   unsigned short highestSeqIPLength;         // The IP packet length of the highest seq. packet (to detetmine transaction end) [bytes]
   char           highestSeqTCPFlags;         // The TCP flags of the highest seq. packet (to detetmine transaction end)

   unsigned long  IPBytes[2];                 // The amount of IP data seen in this transaction [bytes]
   unsigned long  IPSessionBytes[2];          // The amount of IP session data sent during this transaction [bytes]
   unsigned long  highestACKedIPSessionByte[2];        // The IP session byte counter for the data packet corresponding to the last received ACK
   unsigned long  highestACKedIPByte[2];               // The IP byte counter for the data packet corresponding to the last received ACK
   unsigned long  lastButHighestACKedIPSessionByte[2]; // The IP session byte counter for the data packet corresponding to the last but one received ACK
   unsigned long  lastButHighestACKedIPByte[2];        // The IP byte counter for the data packet corresponding to the last but one received ACK

   // Channel rate statistics (only one-way)
   double         CRMaxTP;                    // The maximum channel rate during this transaction [bps]
   double         CRMeanTP;                   // The average channel rate during this transaction [bps]
   double         CRDuration;                 // The overall length of channel rate measurement periods for this transaction [s]

   // Loss info (only one-way)
   unsigned long  signPacketsSeenBMP;         // The number of significant packets seen for loss estimation before the meas. point
   unsigned long  signPacketsSeenAMP;         // The number of significant packets seen for loss estimation after the meas. point
   unsigned long  signPacketsRetrAMP;         // The number of AMP significant packets for which at least one retransmission was seen
   unsigned long  signPacketsReorderedBMP;    // The number of BMP significant packets that have been reordered
   unsigned long  signPacketsLostBMP;         // Estimated number of significant packets lost before the meas. point
   unsigned long  signPacketsLostAMP;         // Estimated number of significant packets lost after the meas. point
   unsigned long  signPacketsLostAMPTS;       // Number of significant packets lost after the meas. point (estimated by TCP timestamps)

   bool           lossReliable;               // True if the loss estimation algorithm is reliable (no packet boundary offset or spurTO FIN ambiguity)
   bool           rtxDataOffset;              // True if overlapping data retransmission was seen (loss is unreliable)
   bool           captureLoss;                // True if capture loss was seen (loss is unreliable)

   unsigned long  initRWndSize[2];            // The initial window size (on the first data ACK)
   unsigned long  minRWndSize[2];             // Smallest receiver window size seen [bytes]
   unsigned long  maxRWndSize[2];             // Largest receiver window size seen [bytes]
   double         meanRWndSize[2];            // Average receiver window size size [bytes]
   unsigned long  rwndsSeen[2];               // The number of receiver window advertisements seen

   double         flightSizeMean;
   unsigned long  flightSizeLastValue;
   struct timeval flightSizeLastTime;
   double         flightSizeTimeSum;

   // RTT statistics
   double         smallPipeRTT[2];            // Mean unloaded RTT [s]
   unsigned long  smallPipeRTTSamples[2];     // Number of samples for the small pipe RTT
   double         largePipeRTT[2];            // Mean loaded RTT [s]
   unsigned long  largePipeRTTSamples[2];     // Number of samples for the large pipe RTT
   double         minRTT[2];                  // The minimum RTT ever seen during the TCP transaction (-1 if none measured)
   double         maxRTT[2];                  // The maximum RTT ever seen during the TCP transaction (-1 if none measured)

   void Init()
   {
      contentType.clear();
      lastRevReqURI.clear();
      lastRevReqHost.clear();
      #ifdef WRITE_TCPTA_FILES
         logfile=NULL;
      #endif

      lastReport.time.tv_sec=0;
      lastReport.time.tv_usec=0;
      lastReport.reportLastIPByte=0;
      lastReport.reportLastIPSessionByte=0;

      reportFirstTime.tv_sec=0;
      reportFirstTime.tv_usec=0;
      reportLastTime.tv_sec=0;
      reportLastTime.tv_usec=0;
      reportFirstIPByte=0;
      reportLastIPByte=0;
      reportFirstIPSessionByte=0;
      reportLastIPSessionByte=0;
      reportStartValid=false;

      ssEndACKTime.tv_sec=0;
      ssEndACKTime.tv_usec=0;
      ssEndIPSessionBytes=0;
      ssEndValid=false;

      firstDataPacketSeq=0;
      firstDataPacketTime.tv_sec=0;
      firstDataPacketTime.tv_usec=0;
      firstDataACKTime.tv_sec=0;
      firstDataACKTime.tv_usec=0;

      lastButHighestDataACKSeen=0;
      lastButHighestDataACKTime.tv_sec=0;
      lastButHighestDataACKTime.tv_usec=0;
      highestDataACKSeen=0;
      highestDataACKTime.tv_sec=0;
      highestDataACKTime.tv_usec=0;

      highestSeqIPLength=0;
      highestSeqTCPFlags=0;

      IPBytes[0]=0;
      IPBytes[1]=0;
      IPSessionBytes[0]=0;
      IPSessionBytes[1]=0;
      highestACKedIPSessionByte[0]=0;
      highestACKedIPSessionByte[1]=0;
      highestACKedIPByte[0]=0;
      highestACKedIPByte[1]=0;
      lastButHighestACKedIPSessionByte[0]=0;
      lastButHighestACKedIPSessionByte[1]=0;
      lastButHighestACKedIPByte[0]=0;
      lastButHighestACKedIPByte[1]=0;

      CRMaxTP=-1;
      CRMeanTP=-1;
      CRDuration=0;

      signPacketsSeenBMP=0;
      signPacketsSeenAMP=0;
      signPacketsRetrAMP=0;
      signPacketsReorderedBMP=0;
      signPacketsLostBMP=0;
      signPacketsLostAMP=0;
      signPacketsLostAMPTS=0;

      lossReliable=true;
      rtxDataOffset=false;
      captureLoss=false;

      initRWndSize[0]=0;
      initRWndSize[1]=0;
      minRWndSize[0]=0;
      minRWndSize[1]=0;
      maxRWndSize[0]=0;
      maxRWndSize[1]=0;
      meanRWndSize[0]=0;
      meanRWndSize[1]=0;
      rwndsSeen[0]=0;
      rwndsSeen[1]=0;

      flightSizeMean=0;
      flightSizeLastValue=0;
      flightSizeLastTime.tv_sec=0;
      flightSizeLastTime.tv_usec=0;
      flightSizeTimeSum=0;

      smallPipeRTT[0]=0;
      smallPipeRTT[1]=0;
      smallPipeRTTSamples[0]=0;
      smallPipeRTTSamples[1]=0;
      largePipeRTT[0]=0;
      largePipeRTT[1]=0;
      largePipeRTTSamples[0]=0;
      largePipeRTTSamples[1]=0;
      minRTT[0]=-1;
      minRTT[1]=-1;
      maxRTT[0]=-1;
      maxRTT[1]=-1;
   }
};

class MP4 {

public:

   bool           found;                     // True if Flash content is found in the TCP stream

   void Init()
   {
      found=false;
   }
};

class FLV {

public:

   bool           found;                     // True if Flash content is found in the TCP stream
   unsigned long  startPos;                  // The start position of the FLV content in the TCP stream [sequence number]
   struct timeval startTime;                 // The time of the first FLV DATA ACK [s]

   bool           rebuffFlag;                // True if rebuffering is ongoing
   double         rebuffTransportTS;         // Transport timestamp at the beginning of the last rebuffering event [s]
   double         rebuffMediaTS;             // Media timestamp at the beginning of the last rebuffering event [s]
   double         startMediaTS;              // Media timestamp present in the first FLV frame [s]
   double         lastMediaTS;               // The last (highest) media timestamp seen [s]
   double         lastTransportTS;           // The last transport timestamp with correct FLV TAG [s]
   unsigned short rebuffNum;                 // The total number of rebuffering events during the FLV stream
   double         rebuffTime;                // The total amount of time spent with rebuffering during the FLV stream
   double         rebuffInit;                // The initial rebuffering time at the beginning of the FLV stream

   bool           loadedOK;                  // True if a complete FLV stream was seen
   unsigned long  videoBytes;
   unsigned long  audioBytes;
   unsigned short soundFormat;
   unsigned short soundType;
   unsigned short soundRate;
   unsigned short videoCodec;

   double         lastQoETimestamp;          // (relative) wallclock TS when the last QoE was calculated [s]
   double         lastQoETransportTS;        // (relative) transport TS when the last QoE was calculated [s]
   double         lastQoERebuffTime;
   std::list<double> qoeList;                // List of calculated QoE score values during consecutive measurement windows
   std::list<double> qoeTime;                // List of QoE start times (relative transport time) [s]

   void Init()
   {
      found=false;
      startPos=0;
      startTime.tv_sec=0;
      startTime.tv_usec=0;

      rebuffFlag=true;
      rebuffTransportTS=0;
      rebuffMediaTS=0;
      startMediaTS=-1;
      lastMediaTS=0;
      lastTransportTS=0;
      rebuffNum=0;
      rebuffTime=0;
      rebuffInit=0;

      loadedOK=false;
      videoBytes=0;
      audioBytes=0;
      soundFormat=0;
      soundType=0;
      soundRate=0;
      videoCodec=0;

      lastQoETimestamp = 0;
      lastQoETransportTS = 0;
      lastQoERebuffTime = 0;
      qoeList.clear();
      qoeTime.clear();
   }
};

// TCP connection data
// -------------------
class TCPConn {

public:

   // 0 - direction Net A -> Net B
   // 1 - direction Net B -> Net A

   // PCAP packets of the connection
   bool           writeDump;                  // True if a packet dump shall be written for this TCP connection

   // Payload processing
   RangeList      payloadRanges[2];
   CircularBuffer payloadCache[2];
   unsigned long  payloadPos[2];              // The next payload sequence number to process

   // Content container decoding
   bool           contentFound[2];            // True if (at least one) content signature is found (e.g., FLV, MP4, etc.)
   FLV            flv[2];
   MP4            mp4[2];

   bool           isTorrent;
   std::string    userAgent;
   std::string    lastReqURI[2];
   std::string    lastReqHost[2];
   std::string    contentType;

   // Statistics
   unsigned long  packetsSeen[2];             // The number of packets seen
   unsigned long  dataPacketsSeen[2];         // The number of data packets seen
   unsigned long  signPacketsSeenBMP[2];      // The number of significant packets seen for loss estimation before the meas. point
   unsigned long  signPacketsSeenAMP[2];      // The number of significant packets seen for loss estimation after the meas. point
   unsigned long  signPacketsRetrAMP[2];      // The number of AMP significant packets for which at least one retransmission was seen
   unsigned long  signPacketsReorderedBMP[2]; // The number of BMP significant packets that have been reordered
   unsigned long  signPacketsLostBMP[2];      // Estimated number of significant packets lost before the meas. point
   unsigned long  signPacketsLostAMP[2];      // Estimated number of significant packets lost after the meas. point
   unsigned long  signPacketsLostAMPTS[2];    // Number of significant packets lost after the meas. point (estimated by TCP timestamps)
   bool           lossReliable;               // True if the loss estimation algorithm is reliable (no packet boundary offset or spurTO FIN ambiguity)
   bool           rtxDataOffset;              // True if overlapping data retransmission was seen (loss is unreliable)
   bool           captureLoss;                // True if capture loss was seen (loss is unreliable)

   unsigned long  IPBytes[2];                 // The amount of IP data seen in this connection [bytes]
   unsigned long  IPSessionBytes[2];          // The amount of IP session data sent during the TCP connection (calculated at the end of the connection) [bytes]
   unsigned long  PLBytes[2];                 // The amount of TCP payload bytes seen in this connection [bytes]
   unsigned long  PLBytesAlreadySeen[2];      // The amount of TCP payload bytes already seen at the monitoring point (spurious TO upper bound) [bytes]

   // Connection setup related variables
   unsigned short direction;                  // The direction of the first SYN
   bool           setupSuccess;               // True if the TCP connections is set up successfully
   std::map<unsigned long,char> SYNReg;       // Registry of SYN SEQs seen
   std::map<unsigned long,char> SYNACKReg;    // Registry of SYN ACK SEQs seen
   struct timeval firstSYNTime;               // The time when the first SYN was seen
   double         firstSYNGap;                // Time difference between the first SYN and the last IP packet [s]
   unsigned short firstSYNLen;                // The IP length of the first SYN [bytes]
   unsigned short SYNCount;                   // The number of SYNs seen
   struct timeval firstSYNACKTime;            // The time when the first SYN ACK was seen (for initial partial RTT measurement)
   double         firstSYNACKGap;             // Time difference between the first SYN ACK and the last IP packet [s]
   unsigned short firstSYNACKLen;             // The IP length of the first SYN ACK [bytes]
   unsigned short SYNACKCount;                // The number of SYNACKs seen
   struct timeval firstACKTime;               // The time when the first ACK was seen (for setup delay & partial RTT measurement)
   double         firstACKGap;                // Time difference between the first ACK and the last IP packet [s]
   unsigned short firstACKLen;                // The IP length of the first ACK [bytes]
   bool           unloadedSetup;              // True if the user was idle before & during connection setup
   double         initialRTT[2];              // Partial RTT upon connection setup (-1 if not measured [SYN or SYN ACK is retransmitted]) [s]
   unsigned long  ISN[2];                     // Initial sequence numbers

   // Connection termination
   static const char TERM_ALIVE = 0x0;        // It is still alive
   static const char TERM_FIN = 0x1;          // Terminated with normally
   static const char TERM_RST = 0x2;          // Terminated with RST
   static const char TERM_TO = 0x3;           // Timeouted
   char           termination;
   bool           FINSent[2];                 // True if FIN already sent
   struct timeval lastPacketTime[2];          // The time of the last packet seen (used for closeTime & connection breakdown check)
   struct timeval closeTime;                  // The time when a TCP connection closes (FIN or RST or timeout)

   // Option usage
   bool           SACKPermitted[2];           // True if a SACK permitted option was seen
   bool           SACKSeen[2];                // True if a SACK (not SACK permitted!) option was seen
   bool           TSSeen[2];                  // True if a timestamp option was seen

   // Loss estimation related variables
   unsigned long  dupACKCount[2];             // The actual number of dupACKs seen in the TCP connection (with highestACK)
   // Loss detection phase variables
   enum           SNDLossStates
                  {
                     NORMAL,
                     UNKNOWN_RTX,
                     UNNECESSARY_RTX,
                     NECESSARY_RTX,
                     POSSIBLE_EWL
                  };
   SNDLossStates  sndLossState[2];            // 0: UL, 1: DL
   enum           RCVLossStates
                  {
                     NO_HOLE,
                     HOLE
                  };
   RCVLossStates  rcvLossState[2];            // 0: UL, 1: DL

   unsigned long  rtxFirstSeq[2];             // The SEQ of the first retransmitted segment that caused entering RTX SNDLossState
   char           rtxFirstSeqLossInfo[2];     // The type of loss (AMP/BMP) for the the segment that caused entering RTX SNDLossState
   unsigned long  rtxHighestSeq[2];           // The SEQ of the highest segment that was sent before entering RTX SNDLossState
   unsigned long  rtxDupACKSeq[2];            // The highest dupACK seen in RTX (and POSSIBLE_EWL) state
   unsigned long  rtxEWLFirstSeq[2];          // The starting SEQ of a possible end-of-window loss (the first retransmission after the last dupACK in RTX state)

   // TCP timestamp-based loss verification
   typedef struct {bool tsSeen[2];unsigned long ts[2];bool rtxSeen;} TSRegEntry;
   typedef std::multimap<unsigned long /*seq*/, TSRegEntry> TSReg;
   TSReg          tsReg[2];                   // Timestamp registry for DATA packets
   bool           tsLossReliable;             // True if normal loss reliable is true _AND_ TS is used with high enough precision, and all necessary timestamps were seen

   // [For Reiner] List containing info for RTX periods
   typedef struct {unsigned long seq; SNDLossStates type; char lossInfo;} RTXPeriodListEntry;   // Note: lossInfo is only meaningful if type = NECESSARY_RTX
   std::list<RTXPeriodListEntry> rtxPeriodList[2];
   unsigned long  rtxPeriods[2];              // Number of retransmission periods (AMP+BMP including spurious)
   // [\For Reiner]

   // RTT calculation state variables
   bool           inRTTCalcState[2];          // True if there is a DATA packet outstanding for which we can calculate RTT (packet had highest SEQ, there were no retransmissions since it has been sent)
   unsigned long  firstRTTCalcSeq[2];         // The lowest SEQ which is a candidate for RTT calculation (all higher SEQ packets are also candidates)
   // List containing info for packets sent with the highest TCP SEQ (can be used for RTT and channel rate calculation, and for reordering check)
   typedef struct {unsigned long seq; struct timeval time; unsigned long ipSessionByte; unsigned long ipByte; unsigned short ipId; unsigned long pipeSize;} HighestSeqListEntry;
   std::list<HighestSeqListEntry> highestSeqList[2];

   // Transaction related variables (TAFirstXXX variables may go into the transactions themselves)
   bool           ongoingTransaction[2];             // True if there is an ongoing transaction
   std::list<TCPTransaction> transactionList[2];     // List of transactions
   unsigned short transactionReliability[2];         // Reliability of transactions (0 is the worst, 2 is the best)
   unsigned long  TAFirstIPByte[2][2];               // The amount of IP data seen on the TCP connection at the start of the ongoing transaction [bytes]
   unsigned long  TAFirstIPSessionByte[2][2];        // The amount of IP session data sent at the start of the ongoing TCP transaction [bytes]
   double         TAFirstSmallPipeRTT[2][2];         // The value of the smallPipeRTT counter at the start of the ongoing TCP transaction (to calculate avg. small pipe RTT for the transaction)
   unsigned long  TAFirstSmallPipeRTTSamples[2][2];  // The value of the smallPipeRTTSamples counter at the start of the ongoing TCP transaction (to calculate avg. small pipe RTT for the transaction)
   double         TAFirstLargePipeRTT[2][2];         // The value of the largePipeRTT counter at the start of the ongoing TCP transaction (to calculate avg. large pipe RTT for the transaction)
   unsigned long  TAFirstLargePipeRTTSamples[2][2];  // The value of the largePipeRTTSamples counter at the start of the ongoing TCP transaction (to calculate avg. large pipe RTT for the transaction)
   
   // Detect repeated data resends
   unsigned long  lastDataPacketSeq[2];       // The sequence number of the last DATA packet
   unsigned short lastDataPacketSeqCount[2];  // How many times have we seen the last DATA sequence number

   // Data packet stats
   unsigned short minDataPacketIPLen[2];      // Smallest IP data packet seen [bytes]
   unsigned short maxDataPacketIPLen[2];      // Largest IP data packet seen [bytes]
   double         meanDataPacketIPLen[2];     // Average IP data packet size [bytes]
   bool           nonPSHDataPacketSeen[2];    // True if at least one data packet with no PSH (and no FIN) flag was seen (if true, MSS estimation should be reliable)

   // Window related variables
   bool           wndScaleSeen[2];            // True if a window scale advertisement was seen in the first SYN/SYNACK (scaling factor will be only used if both ends support it)
   unsigned char  wndScaleVal[2];             // The advertised receiver window will be shifted with that many bits (if scaling is used)
   unsigned long  initRWndSize[2];            // The initial window size (on the first data ACK)
   unsigned long  minRWndSize[2];             // Smallest receiver window size seen [bytes]
   unsigned long  maxRWndSize[2];             // Largest receiver window size seen [bytes]
   double         meanRWndSize[2];            // Average receiver window size size [bytes]
   unsigned short lastWndSize[2];             // The last receiver window size [bytes] (for detecting window update ACKs and distinguish them from dupACKs)
   unsigned long  rwndsSeen[2];               // The number of receiver window advertisements seen

   // RTT statistics
   double         smallPipeRTT[2];            // Mean unloaded RTT [s] (only for DATA packets)
   unsigned long  smallPipeRTTSamples[2];     // Number of samples for the small pipe RTT
   double         largePipeRTT[2];            // Mean loaded RTT [s] (only for DATA packets)
   unsigned long  largePipeRTTSamples[2];     // Number of samples for the large pipe RTT
   double         minRTT[2];                  // The minimum RTT ever seen during the TCP connection (the SYN-SYNACK-ACK RTT is also included here) (-1 if none measured)
   double         maxRTT[2];                  // The maximum RTT ever seen during the TCP connection (the SYN-SYNACK-ACK RTT is also included here) (-1 if none measured)

   // TP&GP calculation
   struct timeval firstDataPacketTime[2];     // The time of the first DATA packet
   struct timeval highestDataACKTime[2];      // The time of the ACK that acks the highest seq DATA packet
   unsigned long  highestDataACKSeen[2];      // The acknowledgement number of the ACK that acks the highest seq DATA packet
   unsigned long  highestDataACKIPSessionBytes[2]; // The IPSessionBytes counter for the data packet corresponding to the highest ACK received

   // Other status variables
   unsigned long  highestExpectedSeq[2];      // The SEQ after the highest SEQ seen
   unsigned long  highestExpectedDataSeq[2];  // The SEQ after the highest DATA SEQ seen (for new DATA packet determination - because FIN-DATA reorderings distort BMP loss estimation)
   unsigned long  highestACKSeen[2];          // The highest acknowledge number seen

   PacketTrainList packetTrains[2];           // List of packets seen

   void Init()
   {
      writeDump=false;

      payloadPos[0]=1;
      payloadPos[1]=1;

      contentFound[0]=false;
      contentFound[1]=false;
      flv[0].Init();
      flv[1].Init();
      mp4[0].Init();
      mp4[1].Init();
      
      isTorrent=false;
      userAgent.clear();
      lastReqURI[0].clear();
      lastReqURI[1].clear();
      lastReqHost[0].clear();
      lastReqHost[1].clear();

      packetsSeen[0]=0;
      packetsSeen[1]=0;
      dataPacketsSeen[0]=0;
      dataPacketsSeen[1]=0;
      signPacketsSeenBMP[0]=0;
      signPacketsSeenBMP[1]=0;
      signPacketsSeenAMP[0]=0;
      signPacketsSeenAMP[1]=0;
      signPacketsRetrAMP[0]=0;
      signPacketsRetrAMP[1]=0;
      signPacketsReorderedBMP[0]=0;
      signPacketsReorderedBMP[1]=0;
      signPacketsLostBMP[0]=0;
      signPacketsLostBMP[1]=0;
      signPacketsLostAMP[0]=0;
      signPacketsLostAMP[1]=0;
      signPacketsLostAMPTS[0]=0;
      signPacketsLostAMPTS[1]=0;
      lossReliable=true;
      rtxDataOffset=false;
      captureLoss=false;

      IPBytes[0]=0;
      IPBytes[1]=0;
      IPSessionBytes[0]=0;
      IPSessionBytes[1]=0;
      PLBytes[0]=0;
      PLBytes[1]=0;
      PLBytesAlreadySeen[0]=0;
      PLBytesAlreadySeen[1]=0;

      direction=0;
      setupSuccess=false;
      SYNReg.clear();
      SYNACKReg.clear();
      firstSYNTime.tv_sec=0;
      firstSYNTime.tv_usec=0;
      firstSYNGap=0;
      firstSYNLen=0;
      SYNCount=0;
      firstSYNACKTime.tv_sec=0;
      firstSYNACKTime.tv_usec=0;
      firstSYNACKGap=0;
      firstSYNACKLen=0;
      SYNACKCount=0;
      firstACKTime.tv_sec=0;
      firstACKTime.tv_usec=0;
      firstACKGap=0;
      firstACKLen=0;
      unloadedSetup=false;
      initialRTT[0]=-1;
      initialRTT[1]=-1;
      ISN[0]=0;
      ISN[1]=0;

      termination=TERM_ALIVE;
      FINSent[0]=false;
      FINSent[1]=false;
      lastPacketTime[0].tv_sec=0;
      lastPacketTime[0].tv_usec=0;
      lastPacketTime[1].tv_sec=0;
      lastPacketTime[1].tv_usec=0;
      closeTime.tv_sec=0;
      closeTime.tv_usec=0;

      SACKPermitted[0]=false;
      SACKPermitted[1]=false;
      SACKSeen[0]=false;
      SACKSeen[1]=false;
      TSSeen[0]=false;
      TSSeen[1]=false;

      dupACKCount[0]=0;
      dupACKCount[1]=0;

      sndLossState[0]=NORMAL;
      sndLossState[1]=NORMAL;
      rcvLossState[0]=NO_HOLE;
      rcvLossState[1]=NO_HOLE;
      rtxFirstSeq[0]=0;
      rtxFirstSeq[1]=0;
      rtxFirstSeqLossInfo[0]=PacketTrainTCPPacket::NOT_LOST;
      rtxFirstSeqLossInfo[1]=PacketTrainTCPPacket::NOT_LOST;
      rtxHighestSeq[0]=0;
      rtxHighestSeq[1]=0;
      rtxDupACKSeq[0]=0;
      rtxDupACKSeq[1]=0;
      rtxEWLFirstSeq[0]=0;
      rtxEWLFirstSeq[1]=0;

      tsReg[0].clear();
      tsReg[1].clear();
      tsLossReliable=false;

      rtxPeriodList[0].clear();
      rtxPeriodList[1].clear();
      rtxPeriods[0]=0;
      rtxPeriods[1]=0;

      inRTTCalcState[0]=false;
      inRTTCalcState[1]=false;
      firstRTTCalcSeq[0]=0;
      firstRTTCalcSeq[1]=0;
      highestSeqList[0].clear();
      highestSeqList[1].clear();

      ongoingTransaction[0]=false;
      ongoingTransaction[1]=false;
      transactionList[0].clear();
      transactionList[1].clear();
      transactionReliability[0]=0;
      transactionReliability[1]=0;
      TAFirstIPByte[0][0]=0;
      TAFirstIPByte[0][1]=0;
      TAFirstIPByte[1][0]=0;
      TAFirstIPByte[1][1]=0;
      TAFirstIPSessionByte[0][0]=0;
      TAFirstIPSessionByte[0][1]=0;
      TAFirstIPSessionByte[1][0]=0;
      TAFirstIPSessionByte[1][1]=0;
      TAFirstSmallPipeRTT[0][0]=0;
      TAFirstSmallPipeRTT[0][1]=0;
      TAFirstSmallPipeRTT[1][0]=0;
      TAFirstSmallPipeRTT[1][1]=0;
      TAFirstSmallPipeRTTSamples[0][0]=0;
      TAFirstSmallPipeRTTSamples[0][1]=0;
      TAFirstSmallPipeRTTSamples[1][0]=0;
      TAFirstSmallPipeRTTSamples[1][1]=0;
      TAFirstLargePipeRTT[0][0]=0;
      TAFirstLargePipeRTT[0][1]=0;
      TAFirstLargePipeRTT[1][0]=0;
      TAFirstLargePipeRTT[1][1]=0;
      TAFirstLargePipeRTTSamples[0][0]=0;
      TAFirstLargePipeRTTSamples[0][1]=0;
      TAFirstLargePipeRTTSamples[1][0]=0;
      TAFirstLargePipeRTTSamples[1][1]=0;

      lastDataPacketSeq[0]=0;
      lastDataPacketSeq[1]=0;
      lastDataPacketSeqCount[0]=0;
      lastDataPacketSeqCount[1]=0;

      minDataPacketIPLen[0]=0;
      minDataPacketIPLen[1]=0;
      maxDataPacketIPLen[0]=0;
      maxDataPacketIPLen[1]=0;
      meanDataPacketIPLen[0]=0;
      meanDataPacketIPLen[1]=0;
      nonPSHDataPacketSeen[0]=false;
      nonPSHDataPacketSeen[1]=false;

      wndScaleSeen[0]=false;
      wndScaleSeen[1]=false;
      wndScaleVal[0]=0;
      wndScaleVal[1]=0;
      initRWndSize[0]=0;
      initRWndSize[1]=0;
      minRWndSize[0]=0;
      minRWndSize[1]=0;
      maxRWndSize[0]=0;
      maxRWndSize[1]=0;
      meanRWndSize[0]=0;
      meanRWndSize[1]=0;
      lastWndSize[0]=0;
      lastWndSize[1]=0;
      rwndsSeen[0]=0;
      rwndsSeen[1]=0;

      smallPipeRTT[0]=0;
      smallPipeRTT[1]=0;
      smallPipeRTTSamples[0]=0;
      smallPipeRTTSamples[1]=0;
      largePipeRTT[0]=0;
      largePipeRTT[1]=0;
      largePipeRTTSamples[0]=0;
      largePipeRTTSamples[1]=0;
      minRTT[0]=-1;
      minRTT[1]=-1;
      maxRTT[0]=-1;
      maxRTT[1]=-1;

      firstDataPacketTime[0].tv_sec=0;
      firstDataPacketTime[0].tv_usec=0;
      firstDataPacketTime[1].tv_sec=0;
      firstDataPacketTime[1].tv_usec=0;
      highestDataACKTime[0].tv_sec=0;
      highestDataACKTime[0].tv_usec=0;
      highestDataACKTime[1].tv_sec=0;
      highestDataACKTime[1].tv_usec=0;
      highestDataACKSeen[0]=0;
      highestDataACKSeen[1]=0;
      highestDataACKIPSessionBytes[0]=0;
      highestDataACKIPSessionBytes[1]=0;

      highestExpectedSeq[0]=0;
      highestExpectedSeq[1]=0;
      highestExpectedDataSeq[0]=0;
      highestExpectedDataSeq[1]=0;
      highestACKSeen[0]=0;
      highestACKSeen[1]=0;
      packetTrains[0].Init();
      packetTrains[1].Init();
   }
};

#endif
