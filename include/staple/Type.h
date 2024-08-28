#ifndef TYPE_H
#define TYPE_H

#include <iostream>
#include <iomanip>
#include <sys/time.h>
#include <sys/types.h>
#include <string.h>

// Defines
#define USE_HASH_MAP                               // If defined, __gnu_cxx::hash is used instead of std::map
//#define PROFILE                                    // If defined, performance/memory profiling info is written into file
//#define MAKE_URL_HIST                              // If defined, an HTTP URL histogram will be maintained (can increase the memory consumption seriously!)
//#define WRITE_TCPTA_FILES                          // If defined, a file will be written for each TCP TA
#define WRITE_SRTO_STATS                  false    // If true: spurious timeout related info is written to the Perfmon TCP TA logs (side effect: the loss of unreliable TCP TAs will be written to the logs as well)
#define STATUS_LOG_PERIOD                 60       // Status log period [s]
#define PERFMON_ROP                       300      // Perfmon reporting period [s]
#define TCPTA_ROP                         5        // TCP transaction reporting period [s]
#define TS_MAJOR_REORDERING_THRESH        1        // Above this threshold, a timestamp reordering is considered to be a major fault (all sessions will be terminated) [s]
#define TS_JUMP_THRESH                    300      // Above this threshold, a timestamp difference is conidered to be a jump [s]
#define L2_DUPLICATE_TDIFF                0.1      // Duplicated L2 packets will be removed within this time threshold [s]
#define DECODE_EVERY_SECOND_L2_DUPLICATE  true     // True: every second L2 duplicate will be decoded, false: none of the L2 duplicates will be decoded
#define DUPSTATS_MAX                      4        // The last bin of the duplicate packet number statistics (has DUPSTATS_MAX and above)
extern unsigned int TCPTA_SSTHRESH;                // We assume that after this amount of data, the slow start is over (used in TCP transaction TP calculation) [bytes]
extern unsigned int TCPTA_SSMAXFS;                 // We assume that above this flightsize, the slow start is over (used in TCP transaction TP calculation) [bytes]
extern unsigned int TCPTA_MINSIZE;
extern unsigned int CHANNELRATE_MIN_PIPE;          // Above this amount of unacknowledged data a TCP is considered to fill the pipe [bytes]
extern unsigned int CHANNELRATE_MIN_TIME;          // The minimum duration for which channel rate may be calculated [s]
extern unsigned int CHANNELRATE_MIN_DATA;          // The minimum amount of data for which channel rate may be calculated [bytes]
#define CHANNELRATE_SHORT                          // Make short measurements (after CHANNELRATE_MIN_DATA or CHANNELRATE_MIN_TIME, start a new measurement)
extern double ACK_COMPRESSION_TIME;                // ACKs arriving closer than this are considered compressed [s]
// Payload processing
#define TCP_PL_CACHE_INIT_SIZE            8000     // Initial size of the TCP payload cache (e.g., for FLV signature search) [bytes]
#define TCP_PL_CACHE_NORMAL_SIZE          300000   // Normal size of the TCP payload cache (e.g., during FLV decoding) [bytes]
#define TCP_PL_CACHE_MAX_SIZE             4*300000 // Maximum size of the TCP payload cache (e.g., during FLV decoding) [bytes]
#define MAX_SIGNATURE_LIMIT               2000     // The maximum amount of payload bytes to search for content signature [bytes]
// FLV
#define FLVLOGLEVEL                       3
#define FLV_SIGNATURE_LIMIT               2000     // The number of payload bytes to search for FLV signature at the beginning of a TCP connection [bytes]
#define FLV_REBUFF_THRESH                 2        // Threshold for FLV rebuffering [s]
#define FLV_QOE_TIME                      30       // Duration of FLV QoE statistics [s]
// MP4
#define MP4_SIGNATURE_LIMIT               2000     // The number of payload bytes to search for MP4 signature at the beginning of a TCP connection [bytes]
#define IPSESSIONDATA_SLOTTIME            1        // Duration of the IP session data counter slot (influences background load calculation for TCP!!!) [s]
extern unsigned int UNLOADED_MAXDATA_BEFORE;       // Maximum amount of UL/DL IP session data that may be sent before the TCP SYN in the last slot so that the TCP setup can be considered unloaded [bytes]
extern unsigned int UNLOADED_MAXDATA_DURING;       // Maximum amount of UL/DL >>parallel<< IP session data that may be sent during the TCP SYN-SYNACK-ACK procedure so that the TCP setup can be considered unloaded [bytes]
#define MAX_HISTORY_RANGE                 262144   // The maximum sequence range kept in history [bytes]
#define HISTORY_MAX_ACKED_AGE             30       // A packet older than this threshold can be erased from the history if it is already ACKed [s]
#define TCP_SEQ_INSANE_THRESH             1000000  // Maximum valid TCP sequence number difference [bytes]
#define MAX_PACKETLENGTH                  65535    // Max. length of L2 packets [bytes]

#ifdef USE_HASH_MAP
#include <unordered_map>
#endif

typedef unsigned char Byte;

typedef union
{
   u_int8_t byte[2];
   u_int16_t data;
} Word;

typedef union
{
   u_int8_t byte[4];
   u_int32_t data;
} DoubleWord;

typedef union
{
   u_int8_t byte[8];
   u_int64_t data;
} QuadWord;

// IP address key for associative maps
class IPAddressId {
public:
   DoubleWord        IP;
   void Print(std::ostream& outStream) const
   {
      outStream << "IP " << (unsigned)IP.byte[3] << "." << (unsigned)IP.byte[2] << "." << (unsigned)IP.byte[1] << "." << (unsigned)IP.byte[0] << "\n";
   }
};

struct IPAddressIdTraits {
#if defined(USE_HASH_MAP)
   // Hash function for IPAddressId (needed by hash_map)
   size_t operator()(const IPAddressId& x) const
   {
      return std::hash< u_int32_t >()((u_int32_t)x.IP.data);
   };
   // Equality function for IPAddressId (needed by hash_map)
   bool operator()(const IPAddressId& x, const IPAddressId& y) const
   {
      return (x.IP.data==y.IP.data);
   };
#else
   // Sorting (needed by std::map)
   bool operator() (const IPAddressId& x, const IPAddressId& y) const
   {
      return (x.IP.data < y.IP.data);
   }
#endif
};

class MACAddress {
public:
   unsigned char addr[6];
   // Needed for sorting
   bool operator <(const MACAddress& x) const
   {
      return (memcmp(addr,x.addr,6)<0);
   };
   // Needed for finding
   bool operator ==(const MACAddress& x) const
   {
      return (memcmp(addr,x.addr,6)==0);
   };
   bool comparePrefix(const MACAddress& x, const unsigned short len) const
   {
      return (memcmp(addr,x.addr,len)==0);
   };
   void Print(std::ostream& outStream) const
   {
      // Store original format flags
      std::ios_base::fmtflags origFormat = outStream.flags();
      // Print
      outStream << std::hex;
      outStream << std::setw(2) << std::right << std::setfill('0') << (int)addr[0];
      outStream << std::setw(2) << std::right << std::setfill('0') << (int)addr[1];
      outStream << std::setw(2) << std::right << std::setfill('0') << (int)addr[2];
      outStream << std::setw(2) << std::right << std::setfill('0') << (int)addr[3];
      outStream << std::setw(2) << std::right << std::setfill('0') << (int)addr[4];
      outStream << std::setw(2) << std::right << std::setfill('0') << (int)addr[5];
      // Revert to original formatting settings
      outStream.flags(origFormat);
   }
};

#endif
