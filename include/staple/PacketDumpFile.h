#ifndef PACKETDUMPFILE_H
#define PACKETDUMPFILE_H

#include <map>
#include <zlib.h>
#include <staple/Packet.h>

class Staple;

// Entry in the list of dumpfiles to be processed
class DumpFileListEntry {

public:
   std::string name;                                        // Name of the file ("" means stdin)
   struct timeval firstPacketTime;

   DumpFileListEntry()
   {
      name = std::string("");
      firstPacketTime.tv_sec = 0;
      firstPacketTime.tv_usec = 0;
   };

   // Needed for sorting
   bool operator <(const DumpFileListEntry& x) const
   {
      if (firstPacketTime.tv_sec != x.firstPacketTime.tv_sec) return (firstPacketTime.tv_sec < x.firstPacketTime.tv_sec);
      return (firstPacketTime.tv_usec < x.firstPacketTime.tv_usec);
   };
   // Needed for finding
   bool operator ==(const DumpFileListEntry& x) const
   {
      return ((firstPacketTime.tv_sec == x.firstPacketTime.tv_sec) && (firstPacketTime.tv_usec == x.firstPacketTime.tv_usec));
   };
};

// Entry for L2 duplicate packet detection registry
class L2RawPacket {

public:
   unsigned short savedL2PacketLength;                      // Number of captured bytes
   unsigned short origL2PacketLength;                       // Number of bytes in the full packet
   Byte* data;                                              // Pointer to the packet data (incl. L2 header) (needed to double check CRC32 lookup by exact comparison)
   unsigned short dupCount;                                 // Number of duplicates seen
   bool           isIP;                                     // True if packet is an IP packet (needed for statistics)
   
   L2RawPacket()
   {
      savedL2PacketLength = 0;
      origL2PacketLength = 0;
      data = NULL;
      dupCount = 0;
      isIP = false;
   }
};

// PacketDumpFile class
class PacketDumpFile {

public:

typedef enum {    NO_ERROR,
                  ERROR_OPEN,
                  ERROR_FORMAT,
                  ERROR_L2_DUPLICATE,
                  ERROR_EOF} ErrorCode;

typedef enum {    LINKTYPE_ETH,
                  LINKTYPE_PPP,
                  LINKTYPE_RAW
                  } LinkType;

   // List of input files to be processed
   std::list<DumpFileListEntry>              inputFileList;
   std::list<DumpFileListEntry>::iterator    actFileIndex;

protected:

   // Status variables on the actual file opened
   gzFile             inFile;
   gzFile             outFile;
   unsigned long      outfileSlotNum;
   unsigned short     byteOrderChange;
   bool               modifiedFormat;
   LinkType           linkType;

   // Data from the input dump file header (needed to produce output dump)
   DoubleWord         utcOffset;
   DoubleWord         granularity;
   DoubleWord         snapLength;
   DoubleWord         linkTypeCode;
   // Info on the actual packet
   unsigned long      savedL2PacketLength;
   unsigned long      origL2PacketLength;

   // L2 duplicate packet filtering info
   std::multimap<unsigned long, L2RawPacket> l2RawPacketReg;         // L2 raw packet registry for fast CRC-based lookup
   typedef struct
   {
      struct timeval time;
      std::multimap<unsigned long, L2RawPacket>::iterator regIndex;  // Iterator to the L2 packet in the registry
   } L2RawPacketListEntry;
   std::list<L2RawPacketListEntry> l2RawPacketList;                  // L2 packet list for time-based history management
   
   Staple&        staple;
   
public:
                  ~PacketDumpFile();
                  PacketDumpFile(Staple& s)
                   : staple(s)
                  {
                     inFile = NULL;
                     outFile = NULL;
                  }
   ErrorCode      CreateInputFileList(char*);
   ErrorCode      FirstInputFile();
   ErrorCode      NextInputFile();
   ErrorCode      OpenInputFile(char*);
   ErrorCode      OpenOutputFile();
   L2Packet*      ReadPacket(ErrorCode*);
   void           CloseInputFile();
   void           WriteActualPacket();
   void           CloseOutputFile();
};

// GLOBAL function for decoding IP packets (TODO: inheritance)
L3Packet* DecodeIPPacket(char*, unsigned short, Staple&);

#endif
