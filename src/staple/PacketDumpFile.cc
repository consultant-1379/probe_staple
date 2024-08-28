#include <sys/time.h>
#include <sys/stat.h>
#include <dirent.h>

#include <string>
#include <sstream>                                       // std::stringstream

#include <staple/Staple.h>
#include <staple/Type.h>
#include <staple/PacketDumpFile.h>

#include "Util.h"

char tmpBuffer[MAX_PACKETLENGTH];                        // Temporay storage at file read
unsigned long crcTable[256];                             // Data structure for fast CRC-32 calculation of L2 packets

PacketDumpFile::ErrorCode PacketDumpFile::CreateInputFileList(char *p_fileName)
{
   // First, create the list of input files to be opened
   // --------------------------------------------------
   inputFileList.clear();
   // Is the specified input file a directory?
   struct stat statres;
   stat(p_fileName, &statres);
   if (S_ISDIR(statres.st_mode))
   {
      // Set the path name (add "/" if needed)
      std::string path = std::string(p_fileName);
      if (path[path.size()-1] != '/') path += '/';

      // Open directory
      DIR *dp;
      if ((dp = opendir(p_fileName)) == NULL) return ERROR_OPEN;
      // Get list of files
      struct dirent *dirp;
      while ((dirp = readdir(dp)) != NULL)
      {
         // Consider files only, not directories
         std::string fullName = path + std::string(dirp->d_name);
         stat(fullName.c_str(), &statres);
         if (!S_ISDIR(statres.st_mode))
         {
            // Logging
            if (staple.logLevel>=5)
            {
               staple.logStream << "Checking file: " << fullName << "\n";
            }
            // Open the file
            PacketDumpFile tmpDumpFile(staple);
            ErrorCode errorCode = tmpDumpFile.OpenInputFile((char*)fullName.c_str());
            // If it is not a packet dump file, go to the next file
            if (errorCode != NO_ERROR)
            {
               tmpDumpFile.CloseInputFile();
               continue;
            }
            // Read the first packet
            L2Packet* pL2Packet = NULL;
            while (pL2Packet == NULL)
            {
               // Read a packet
               pL2Packet = tmpDumpFile.ReadPacket(&errorCode);
               // Handle EOF
               if (errorCode == ERROR_EOF) break;
            }
            // Successful packet read
            if (pL2Packet != NULL)
            {
               DumpFileListEntry newFile;
               newFile.name = fullName;
               newFile.firstPacketTime = pL2Packet->time;
               // Append to the file list
               inputFileList.push_back(newFile);
               // Delete packet
               delete pL2Packet;
            }
            // Close packet dump file
            tmpDumpFile.CloseInputFile();
         }
      }
      closedir(dp);
      // Sort dump file list according to their first packet timestamp
      inputFileList.sort();
   }
   // Single file only
   else
   {
      DumpFileListEntry newFile;
      newFile.name = ((p_fileName==NULL) ? "" : p_fileName); // "" and NULL means stdin
      inputFileList.push_back(newFile);
   }
   // Logging
   if (staple.logLevel >=5)
   {
      for (std::list<DumpFileListEntry>::iterator index = inputFileList.begin(); index!=inputFileList.end(); index++)
      {
         staple.logStream << "Found packet dump file " << (*index).name << " with first packet at " << (*index).firstPacketTime.tv_sec << "s\n";
      }
   }

   return NO_ERROR;
}

PacketDumpFile::ErrorCode PacketDumpFile::FirstInputFile()
{
   // No files at all -> return with error
   if (inputFileList.empty()) return ERROR_OPEN;
   // Open the first file in the list (or stdin)
   actFileIndex = inputFileList.begin();
   char* fileName = ((*actFileIndex).name == "") ? NULL : (char*)((*actFileIndex).name.c_str()); // ""->NULL: stdin
   // Open the file
   if (staple.logLevel>=5)
   {
      staple.logStream << "Opening first packet dump file: " << (*actFileIndex).name << "\n";
   }
   ErrorCode errorCode = OpenInputFile(fileName);
   return errorCode;
}

PacketDumpFile::ErrorCode PacketDumpFile::NextInputFile()
{
   // No files in the input file list or already reached the end -> return with error
   if ((inputFileList.empty()) || (actFileIndex==inputFileList.end())) return ERROR_OPEN;
   // Close the last file
   CloseInputFile();
   // Move to the next file
   actFileIndex++;
   // Return if we just have reached the end
   if (actFileIndex == inputFileList.end()) return ERROR_OPEN;
   // Open the file
   if (staple.logLevel>=5)
   {
      staple.logStream << "Opening next packet dump file: " << (*actFileIndex).name << "\n";
   }
   ErrorCode errorCode = OpenInputFile((char*)(*actFileIndex).name.c_str());
   return errorCode;
}

PacketDumpFile::~PacketDumpFile()
{
   // Free up allocated L2 packet memory
   // ----------------------------------
   std::multimap<unsigned long, L2RawPacket>::iterator regIndex;
   while (!l2RawPacketList.empty())
   {
      // Find packet in the registry
      regIndex = l2RawPacketList.front().regIndex;
      // Free up memory allocated for the L2 packet
      delete (*regIndex).second.data;
      // Erase element both from registry & list
      l2RawPacketReg.erase(regIndex);
      l2RawPacketList.pop_front();
   }
}

PacketDumpFile::ErrorCode PacketDumpFile::OpenInputFile(char *p_fileName)
{
   // Init L2 packet registry and list (for L2 duplicate packet filtering)
   l2RawPacketReg.clear();
   l2RawPacketList.clear();

   // Normal file
   if (p_fileName != 0)
   {
      inFile = gzopen(p_fileName,"rb");
   }
   // STDIN
   else
   {
// Does not work & platform dependent (only under windows)
//      setmode(fileno(stdin),O_BINARY);
      inFile = gzdopen(fileno(stdin),"rb");
   }

   // File open error
   if (inFile == NULL) return ERROR_OPEN;

   // Read dumpfile header
   DoubleWord tmpDoubleWord;
   Word tmpWord;
   if (gzread(inFile,tmpBuffer,24)<=0) return ERROR_EOF;

   // Determine byte order based on "magic number"
   byteOrderChange = 0;
   tmpDoubleWord.byte[0] = tmpBuffer[0];
   tmpDoubleWord.byte[1] = tmpBuffer[1];
   tmpDoubleWord.byte[2] = tmpBuffer[2];
   tmpDoubleWord.byte[3] = tmpBuffer[3];
   switch (tmpDoubleWord.data)
   {
      case 0xa1b2c3d4:
      {
         byteOrderChange = 0;
         modifiedFormat = false;
         if (staple.logLevel>=5) staple.logStream << "TCPDump's normal byte order detected.\n";
         break;
      }
      case 0xd4c3b2a1:
      {
         byteOrderChange = 1;
         modifiedFormat = false;
         if (staple.logLevel>=5) staple.logStream << "TCPDump's reverse byte order detected.\n";
         break;
      }
      case 0xa1b2cd34:
      {
         byteOrderChange = 0;
         modifiedFormat = true;
         if (staple.logLevel>=5) staple.logStream << "Kuznetsov's normal byte order detected.\n";
         break;
      }
      case 0x34cdb2a1:
      {
         byteOrderChange = 1;
         modifiedFormat = true;
         if (staple.logLevel>=5) staple.logStream << "Kuznetsov's reverse byte order detected.\n";
         break;
      }
      default:
      {
         return ERROR_FORMAT;
      }
   }
   // Read version number
   tmpWord.byte[byteOrderChange] = tmpBuffer[4];
   tmpWord.byte[1-byteOrderChange] = tmpBuffer[5];
   unsigned short majorVersion = tmpWord.data;
   tmpWord.byte[byteOrderChange] = tmpBuffer[6];
   tmpWord.byte[1-byteOrderChange] = tmpBuffer[7];
   unsigned short minorVersion = tmpWord.data;
   if (staple.logLevel>=5) staple.logStream << "Dumpfile version is " << majorVersion << "." << minorVersion << ".\n";

   // Read UTC time offset
   utcOffset.byte[3*byteOrderChange] = tmpBuffer[8];
   utcOffset.byte[1+byteOrderChange] = tmpBuffer[9];
   utcOffset.byte[2-byteOrderChange] = tmpBuffer[10];
   utcOffset.byte[3*(1-byteOrderChange)] = tmpBuffer[11];

   // Read timestamp granularity info
   granularity.byte[3*byteOrderChange] = tmpBuffer[12];
   granularity.byte[1+byteOrderChange] = tmpBuffer[13];
   granularity.byte[2-byteOrderChange] = tmpBuffer[14];
   granularity.byte[3*(1-byteOrderChange)] = tmpBuffer[15];

   // Read snaplength
   snapLength.byte[3*byteOrderChange] = tmpBuffer[16];
   snapLength.byte[1+byteOrderChange] = tmpBuffer[17];
   snapLength.byte[2-byteOrderChange] = tmpBuffer[18];
   snapLength.byte[3*(1-byteOrderChange)] = tmpBuffer[19];
   if (staple.logLevel>=5) staple.logStream << "Snaplength is " << snapLength.data << " bytes.\n";

   // Read link type
   linkTypeCode.byte[3*byteOrderChange] = tmpBuffer[20];
   linkTypeCode.byte[1+byteOrderChange] = tmpBuffer[21];
   linkTypeCode.byte[2-byteOrderChange] = tmpBuffer[22];
   linkTypeCode.byte[3*(1-byteOrderChange)] = tmpBuffer[23];
   switch (linkTypeCode.data)
   {
      case 0x0001:
      {
         if (staple.logLevel>=5) staple.logStream << "Link type is Ethernet.\n";
         linkType = LINKTYPE_ETH;
         break;
      }
      case 0x0009:
      {
         if (staple.logLevel>=5) staple.logStream << "Link type is PPP.\n";
         linkType = LINKTYPE_PPP;
         break;
      }
      case 0x000c:
      case 0x0065:
      case 0x006a:
      {
         if (staple.logLevel>=5) staple.logStream << "Link type is Linux classical IP over ATM (RAW IP).\n";
         linkType = LINKTYPE_RAW;
         break;
      }
      default:
      {
         staple.logStream << "Unknown link type " << linkTypeCode.data << "!\n";
         return ERROR_FORMAT;
      }
   }

   // Initialize CRC32 table for L2 duplicate packet detection
   unsigned long crc, poly;
   poly = 0xedb88320;
   for (int i=0;i<256;i++)
   {
      crc=i;
      for (int j=8;j>0;j--)
      {
         if (crc&1)
         {
            crc = (crc>>1)^poly;
         }
         else
         {
            crc >>= 1;
         }
      }
      crcTable[i] = crc;
   }

   return NO_ERROR;
}

L2Packet* PacketDumpFile::ReadPacket(ErrorCode* p_pErrorCode)
{
   // Read dump header
   // ----------------
   if (gzread(inFile,tmpBuffer,16)<=0)
   {
      // End of file reached (or other read error)
      *p_pErrorCode = ERROR_EOF;
      return NULL;
   }
 
   Word tmpWord;
   DoubleWord tmpDoubleWord;
   if (staple.logLevel>=5) staple.logStream << "Reading packet from dump file at position " << gztell(inFile) << "\n";

   // Read capture time (byte order and platform dependency check TBD)
   struct timeval time;
   tmpDoubleWord.byte[3*byteOrderChange] = tmpBuffer[0];
   tmpDoubleWord.byte[1+byteOrderChange] = tmpBuffer[1];
   tmpDoubleWord.byte[2-byteOrderChange] = tmpBuffer[2];
   tmpDoubleWord.byte[3*(1-byteOrderChange)] = tmpBuffer[3];
   time.tv_sec = tmpDoubleWord.data;
   tmpDoubleWord.byte[3*byteOrderChange] = tmpBuffer[4];
   tmpDoubleWord.byte[1+byteOrderChange] = tmpBuffer[5];
   tmpDoubleWord.byte[2-byteOrderChange] = tmpBuffer[6];
   tmpDoubleWord.byte[3*(1-byteOrderChange)] = tmpBuffer[7];
   time.tv_usec = tmpDoubleWord.data;
   // Read saved & original link layer packet length
   tmpDoubleWord.byte[3*byteOrderChange] = tmpBuffer[8];
   tmpDoubleWord.byte[1+byteOrderChange] = tmpBuffer[9];
   tmpDoubleWord.byte[2-byteOrderChange] = tmpBuffer[10];
   tmpDoubleWord.byte[3*(1-byteOrderChange)] = tmpBuffer[11];
   savedL2PacketLength = tmpDoubleWord.data;
   tmpDoubleWord.byte[3*byteOrderChange] = tmpBuffer[12];
   tmpDoubleWord.byte[1+byteOrderChange] = tmpBuffer[13];
   tmpDoubleWord.byte[2-byteOrderChange] = tmpBuffer[14];
   tmpDoubleWord.byte[3*(1-byteOrderChange)] = tmpBuffer[15];
   origL2PacketLength = tmpDoubleWord.data;
   if (staple.logLevel>=5) staple.logStream << "Link layer packet length is " << origL2PacketLength << " (" << savedL2PacketLength << " dumped) bytes.\n";

   // Kuznetsov's HACK
   if (modifiedFormat == true)
   {
      if (gzread(inFile,tmpBuffer,8)<=0)
      {
         // End of file reached (or other read error)
         *p_pErrorCode = ERROR_EOF;
         return NULL;
      }
   }

   // L2 duplicate packet list length enforcement
   // -------------------------------------------
   while ((!l2RawPacketList.empty()) && staple.ignoreL2Duplicates)
   {
      // Check oldest packet time
      struct timeval timeDiff = AbsTimeDiff(l2RawPacketList.front().time, time);
      double tDiff = timeDiff.tv_sec + (double)timeDiff.tv_usec/1000000;
      // If packet timeouted -> remove it
      if (tDiff > L2_DUPLICATE_TDIFF)
      {
         // Find it in the registry too
         std::multimap<unsigned long, L2RawPacket>::iterator regIndex = l2RawPacketList.front().regIndex;
         // Free up memory allocated for the L2 packet
         delete (*regIndex).second.data;
         // Erase element both from registry & list
         l2RawPacketReg.erase(regIndex);
         l2RawPacketList.pop_front();
      }
      else break;
   }

   // Read raw L2 packet (network byte order)
   // ---------------------------------------
   // Access to the possible new L2 packet in the registry (for future use after storage, e.g. for isIP decision)
   std::multimap<unsigned long, L2RawPacket>::iterator newL2RawPacketIndex;

   // Read L2 packet
   if (gzread(inFile,tmpBuffer,savedL2PacketLength)<=0)
   {
      // End of file reached (or other read error)
      *p_pErrorCode = ERROR_EOF;
      return NULL;
   }

   // Calculate L2 CRC32 and detect duplicates
   // ----------------------------------------
   bool found = false;
   if (staple.ignoreL2Duplicates)
   {
      unsigned long crc=0xffffffff;
      for (int i=0;i<savedL2PacketLength;i++)
      {
         crc = ((crc>>8) & 0x00ffffff) ^ crcTable[(crc^tmpBuffer[i]) & 0xff];
      }
      crc ^= 0xffffffff;
      // Try to find the packet in the L2 duplicate registry
      std::multimap<unsigned long, L2RawPacket>::iterator oldL2RawPacketIndex;
      std::multimap<unsigned long, L2RawPacket>::iterator index = l2RawPacketReg.find(crc);
      // Found the same CRC
      if (index != l2RawPacketReg.end())
      {
         // Check all the packets with the same CRC 
         while ((*index).first==crc)
         {
            // Same original and saved length?
            L2RawPacket& oldL2RawPacket = (*index).second;
            if ((origL2PacketLength == oldL2RawPacket.origL2PacketLength) && (savedL2PacketLength == oldL2RawPacket.savedL2PacketLength))
            {
               // Same content?
               if (memcmp((char*)tmpBuffer,(char*)oldL2RawPacket.data,savedL2PacketLength) == 0)
               {
                  // Packet found -> L2 duplicate
                  found=true;
                  oldL2RawPacketIndex=index;
                  break;
               }
            }
            // Not the same, check the next packet (if there is any)
            index++;
            if (index == l2RawPacketReg.end()) break;
         }
      }
   
      if (found == true)
      {
         // Duplicated packet -> get reference to the old L2 packet
         L2RawPacket& oldL2RawPacket = (*oldL2RawPacketIndex).second;
         // Increase its dupCount
         oldL2RawPacket.dupCount++;
         // Update statistics
         staple.packetsDuplicated[(oldL2RawPacket.dupCount<DUPSTATS_MAX) ? oldL2RawPacket.dupCount : DUPSTATS_MAX]++;
         if (oldL2RawPacket.isIP == true)
         {
            staple.ipStats.packetsDuplicated[(oldL2RawPacket.dupCount<DUPSTATS_MAX) ? oldL2RawPacket.dupCount : DUPSTATS_MAX]++;
         }
         // All, or every second duplicate will be ignored
         if (((oldL2RawPacket.dupCount&1) == 1) || (DECODE_EVERY_SECOND_L2_DUPLICATE == false))
         {
            // Return with error
            if (staple.logLevel>=5) staple.logStream << "L2 duplicate detected (packet ignored) at " << gztell(inFile) << "\n";
   
            *p_pErrorCode = ERROR_L2_DUPLICATE;
            return NULL;
         }
      }
      else
      {
         // Non-duplicated (new) packet -> create L2 packet
         L2RawPacket l2RawPacket;
         l2RawPacket.origL2PacketLength = origL2PacketLength;
         l2RawPacket.savedL2PacketLength = savedL2PacketLength;
         l2RawPacket.data = new Byte[savedL2PacketLength];
         memcpy(l2RawPacket.data,tmpBuffer,savedL2PacketLength);
         // Add L2 packet to the map
         std::multimap<unsigned long, L2RawPacket>::iterator index = l2RawPacketReg.insert(std::make_pair(crc,l2RawPacket));
         // Enable future access of the newly stored packet (e.g., for isIP decision during decoding)
         newL2RawPacketIndex = index;
         // Create list entry
         L2RawPacketListEntry l2RawPacketListEntry;
         l2RawPacketListEntry.time = time;
         l2RawPacketListEntry.regIndex = index;
         // Add it to the end of the list
         l2RawPacketList.push_back(l2RawPacketListEntry);
         // Update statistics
         staple.packetsDuplicated[0]++;
      }
   }

   // Decode L2 packet
   // ----------------
   // Declare L2 return packet
   L2Packet* pL2Packet = NULL;

   unsigned short actPos = 0;
   bool isIP = true;

   switch (linkType)
   {
      // Read Ethernet link layer header
      // -------------------------------
      case LINKTYPE_ETH:
      {
         // Allocate Ethernet return packet
         EthernetPacket* pEthernetPacket = new EthernetPacket(staple);
         pEthernetPacket->Init();
   
         // Read source & dest MAC addresses
         memcpy(pEthernetPacket->dstMAC.addr,&tmpBuffer[actPos],6);
         memcpy(pEthernetPacket->srcMAC.addr,&tmpBuffer[actPos+6],6);
         actPos += 12;
   
         // Read Type/Length
         tmpWord.byte[staple.byteOrderPlatform] = tmpBuffer[actPos++];
         tmpWord.byte[1 - staple.byteOrderPlatform] = tmpBuffer[actPos++];
   
         // VLAN frame?
         short VLANId = -1;
         if (tmpWord.data == 0x8100)
         {
            // Read additional VLAN tag
            tmpWord.byte[staple.byteOrderPlatform] = tmpBuffer[actPos++];
            tmpWord.byte[1 - staple.byteOrderPlatform] = tmpBuffer[actPos++];
            VLANId = tmpWord.data&0x0fff;
   
            // Read Type/Length
            tmpWord.byte[staple.byteOrderPlatform] = tmpBuffer[actPos++];
            tmpWord.byte[1 - staple.byteOrderPlatform] = tmpBuffer[actPos++];
         }
         pEthernetPacket->VLANId = VLANId;
   
         // Non-IP packet?
         if (tmpWord.data != 0x0800) isIP=false;

         // Assign return packet
         pL2Packet = (L2Packet*)pEthernetPacket;
         break;
      }
      // Read PPP link layer header
      // --------------------------
      case LINKTYPE_PPP:
      {
         // Skip flag, address and control
         actPos += 3;
   
         // Read protocol
         tmpWord.byte[staple.byteOrderPlatform] = tmpBuffer[actPos++];
         tmpWord.byte[1 - staple.byteOrderPlatform] = tmpBuffer[actPos++];

         // Non-IP packet?
         if (tmpWord.data != 0x0021) isIP=false;
         // NO BREAK!!! (to build the default return packet)
      }
      // Build the default L2 return packet
      // ----------------------------------
      default:
      {
         // Allocate the default L2 return packet
         pL2Packet = new L2Packet(staple);
         pL2Packet->Init();
         break;
      }
   }
   // Fill out common L2 fields
   pL2Packet->time = time;
   pL2Packet->l2SavedLen = savedL2PacketLength;

   // If new L2 packet was created & it is an IP packet -> set IP flag & update IP duplicate statistics
   if (staple.ignoreL2Duplicates && (found == false) && (isIP == true))
   {
      (*newL2RawPacketIndex).second.isIP = true;
      staple.ipStats.packetsDuplicated[0]++;
   }

   // Decode L3 packet and embed it into the L2 return packet
   // -------------------------------------------------------
   // Calculate saved L3 packet length (this may include L2 padding [but not PPP FCS]!)
   unsigned short savedL3PacketLength = ((linkType==LINKTYPE_PPP) && (savedL2PacketLength>=(origL2PacketLength-2))) ?
                         origL2PacketLength-actPos-2 :
                         savedL2PacketLength-actPos;
   // If L3 packet is IP, decode it
   if (isIP==true)
   {
      // Embed L3 packet into the L2 packet
      pL2Packet->pL3Packet = DecodeIPPacket((char*)&tmpBuffer[actPos], savedL3PacketLength, staple);
      if (pL2Packet->pL3Packet) pL2Packet->pL3Packet->pL2Packet = pL2Packet;

      // Overwrite direction & match info (only for ethernet packets, if we have the switch MAC addresses specified)
      if ((pL2Packet->pL3Packet != NULL) && (pL2Packet->l2Type==L2Packet::ETHERNET) && ((staple.netMACLen[0]>0) || (staple.netMACLen[1]>0)))
      {
         int macMatchNum=0;
         int macDir=0;
         // Check MAC A match (if specified)
         if (staple.netMACLen[0]>0)
         {
            if (((EthernetPacket*)pL2Packet)->srcMAC.comparePrefix(staple.netMAC[0] , staple.netMACLen[0]) == true)
            {
               macMatchNum++;
               macDir = 0;
            }
            else if (((EthernetPacket*)pL2Packet)->dstMAC.comparePrefix(staple.netMAC[0], staple.netMACLen[0]) == true)
            {
               macMatchNum++;
               macDir = 1;
            }
         }
         // Check MAC B match (if specified)
         if (staple.netMACLen[1]>0)
         {
            if (((EthernetPacket*)pL2Packet)->srcMAC.comparePrefix(staple.netMAC[1], staple.netMACLen[1]) == true)
            {
               macMatchNum++;
               macDir = 1;
            }
            else if (((EthernetPacket*)pL2Packet)->dstMAC.comparePrefix(staple.netMAC[1], staple.netMACLen[1]) == true)
            {
               macMatchNum++;
               macDir = 0;
            }
         }
         // Both MAC addresses must match if we specified both, otherwise 1 match is enough
         if (((macMatchNum==1) && ((staple.netMACLen[0]>0)^(staple.netMACLen[1]>0))) ||
            ((macMatchNum==2) && ((staple.netMACLen[0]>0)&&(staple.netMACLen[1]>0))))
         {
            ((IPPacket*)(pL2Packet->pL3Packet))->match = true;
            ((IPPacket*)(pL2Packet->pL3Packet))->direction = macDir;
         }
      }
   }

   // We have read the L3 packet
   actPos += savedL3PacketLength;

   // Skip rest of the packet (e.g., PPP FCS)
   actPos = savedL2PacketLength;

   *p_pErrorCode = NO_ERROR;
   return pL2Packet;
}

// GLOBAL function for decoding IP packets (TODO: inheritance)
L3Packet* DecodeIPPacket(char* p_pBuffer, unsigned short p_len, Staple& staple)
{
   Byte tmpByte;
   Word tmpWord;
   DoubleWord tmpDoubleWord;
   unsigned short actPos = 0;
   // Check whether we have captured the first byte of the IP packet
   bool decodable = true;
   if (p_len < 1) decodable=false;
   // Read IP version & IP header length if possible
   unsigned short IPHLen;
   if (decodable==true)
   {
      tmpByte = p_pBuffer[actPos++];

      // Non-IPv4 packets will not be decoded
      if ((tmpByte&0xf0) != 0x40)
      {
         decodable=false;
      }
      // IPv4 packet
      else
      {
         // IP header length
         IPHLen = 4*(tmpByte&0x0f);
         // Sanity check of IPHLen
         if (IPHLen < 20)
         {
            if (staple.logLevel>=5) staple.logStream << "IP header length too low!\n";
            return NULL;
         }
         // Check whether we have captured the entire IP header
         if ((p_len-actPos) < (IPHLen-1)) decodable=false;
      }
   }

   // Non-IPv4 or too short packets are not decoded
   // ---------------------------------------------
   if (decodable==false) return NULL;

   // Skip ToS
   actPos++;

   // Read full IP packet length
   tmpWord.byte[staple.byteOrderPlatform] = p_pBuffer[actPos++];
   tmpWord.byte[1 - staple.byteOrderPlatform] = p_pBuffer[actPos++];
   unsigned short IPPktLen = tmpWord.data;

   // Sanity check of IPHLen vs. IPPktLen
   if (IPHLen > IPPktLen)
   {
      if (staple.logLevel>=5) staple.logStream << "IP header length too high!\n";
      return NULL;
   }

   // Read IP Id
   tmpWord.byte[staple.byteOrderPlatform] = p_pBuffer[actPos++];
   tmpWord.byte[1 - staple.byteOrderPlatform] = p_pBuffer[actPos++];
   unsigned short IPId = tmpWord.data;

   // Read IP flags and fragmentation info
   tmpWord.byte[staple.byteOrderPlatform] = p_pBuffer[actPos++];
   tmpWord.byte[1 - staple.byteOrderPlatform] = p_pBuffer[actPos++];

   unsigned char IPFlags = (tmpWord.data&0xe000)>>13;
   unsigned short fragOffset = (tmpWord.data&0x1fff)<<3;

   // Skip TTL
   actPos++;

   // Read protocol
   unsigned char protocol = p_pBuffer[actPos++];

   // Skip IP CRC
   actPos += 2;

   // Read source IP address
   tmpDoubleWord.byte[3*staple.byteOrderPlatform] = p_pBuffer[actPos++];
   tmpDoubleWord.byte[1+staple.byteOrderPlatform] = p_pBuffer[actPos++];
   tmpDoubleWord.byte[2-staple.byteOrderPlatform] = p_pBuffer[actPos++];
   tmpDoubleWord.byte[3*(1-staple.byteOrderPlatform)] = p_pBuffer[actPos++];
   DoubleWord srcIP = tmpDoubleWord;

   // Read destination IP address
   tmpDoubleWord.byte[3*staple.byteOrderPlatform] = p_pBuffer[actPos++];
   tmpDoubleWord.byte[1+staple.byteOrderPlatform] = p_pBuffer[actPos++];
   tmpDoubleWord.byte[2-staple.byteOrderPlatform] = p_pBuffer[actPos++];
   tmpDoubleWord.byte[3*(1-staple.byteOrderPlatform)] = p_pBuffer[actPos++];
   DoubleWord dstIP = tmpDoubleWord;

   // Filter IP addresses & determine packet direction
   bool matchNet[2];
   short matchNum[2];
   matchNet[0] = false;
   matchNet[1] = false;
   matchNum[0] = -1;
   matchNum[1] = -1;
   unsigned char direction;
   for (unsigned short netId=0;netId<=1;netId++)
   {
      for (unsigned short actFilter = 0; actFilter < staple.addrFilterNum[netId]; ++actFilter)
      {
         // Perform IP filtering if necessary
         if (staple.netGiven[netId][actFilter])
         {
            if ((srcIP.data & staple.netMask[netId][actFilter].data) == (staple.netIP[netId][actFilter].data & staple.netMask[netId][actFilter].data))
            {
               matchNet[netId] = true;
               matchNum[netId] = actFilter;
               direction = netId;
               break;
            }
            else if ((dstIP.data & staple.netMask[netId][actFilter].data) == (staple.netIP[netId][actFilter].data & staple.netMask[netId][actFilter].data))
            {
               matchNet[netId] = true;
               matchNum[netId] = actFilter;
               direction = 1-netId;
               break;
            }
         }
      }
   }

   // Skip IP options
   actPos += IPHLen-20;

   // TCP packet (check snaplength)
   // -----------------------------
   if ((protocol == 6) && ((p_len-actPos) >= 20))
   {
      // Create TCP return packet
      TCPPacket* pL3Packet = new TCPPacket(staple);
      pL3Packet->Init();
      pL3Packet->IPPktLen = IPPktLen;
      pL3Packet->IPId = IPId;
      pL3Packet->IPFlags = IPFlags;
      pL3Packet->fragOffset = fragOffset;
      pL3Packet->srcIP = srcIP;
      pL3Packet->dstIP = dstIP;
      pL3Packet->match = (matchNet[0] || matchNet[1]);
      pL3Packet->direction = direction;

      // Read TCP source port
      tmpWord.byte[staple.byteOrderPlatform] = p_pBuffer[actPos++];
      tmpWord.byte[1-staple.byteOrderPlatform] = p_pBuffer[actPos++];
      pL3Packet->srcPort = tmpWord.data;

      // Read TCP destination port
      tmpWord.byte[staple.byteOrderPlatform] = p_pBuffer[actPos++];
      tmpWord.byte[1-staple.byteOrderPlatform] = p_pBuffer[actPos++];
      pL3Packet->dstPort = tmpWord.data;

      // Read TCP sequence number
      tmpDoubleWord.byte[3*staple.byteOrderPlatform] = p_pBuffer[actPos++];
      tmpDoubleWord.byte[1+staple.byteOrderPlatform] = p_pBuffer[actPos++];
      tmpDoubleWord.byte[2-staple.byteOrderPlatform] = p_pBuffer[actPos++];
      tmpDoubleWord.byte[3*(1-staple.byteOrderPlatform)] = p_pBuffer[actPos++];
      pL3Packet->seq = tmpDoubleWord.data;

      // Read TCP acknowledgement number
      tmpDoubleWord.byte[3*staple.byteOrderPlatform] = p_pBuffer[actPos++];
      tmpDoubleWord.byte[1+staple.byteOrderPlatform] = p_pBuffer[actPos++];
      tmpDoubleWord.byte[2-staple.byteOrderPlatform] = p_pBuffer[actPos++];
      tmpDoubleWord.byte[3*(1-staple.byteOrderPlatform)] = p_pBuffer[actPos++];
      pL3Packet->ack = tmpDoubleWord.data;

      // Read TCP header length
      tmpByte = p_pBuffer[actPos++];
      unsigned short TCPHLen = (tmpByte&0xf0)>>2;

      // Sanity check of TCPHLen
      if (TCPHLen < 20)
      {
         if (staple.logLevel>=5) staple.logStream << "TCP header length too low!\n";
         delete pL3Packet;
         return NULL;
      }

      // Sanity check of IPHLen+TCPHLen vs. IPPktLen
      if ((IPHLen+TCPHLen) > IPPktLen)
      {
         if (staple.logLevel>=5) staple.logStream << "TCP header length too high!\n";
         delete pL3Packet;
         return NULL;
      }

      // Calculate TCP payload length
      pL3Packet->TCPPLLen = pL3Packet->IPPktLen - IPHLen - TCPHLen;

      // Read TCP flags
      pL3Packet->TCPFlags = p_pBuffer[actPos++];

      // Read TCP receiver window size
      tmpWord.byte[staple.byteOrderPlatform] = p_pBuffer[actPos++];
      tmpWord.byte[1-staple.byteOrderPlatform] = p_pBuffer[actPos++];
      pL3Packet->rwnd = tmpWord.data;

      // Skip CRC & urgent pointer
      actPos += 4;

      // Process TCP options (if snaplength is enough to process ALL options [no partial processing])
      pL3Packet->options = TCPPacket::NONE;
      pL3Packet->sackBlockNum = 0;
      pL3Packet->tsValue = 0;
      pL3Packet->tsEcho = 0;
      pL3Packet->wndScaleVal = 0;
      if ((p_len-actPos) >= (TCPHLen-20))
      {
         unsigned short optBytesRead = 0;
         bool optionLenOK;
         Byte optionType;
         Byte optionLen;
         while ((optBytesRead < (TCPHLen-20)))
         {
            // Read option type
            optionType = p_pBuffer[actPos++];
            optBytesRead++;
            // End of option list
            if (optionType == 0x00) break;
            // NOP option
            if (optionType == 0x01) continue;
            switch (optionType)
            {
               // MSS option
               case 0x02: pL3Packet->options |= TCPPacket::MSS;break;
               // Window scale option
               case 0x03: pL3Packet->options |= TCPPacket::WNDSCALE;break;
               // SACK permitted option
               case 0x04: pL3Packet->options |= TCPPacket::SACKPERM;break;
               // SACK option
               case 0x05: pL3Packet->options |= TCPPacket::SACK;break;
               // Timestamp option
               case 0x08: pL3Packet->options |= TCPPacket::TIMESTAMP;break;
            }
            // Check whether we have captured the option length (because of buggy TCP options/TCP hlen)
            if (optBytesRead < (TCPHLen-20)) optionLenOK=true;
            else optionLenOK=false;
            // Read option length if possible
            if (optionLenOK==true)
            {
               optionLen = p_pBuffer[actPos++];
               optBytesRead++;
               // Sanity check of option length
               if ((optionLen < 2) || (optBytesRead+optionLen-2) > (TCPHLen-20)) optionLenOK=false;
            }
            // Return if option length is wrong
            if (optionLenOK==false)
            {
               if (staple.logLevel>=5) staple.logStream << "Bad TCP option length!\n";
               delete pL3Packet;
               return NULL;
            }
            // Process option content
            switch (optionType)
            {
               // SACK option
               case 0x05:
               {
                  // Check SACK option length (must be multiples of 8 bytes)
                  if ((((optionLen-2)%8) != 0) && ((optionLen-2) > 0))
                  {
                     if (staple.logLevel>=5) staple.logStream << "Bad SACK option length!\n";
                     delete pL3Packet;
                     return NULL;
                  }
                  // Process SACK info
                  pL3Packet->sackBlockNum = (optionLen-2)/8;
                  for (int i=0;i<pL3Packet->sackBlockNum;i++)
                  {
                     tmpDoubleWord.byte[3*staple.byteOrderPlatform] = p_pBuffer[actPos++];
                     tmpDoubleWord.byte[1+staple.byteOrderPlatform] = p_pBuffer[actPos++];
                     tmpDoubleWord.byte[2-staple.byteOrderPlatform] = p_pBuffer[actPos++];
                     tmpDoubleWord.byte[3*(1-staple.byteOrderPlatform)] = p_pBuffer[actPos++];
                     pL3Packet->sackLeftEdge[i] = tmpDoubleWord.data;
                     tmpDoubleWord.byte[3*staple.byteOrderPlatform] = p_pBuffer[actPos++];
                     tmpDoubleWord.byte[1+staple.byteOrderPlatform] = p_pBuffer[actPos++];
                     tmpDoubleWord.byte[2-staple.byteOrderPlatform] = p_pBuffer[actPos++];
                     tmpDoubleWord.byte[3*(1-staple.byteOrderPlatform)] = p_pBuffer[actPos++];
                     pL3Packet->sackRightEdge[i] = tmpDoubleWord.data;
                     optBytesRead += 8;
                  }
                  break;
               }
               // Timestamp option
               case 0x08:
               {
                  // Sanity check of timestamp option length
                  if (optionLen!=10)
                  {
                     if (staple.logLevel>=5) staple.logStream << "Bad TCP timestamp option length!\n";
                     delete pL3Packet;
                     return NULL;
                  }
                  // Read TS Value and TS Echo
                  tmpDoubleWord.byte[3*staple.byteOrderPlatform] = p_pBuffer[actPos++];
                  tmpDoubleWord.byte[1+staple.byteOrderPlatform] = p_pBuffer[actPos++];
                  tmpDoubleWord.byte[2-staple.byteOrderPlatform] = p_pBuffer[actPos++];
                  tmpDoubleWord.byte[3*(1-staple.byteOrderPlatform)] = p_pBuffer[actPos++];
                  pL3Packet->tsValue = tmpDoubleWord.data;
                  tmpDoubleWord.byte[3*staple.byteOrderPlatform] = p_pBuffer[actPos++];
                  tmpDoubleWord.byte[1+staple.byteOrderPlatform] = p_pBuffer[actPos++];
                  tmpDoubleWord.byte[2-staple.byteOrderPlatform] = p_pBuffer[actPos++];
                  tmpDoubleWord.byte[3*(1-staple.byteOrderPlatform)] = p_pBuffer[actPos++];
                  pL3Packet->tsEcho = tmpDoubleWord.data;
                  optBytesRead += 8;
                  break;
               }
               case 0x03:
               {
                  // Sanity check of window scale option length
                  if (optionLen!=3)
                  {
                     if (staple.logLevel>=5) staple.logStream << "Bad TCP window scale option length!\n";
                     delete pL3Packet;
                     return NULL;
                  }
                  // Read window scale value
                  pL3Packet->wndScaleVal = p_pBuffer[actPos++];
                  optBytesRead += 1;
                  break;
               }
               // Other options will not be processed
               default:
               {
                  actPos += optionLen-2;
                  optBytesRead += optionLen-2;
               }
            }
         }
         // Skip option padding
         actPos += (TCPHLen-20)-optBytesRead;
         // Read the TCP packet payload
         unsigned short PLdumped = (pL3Packet->TCPPLLen > (p_len-actPos)) ? (p_len-actPos) : pL3Packet->TCPPLLen;
         if (PLdumped > 0)
         {
            pL3Packet->payload = new Byte[PLdumped];
            pL3Packet->payloadSavedLen = PLdumped;
            memcpy((char*)pL3Packet->payload, (char*)&p_pBuffer[actPos], PLdumped);
            actPos += PLdumped;
         }
      }
      // Not enough snaplen
      else
      {
         // Skip options (=skip the rest of the packet)
         actPos = p_len;
      }

      // Filter ports
      if (pL3Packet->match == true)
      {
         if ((matchNet[0]==true) && (staple.portGiven[0][matchNum[0]] == true))
         {
            unsigned short netAPort = (pL3Packet->direction == 0) ? pL3Packet->srcPort : pL3Packet->dstPort;
            if (netAPort != staple.netPort[0][matchNum[0]]) pL3Packet->match = false;
         }
         if ((matchNet[1]==true) && (staple.portGiven[1][matchNum[1]] == true))
         {
            unsigned short netBPort = (pL3Packet->direction == 0) ? pL3Packet->dstPort : pL3Packet->srcPort;
            if (netBPort != staple.netPort[1][matchNum[0]]) pL3Packet->match = false;
         }
      }

      // Skip rest of the packet (e.g., link layer padding)
      actPos = p_len;
      return pL3Packet;
   }

   // UDP packet
   // ----------
   if ((protocol == 17) && ((p_len-actPos) >= 8))
   {
      // Create UDP return packet
      UDPPacket* pL3Packet = new UDPPacket(staple);
      pL3Packet->Init();
      pL3Packet->IPPktLen = IPPktLen;
      pL3Packet->IPId = IPId;
      pL3Packet->IPFlags = IPFlags;
      pL3Packet->fragOffset = fragOffset;
      pL3Packet->srcIP = srcIP;
      pL3Packet->dstIP = dstIP;
      pL3Packet->match = (matchNet[0] || matchNet[1]);
      pL3Packet->direction = direction;

      // Read UDP source port
      tmpWord.byte[staple.byteOrderPlatform] = p_pBuffer[actPos++];
      tmpWord.byte[1-staple.byteOrderPlatform] = p_pBuffer[actPos++];
      pL3Packet->srcPort = tmpWord.data;

      // Read UDP destination port
      tmpWord.byte[staple.byteOrderPlatform] = p_pBuffer[actPos++];
      tmpWord.byte[1-staple.byteOrderPlatform] = p_pBuffer[actPos++];
      pL3Packet->dstPort = tmpWord.data;

      // Read UDP length
      tmpWord.byte[staple.byteOrderPlatform] = p_pBuffer[actPos++];
      tmpWord.byte[1-staple.byteOrderPlatform] = p_pBuffer[actPos++];
      pL3Packet->UDPPLLen = tmpWord.data;
      pL3Packet->UDPPLLen -= 8;

      // Skip checksum
      actPos += 2;

      // Read the UDP packet payload
      unsigned short PLdumped = (pL3Packet->UDPPLLen > (p_len-actPos)) ? (p_len-actPos) : pL3Packet->UDPPLLen;
      if (PLdumped > 0)
      {
         pL3Packet->payload = new Byte[PLdumped];
         pL3Packet->payloadSavedLen = PLdumped;
         memcpy((char*)pL3Packet->payload, (char*)&p_pBuffer[actPos], PLdumped);
         actPos += PLdumped;
      }

      // Filter ports
      if (pL3Packet->match == true)
      {
         if ((matchNet[0]==true) && (staple.portGiven[0][matchNum[0]] == true))
         {
            unsigned short netAPort = (pL3Packet->direction == 0) ? pL3Packet->srcPort : pL3Packet->dstPort;
            if (netAPort != staple.netPort[0][matchNum[0]]) pL3Packet->match = false;
         }
         if ((matchNet[1]==true) && (staple.portGiven[1][matchNum[1]] == true))
         {
            unsigned short netBPort = (pL3Packet->direction == 0) ? pL3Packet->dstPort : pL3Packet->srcPort;
            if (netBPort != staple.netPort[1][matchNum[0]]) pL3Packet->match = false;
         }
      }

      // Skip rest of the packet (e.g., link layer padding)
      actPos = p_len;
      return pL3Packet;
   }

   // ICMP packet
   // ----------
   if ((protocol == 1) && ((p_len-actPos) >= 2))
   {
      // Create ICMP return packet
      ICMPPacket* pL3Packet = new ICMPPacket(staple);
      pL3Packet->Init();
      pL3Packet->IPPktLen = IPPktLen;
      pL3Packet->IPId = IPId;
      pL3Packet->IPFlags = IPFlags;
      pL3Packet->fragOffset = fragOffset;
      pL3Packet->srcIP = srcIP;
      pL3Packet->dstIP = dstIP;
      pL3Packet->match = (matchNet[0] || matchNet[1]);
      pL3Packet->direction = direction;

      // Read ICMP type code
      tmpWord.byte[staple.byteOrderPlatform] = p_pBuffer[actPos++];
      tmpWord.byte[1-staple.byteOrderPlatform] = p_pBuffer[actPos++];
      pL3Packet->typeCode = tmpWord.data;

      // Skip rest of the packet (incl. link layer padding)
      actPos = p_len;
      return pL3Packet;
   }

   // Non-TCP/non-UDP/non-ICMP (e.g. IGMP) or too short snaplength packet
   // -------------------------------------------------------------------
   // Create IP return packet
   IPPacket* pL3Packet = new IPPacket(staple);
   pL3Packet->Init();
   pL3Packet->IPPktLen = IPPktLen;
   pL3Packet->IPId = IPId;
   pL3Packet->IPFlags = IPFlags;
   pL3Packet->fragOffset = fragOffset;
   pL3Packet->srcIP = srcIP;
   pL3Packet->dstIP = dstIP;
   pL3Packet->match = (matchNet[0] || matchNet[1]);
   pL3Packet->direction = direction;

   // Read the IP packet payload
   unsigned short PLdumped = (pL3Packet->IPPktLen > (p_len-actPos)) ? (p_len-actPos) : pL3Packet->IPPktLen;
   if (PLdumped > 0)
   {
      pL3Packet->payload = new Byte[PLdumped];
      pL3Packet->payloadSavedLen = PLdumped;
      memcpy((char*)pL3Packet->payload, (char*)&p_pBuffer[actPos], PLdumped);
      actPos += PLdumped;
   }

   // Skip rest of the packet (incl. link layer padding)
   actPos = p_len;
   return pL3Packet;
}

void PacketDumpFile::CloseInputFile()
{
   if (inFile!=NULL) gzclose(inFile);
   return;
}

PacketDumpFile::ErrorCode PacketDumpFile::OpenOutputFile()
{
   // Open a (temporary) output dumpfile
   std::stringstream outfileTmpName;
   outfileTmpName << staple.outputDumpTmpPrefix << "_" << outfileSlotNum * staple.outfileSlotTime;
   outFile = gzopen(outfileTmpName.str().c_str(),"wb");
   // File open error
   if (outFile == NULL) return ERROR_OPEN;

   DoubleWord tmpDoubleWord;
   Word tmpWord;

   if (staple.logLevel>=5) staple.logStream << "Writing output dump file header.\n";

   // Write "magic number"
   tmpDoubleWord.data = 0xa1b2c3d4;
   gzwrite(outFile,(char*)(&tmpDoubleWord.data),4);
   // Write version number
   tmpWord.data = 2;
   gzwrite(outFile,(char*)(&tmpWord.data),2);
   tmpWord.data = 4;
   gzwrite(outFile,(char*)(&tmpWord.data),2);
   // Write UTC time offset
   gzwrite(outFile,(char*)(&utcOffset.data),4);
   // Write timestamp granularity info
   gzwrite(outFile,(char*)(&granularity.data),4);
   // Write snaplength
   gzwrite(outFile,(char*)(&snapLength.data),4);
   // Write link type code
   gzwrite(outFile,(char*)(&linkTypeCode.data),4);

   return NO_ERROR;
}

void PacketDumpFile::WriteActualPacket()
{
   // Initialize output file if needed
   if (outFile==NULL)
   {
      outfileSlotNum = staple.actTime.tv_sec / staple.outfileSlotTime;
      OpenOutputFile();
   }

   // Should we start a new slot?
   unsigned long actSlotNum = staple.actTime.tv_sec / staple.outfileSlotTime;
   while (actSlotNum > outfileSlotNum)
   {
      // Close temporary output dump file and rename it to its final name
      CloseOutputFile();
      // Process next slot
      outfileSlotNum++;
      // Open a new (temporary) file
      OpenOutputFile();
   }

   if (staple.logLevel>=5) staple.logStream << "Writing packet to the output dump file at position " << gztell(outFile) << "\n";
   // Write packet time
   gzwrite(outFile,(char*)(&staple.actTime),8);
   // Write saved packet length
   gzwrite(outFile,(char*)(&savedL2PacketLength),4);
   // Write original packet length
   gzwrite(outFile,(char*)(&origL2PacketLength),4);
   // Write packet data
   gzwrite(outFile,(char*)(&tmpBuffer),savedL2PacketLength);

   return;   
}

void PacketDumpFile::CloseOutputFile()
{
   // Close temporary output dump file
   if (outFile!=NULL)
   {
      gzclose(outFile);
      // Rename temporary output dumpfile to its final name
      std::stringstream outfileTmpName;
      std::stringstream outfileName;
      outfileTmpName << staple.outputDumpTmpPrefix << "_" << outfileSlotNum * staple.outfileSlotTime;
      outfileName << staple.outputDumpPrefix << "_" << outfileSlotNum * staple.outfileSlotTime;
      rename(outfileTmpName.str().c_str(), outfileName.str().c_str());
   }
   return;
}
