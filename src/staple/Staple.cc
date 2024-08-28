#include <staple/Staple.h>
#include <staple/Parser.h>
#include <staple/http/Counter.h>
#include "Util.h"

#include <sstream>

Staple::Staple() :
   // Init input parameters
   logLevel(1),
   outputDumpGiven(false),
   outputDumpPrefix("dump"),
   outputDumpTmpPrefix("tmp"),
   outfileSlotTime(300),
   perfmonDirName(""),
   perfmonLogPrefix(""),
   ignoreL2Duplicates(false),
   packetDumpFile(*this),
   // Init internal variables
   packetsRead(0),
   tsMinorReorderingNum(0),
   tsMajorReorderingNum(0),
   tsJumpNum(0),
   tsJumpLen(0),
   logStream(NULL),
   parser(new Parser(*this))
{
   // Init input parameters
   addrFilterNum[0] = 0;
   addrFilterNum[1] = 0;
   netMACLen[0] = 0;
   netMACLen[1] = 0;
   // Init stats
   ipStats.Init();
   tcpStats.Init();
   udpStats.Init();
   icmpStats.Init();
   mp4Stats.Init();
   for (int i = 0; i <= DUPSTATS_MAX; ++i) {packetsDuplicated[i] = 0;}
   parser->Init();
   // Get system time (for processing speed calculation)
   gettimeofday(&startRealTime, 0);
   lastRealTime = startRealTime;
   // Endianness test by Elverion at http://www.allegro.cc/forums/print-thread/592785
   unsigned char ee[2] = {1, 0};
   byteOrderPlatform = *(short*)ee == 1;

   counterContainer_ = new CounterContainer(*this);
}

Staple::~Staple()
{
   parser->FinishConnections();
   delete counterContainer_;
}

void Staple::config(std::string const& key, std::string const& val, void* ptr) throw (std::string)
{
   Staple& staple = *reinterpret_cast<Staple*>(ptr);
   if (key == "byteOrder")
   {
      staple.byteOrderPlatform = (val == "0") ? 0 : 1;
   }
   else if (key == "outDir")
   {
      std::size_t i = val.find_first_not_of("'\"");
      std::size_t j = val.find_first_of("'\"", i + 1);
      if ((i == std::string::npos) || (j == std::string::npos))
      {
         std::ostringstream o;
         o << "bad outDir \"" << val << "\"";
         throw o.str();
      }
      else
      {
         staple.perfmonDirName = val;
      }
   }
   else if (key == "tcpSSBytes")
      TCPTA_SSTHRESH = parseint(val);
   else if (key == "tcpSSFlightSize")
      TCPTA_SSMAXFS = parseint(val);
   else if (key == "tcpMinSize")
      TCPTA_MINSIZE = parseint(val);
   else if (key == "tcpCRMinPipe")
      CHANNELRATE_MIN_PIPE = parseint(val);
   else if (key == "tcpCRMinTime")
      CHANNELRATE_MIN_TIME = parseint(val);
   else if (key == "tcpCRMinBytes")
      CHANNELRATE_MIN_DATA = parseint(val);
   else if (key == "tcpACKComprTime")
      ACK_COMPRESSION_TIME = parsedbl(val);
   else if (key == "tcpRTTMaxBefore")
      UNLOADED_MAXDATA_BEFORE = parseint(val);
   else if (key == "tcpRTTMaxDuring")
      UNLOADED_MAXDATA_DURING = parseint(val);
   else
   {
      std::ostringstream o;
      o << "unknown setting \"" << key << "\" -> \"" << val << "\"";
      throw o.str();
   }
}

CounterContainer* Staple::getCounterContainer()
{
	return counterContainer_;
}
