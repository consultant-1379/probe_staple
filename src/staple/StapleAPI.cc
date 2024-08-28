#include <staple/StapleAPI.h>
#include <staple/Packet.h>
#include <staple/Parser.h>
#include "Util.h"

#ifndef LIBSTAPLE_VERSION
#define LIBSTAPLE_VERSION "unknown"
#endif

std::string staple::libstaple_version()
{
   return LIBSTAPLE_VERSION;
}

staple::StapleAPI::StapleAPI() : s(new Staple()) {}

void staple::StapleAPI::status(std::ostream& ss)
{
   ss << "IP sessions: " << s->ipSessionReg.size()
      << ", TCP connections: " << s->tcpConnReg.size();
   // FIXME efrekui
   // << ", HTTP sessions: " << httpEngine.numSessions();
}

void staple::StapleAPI::config(std::string const& cfg, std::ostream* log)
{
   //FIXME use boost.regex if available
   config_real(cfg, Staple::config, static_cast<void*>(s.get()), log);
}

void staple::StapleAPI::TCPTAlog(std::ostream* ss) { s->parser->perfmonTCPTAFile = ss; }
void staple::StapleAPI::FLVlog(std::ostream* ss) { s->parser->perfmonFLVFile = ss; }
void staple::StapleAPI::HTTPPageLog(std::ostream* ss) { s->parser->setHTTPPageLog(ss); }
void staple::StapleAPI::HTTPRequestLog(std::ostream* ss) { s->parser->setHTTPRequestLog(ss); }

bool staple::StapleAPI::parsePacket(char * bytes, unsigned short int len, const struct timeval & t, bool uplink)
{
   Parser & p = *s->parser;
   EthernetPacket eth(p.staple);
   eth.Init();
   eth.time = t;
   eth.pL3Packet = DecodeIPPacket(bytes, len, p.staple);
   if (!eth.pL3Packet) return false;
   eth.pL3Packet->pL2Packet = &eth;
   static_cast<IPPacket*>(eth.pL3Packet)->direction = uplink ? 0 : 1;
   static_cast<IPPacket*>(eth.pL3Packet)->match = true;
   p.ParsePacket(static_cast<L2Packet*>(&eth));
   return true;
}
