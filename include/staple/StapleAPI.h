#ifndef STAPLEAPI_H
#define STAPLEAPI_H

#include <string>
#include <ostream>
#include <memory>
#include <sys/time.h>

class Staple;

namespace staple
{
   std::string libstaple_version();

   /**
    * Entry point to global settings in libstaple.
    */
   class StapleAPI
   {
   public:
       StapleAPI();
       
       /** Describe runtime status (tracked connections etc.) */
       void status(std::ostream&);
       
       /**
        * Configure runtime parameters.
        *
        * String is in the form of "param = value;" eg:
        *   byteOrder = 1;
        *   tcpMinSize = 100000;
        */
       void config(std::string const&, std::ostream * log = 0);
       
       /** Parse single packet; return success indication. */
       bool parsePacket(char* bytes, unsigned short int len, const struct timeval & t, bool uplink); 
       
       /** Set log stream for TCP TA:s */
       void TCPTAlog(std::ostream *);
       
       /** Set log stream for FLV:s */
       void FLVlog(std::ostream *);

       /** Set log stream for HTTP pages. */
       void HTTPPageLog(std::ostream *);

       /** Set log stream for HTTP requests. */
       void HTTPRequestLog(std::ostream *);
       
   private:
       std::auto_ptr< ::Staple > 
            s;
   };
}

#endif
