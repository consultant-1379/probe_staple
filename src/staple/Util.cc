#include <cstdlib>

#include <staple/Type.h>
#include "Util.h"

struct timeval AbsTimeDiff (const struct timeval& x, const struct timeval& y)
{
   struct timeval high;
   struct timeval low;
   struct timeval result;

   if ((x.tv_sec > y.tv_sec) || ((x.tv_sec == y.tv_sec) && (x.tv_usec > y.tv_usec)))
   {
      high = x;
      low = y;
   }
   else
   {
      high = y;
      low = x;
   }
   if (low.tv_usec > high.tv_usec)
   {
      result.tv_usec = 1000000 + high.tv_usec - low.tv_usec;
      result.tv_sec = (high.tv_sec-1) - low.tv_sec;
   }
   else
   {
      result.tv_usec = high.tv_usec - low.tv_usec;
      result.tv_sec = high.tv_sec - low.tv_sec;
   }
   return result;
}

/** Global constants defined in Type.h */
unsigned int TCPTA_SSTHRESH          = 75000;
unsigned int TCPTA_SSMAXFS           = 30000;
unsigned int TCPTA_MINSIZE           = 10000;
unsigned int CHANNELRATE_MIN_PIPE    = 50000;
unsigned int CHANNELRATE_MIN_TIME    = 10000;
unsigned int CHANNELRATE_MIN_DATA    = 250000;
double       ACK_COMPRESSION_TIME    = .0001;
unsigned int UNLOADED_MAXDATA_BEFORE = 1000;
unsigned int UNLOADED_MAXDATA_DURING = 2000;

/** Based on http://stackoverflow.com/questions/194465/how-to-parse-a-string-to-an-int-in-c */
#include <cerrno>
#include <climits>
unsigned int parseint(std::string const& val) throw (std::string)
{
   char *end;
   errno = 0;
   long l = strtol(val.c_str(), &end, 0);
   if ((errno == ERANGE && l == LONG_MAX) || l > UINT_MAX)
      throw std::string("overflow reading " + val);
   if ((errno == ERANGE && l == LONG_MIN) || l < 0)
      throw std::string("underflow reading " + val);
   if (*end != '\0')
      throw std::string("inconvertible " + val);
   return l;
}

#include <cmath>
double parsedbl(std::string const& val) throw (std::string)
{
   char *end;
   double d = strtod(val.c_str(), &end);
   if (d == HUGE_VAL || d == -HUGE_VAL)
      throw std::string("error reading " + val);
   if (*end != '\0')
      throw std::string("inconvertible " + val);
   return d;
}

void config_real(std::string const& cfg, void f(std::string const&, std::string const&, void*), void* arg, std::ostream *& log)
{
   std::string err = "";
   std::size_t i = 0;
   while (true)
   {
      i = cfg.find_first_not_of(" \t\r\n", i);
      if (i == std::string::npos)
      {
         err = "bad line \"" + cfg.substr(i) + "\"";
         break;
      }
      std::size_t j = cfg.find_first_of(" \t", i);
      if (j == std::string::npos)
      {
         err = "bad param name \"" + cfg.substr(i) + "\"";
         break;
      }
      std::size_t k = cfg.find_first_not_of(" \t", j);
      if (k == std::string::npos || cfg[k] != '=')
      {
         err = "no assignment after param \"" + cfg.substr(j) + "\"";
         break;
      }
      k = cfg.find_first_not_of(" \t", k + 1);
      if (k == std::string::npos)
      {
         err = "no value for parameter \"" + (k + 1 < cfg.size() ? cfg.substr(k + 1) : "EOS") + "\"";
         break;
      }
      std::size_t l = cfg.find_first_of(";\n", k);
      if (l == std::string::npos || cfg[l] != ';')
      {
         err = "bad value/line end \"" + cfg.substr(k) + "\"";
         break;
      }
      try
      {
         f(cfg.substr(i, j - i), cfg.substr(k, l - k), arg);
      }
      catch (std::string& s)
      {
         err = s;
         break;
      }
      i = l + 1;
      if (i >= cfg.size())
         break;
   }
   
   if (err != "")
      *log << "config error: " << err << "\n";
}
