#ifndef MAIN_H
#define MAIN_H

#include <staple/Staple.h>

class PerfmonStaple : public Staple
{
public:
   PerfmonStaple() : lastPerfmonROP(0)
   {
      // Default log is stdout
      logStream.rdbuf(std::cout.rdbuf());
   }
   void main(int, char**);
   void PerfmonLogWrite(bool);

   // Perfmon log files
   std::ofstream     flvfile;
   std::ofstream     flvpartialfile;
   std::ofstream     tcptafile;
   std::ofstream     tcptapartialfile;
   // The ROP number of the last Perfmon log file
   unsigned long     lastPerfmonROP;
};

#endif
